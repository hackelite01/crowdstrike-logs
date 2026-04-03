use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use collector_core::{CollectorError, TenantCredentials};
use config_watcher::schema::AppConfig;
use config_watcher::resolve_credentials;
use falcon_client::{AuthManager, AlertsCollector, build_http_client};
use pipeline::dedup::DeduplicationEngine;
use pipeline::metrics::DedupMetrics;
use pipeline::processor::process_events;
use storage::writer::FileWriter;

/// Live handle for one running tenant task.
pub struct TenantHandle {
    pub name:   String,
    pub config: config_watcher::schema::TenantConfig,
    pub cancel: CancellationToken,
    pub task:   JoinHandle<()>,
}

impl TenantHandle {
    pub fn stop(self) {
        info!(tenant = %self.name, "Stopping tenant");
        self.cancel.cancel();
    }
}

/// Spawn a supervised async task for one tenant.
pub async fn spawn_tenant(
    config:     config_watcher::schema::TenantConfig,
    app_config: Arc<AppConfig>,
) -> Option<TenantHandle> {
    let creds  = resolve_credentials(&config)?;
    let name   = config.name.clone();
    let cancel = CancellationToken::new();

    let task = tokio::spawn(run_tenant(
        name.clone(),
        config.clone(),
        creds,
        app_config,
        cancel.clone(),
    ));

    info!(tenant = %name, "Tenant started");
    Some(TenantHandle { name, config, cancel, task })
}

async fn run_tenant(
    name:       String,
    config:     config_watcher::schema::TenantConfig,
    creds:      TenantCredentials,
    app_config: Arc<AppConfig>,
    cancel:     CancellationToken,
) {
    let http = build_http_client();
    let auth = Arc::new(AuthManager::new(
        name.clone(),
        config.base_url.clone(),
        creds,
        http.clone(),
    ));
    let collector = AlertsCollector::new(
        name.clone(),
        auth.clone(),
        http.clone(),
        config.base_url.clone(),
        app_config.collection.batch_size,
    );

    // Persist dedup state in: <dedup_state_dir>/dedup_<tenant>.json
    let state_dir  = PathBuf::from(&app_config.collection.dedup_state_dir);
    let state_path = state_dir.join(format!("dedup_{}.json", name));

    let metrics = DedupMetrics::new();
    let mut dedup = DeduplicationEngine::new(
        name.clone(),
        app_config.collection.dedup_window_minutes,
        app_config.collection.dedup_lru_size,
        Some(state_path),
        metrics.clone(),
    );

    // Restart safety: restore in-memory cache and cursor from disk
    if let Err(e) = dedup.load().await {
        warn!(tenant = %name, error = %e, "Failed to load dedup state -- starting fresh");
    }

    let log_dir = PathBuf::from(&app_config.outputs.json_file.directory);
    let writer  = FileWriter::new(name.clone(), log_dir);
    let poll    = std::time::Duration::from_secs(app_config.collection.poll_interval_seconds);

    // last_seen is seeded from the persistent cursor so restarts pick up
    // from where we left off instead of replaying the entire backlog.
    let mut last_seen = dedup.last_processed_ts;

    info!(
        tenant    = %name,
        last_seen = ?last_seen,
        cache     = dedup.cache_size(),
        "Tenant polling loop started"
    );

    // Main loop: tokio::select! with sleep ensures only ONE poll executes at a
    // time -- the sleep starts AFTER the previous poll completes so polls never
    // overlap even if a single poll takes longer than poll_interval_seconds.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(tenant = %name, "Tenant cancelled -- shutting down");
                return;
            }
            _ = tokio::time::sleep(poll) => {
                poll_once(
                    &name,
                    &collector,
                    &writer,
                    &mut dedup,
                    &mut last_seen,
                    &metrics,
                ).await;
            }
        }
    }
}

/// One complete poll cycle.
///
/// Flow:
///  1. Determine query_since = last_processed_ts - 2 min (slight backward overlap)
///  2. Paginate query IDs from CrowdStrike
///  3. Pre-filter IDs against in-memory cache (Layer 1) -- skips entity fetch for known dupes
///  4. Fetch entities ONLY for unknown IDs
///  5. Full dedup via filter_events (Layer 1 final + Layer 3 time guard)
///  6. Write passing events to disk
///  7. Advance cursor ONLY after confirmed write (never on failure)
///  8. Persist dedup state to disk atomically
///  9. Emit structured per-poll metrics
async fn poll_once(
    name:      &str,
    collector: &AlertsCollector,
    writer:    &FileWriter,
    dedup:     &mut DeduplicationEngine,
    last_seen: &mut Option<chrono::DateTime<chrono::Utc>>,
    metrics:   &Arc<DedupMetrics>,
) {
    use chrono::Utc;

    let query_since = dedup.query_since().or(*last_seen);
    let now         = Utc::now();
    let mut after: Option<String> = None;
    let mut wrote_any = false;

    debug!(tenant = %name, since = ?query_since, "poll starting");

    loop {
        // Step 1: Query IDs
        let (raw_ids, next_after) =
            match collector.query_ids(query_since, after.as_deref()).await {
                Ok(r) => r,
                Err(CollectorError::RateLimited) => {
                    warn!(tenant = %name, "Rate limited -- backing off 60 s");
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    return;
                }
                Err(e) => {
                    error!(tenant = %name, error = %e, "query_ids failed");
                    return;
                }
            };

        after = next_after;

        if raw_ids.is_empty() {
            if after.is_none() { break; }
            continue;
        }

        // Step 2: Pre-filter IDs (Layer 1 read-only) -- avoids entity fetch for known dupes
        let new_ids = dedup.prefilter_ids(&raw_ids);

        debug!(
            tenant      = %name,
            total       = raw_ids.len(),
            new_ids     = new_ids.len(),
            prefiltered = raw_ids.len().saturating_sub(new_ids.len()),
            "ID pre-filter complete"
        );

        if !new_ids.is_empty() {
            // Step 3: Fetch entities ONLY for IDs not already in cache
            let entities = match collector.fetch_entities(&new_ids).await {
                Ok(e) => e,
                Err(CollectorError::RateLimited) => {
                    warn!(tenant = %name, "Rate limited during entity fetch -- backing off 60 s");
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    return;
                }
                Err(e) => {
                    error!(tenant = %name, error = %e, "fetch_entities failed");
                    return;
                }
            };

            // Step 4: Convert to CollectedEvents (composite_id is the canonical key)
            let events = collector.entities_to_events(entities, now);

            // Step 5: Full dedup filter (Layer 1 final + Layer 3 time guard)
            let new_events = dedup.filter_events(events);

            if !new_events.is_empty() {
                // Step 6: Write to disk
                let processed = process_events(new_events.clone());
                match writer.write_batch(&processed).await {
                    Ok(()) => {
                        // Step 7: Advance cursor ONLY after confirmed write
                        let max_ts = new_events.iter().map(|e| e.timestamp).max();
                        if let Some(ts) = max_ts {
                            dedup.advance_cursor(ts);
                            if last_seen.map_or(true, |prev| ts > prev) {
                                *last_seen = Some(ts);
                            }
                        }
                        wrote_any = true;
                    }
                    Err(e) => {
                        error!(
                            tenant = %name,
                            error  = %e,
                            "Write failed -- cursor NOT advanced, will retry next poll"
                        );
                        // Return without persisting: next poll will re-fetch and re-dedup.
                        // The in-memory cache already has these IDs so they will not be
                        // double-fetched within the same window, but a restart would retry
                        // them (acceptable -- safer than silently dropping data).
                        return;
                    }
                }
            }
        }

        if after.is_none() { break; }
    }

    // Step 8: Persist dedup state atomically after a successful batch
    if wrote_any {
        if let Err(e) = dedup.persist().await {
            warn!(tenant = %name, error = %e, "Dedup state persist failed (non-fatal)");
        }
    }

    // Step 9: Per-poll structured metrics
    let snap = metrics.snapshot();
    info!(
        tenant             = %name,
        new_events         = snap.new_events,
        duplicates_skipped = snap.duplicates_skipped,
        dedup_cache_size   = dedup.cache_size(),
        last_ts            = ?dedup.last_processed_ts,
        "poll complete"
    );
}
