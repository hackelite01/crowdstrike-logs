use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use collector_core::{Collector, TenantCredentials};
use config_watcher::schema::{AppConfig, TenantConfig};
use config_watcher::resolve_credentials;
use falcon_client::{AuthManager, AlertsCollector, build_http_client};
use pipeline::dedup::SlidingWindowDedup;
use pipeline::processor::process_events;
use storage::writer::FileWriter;

/// Live handle for one running tenant task
pub struct TenantHandle {
    pub name: String,
    pub config: TenantConfig,
    pub cancel: CancellationToken,
    pub task: JoinHandle<()>,
}

impl TenantHandle {
    /// Gracefully stop this tenant
    pub fn stop(self) {
        info!(tenant = %self.name, "Stopping tenant");
        self.cancel.cancel();
    }
}

/// Spawn a tenant task: authenticate ? collect ? dedup ? write
pub async fn spawn_tenant(
    config: TenantConfig,
    app_config: Arc<AppConfig>,
) -> Option<TenantHandle> {
    let creds = resolve_credentials(&config)?;
    let name  = config.name.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let task = tokio::spawn(run_tenant(
        name.clone(),
        config.clone(),
        creds,
        app_config,
        cancel_clone,
    ));

    info!(tenant = %name, "Tenant started");
    Some(TenantHandle { name, config, cancel, task })
}

async fn run_tenant(
    name: String,
    config: TenantConfig,
    creds: TenantCredentials,
    app_config: Arc<AppConfig>,
    cancel: CancellationToken,
) {
    let http        = build_http_client();
    let auth        = Arc::new(AuthManager::new(
        name.clone(),
        config.base_url.clone(),
        creds,
        http.clone(),
    ));
    let mut collector = AlertsCollector::new(
        name.clone(),
        auth.clone(),
        http.clone(),
        config.base_url.clone(),
        app_config.collection.batch_size,
    );
    let mut dedup  = SlidingWindowDedup::new(
        app_config.collection.dedup_window_minutes,
        app_config.collection.dedup_window_size,
    );
    let log_dir    = std::path::PathBuf::from(&app_config.outputs.json_file.directory);
    let writer     = FileWriter::new(name.clone(), log_dir);

    let poll = std::time::Duration::from_secs(app_config.collection.poll_interval_seconds);
    let mut last_seen = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(tenant = %name, "Tenant cancelled � shutting down");
                return;
            }
            _ = tokio::time::sleep(poll) => {
                match collector.collect(last_seen).await {
                    Ok(events) => {
                        // Advance cursor from ALL returned events so we never re-fetch
                        // even if every event was deduplicated.
                        let max_ts = events.iter().map(|e| e.timestamp).max();
                        if max_ts > last_seen { last_seen = max_ts; }

                        let new_events = dedup.filter(events);
                        if !new_events.is_empty() {
                            let processed = process_events(new_events);
                            if let Err(e) = writer.write_batch(&processed).await {
                                error!(tenant = %name, error = %e, "Write failed");
                            }
                        }
                    }
                    Err(collector_core::CollectorError::RateLimited) => {
                        warn!(tenant = %name, "Rate limited � backing off 60 s");
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                    Err(e) => {
                        error!(tenant = %name, error = %e, "Collection error");
                    }
                }
            }
        }
    }
}
