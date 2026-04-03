use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use collector_core::CollectedEvent;
use crate::metrics::DedupMetrics;

// ─── Persistent state schema ──────────────────────────────────────────────────

/// The on-disk representation of dedup state for one tenant.
/// Written atomically after every successful batch; loaded on startup.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PersistentDedupState {
    /// Wall-clock timestamp of the last event successfully written to disk.
    /// Used to seed `last_processed_ts` on restart.
    pub last_processed_ts: Option<DateTime<Utc>>,
    /// IDs seen within the active dedup window (stale entries are not written).
    pub recent_ids: Vec<SeenEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SeenEntry {
    pub id:      String,
    pub seen_at: DateTime<Utc>,
}

// ─── Multi-layer DeduplicationEngine ─────────────────────────────────────────

/// Production-grade, multi-layer per-tenant deduplication engine.
///
/// ## Architecture
///
/// ### Layer 1 — In-memory time-windowed cache (fast path)
/// A `HashMap<id, seen_at>` + ordered `VecDeque` for eviction.
/// Bounded by `max_size` (LRU-style capacity eviction) AND by `window`
/// (time-based expiry).  A lookup here is O(1) and requires no I/O.
///
/// ### Layer 2 — Persistent state file
/// Written atomically (`write → .tmp → rename`) after every successful batch.
/// Loaded on startup so the in-memory cache survives restarts.
/// Prevents replay storms when the process is restarted mid-backlog.
///
/// ### Layer 3 — Time-based guard
/// Hard-rejects events whose `timestamp` lies more than `tolerance` before
/// `last_processed_ts`.  Catches stale API responses that slipped past the
/// ID cache (e.g. after a cache warm-up gap).
///
/// ## Dedup at the query layer
/// `prefilter_ids()` prunes the raw ID list returned by the query API
/// **before** calling `fetch_entities`.  This saves API quota and bandwidth
/// and is the first line of defence against duplicates.
pub struct DeduplicationEngine {
    tenant:    String,
    /// Duration of the dedup window (e.g. 5 minutes).
    window:    Duration,
    /// How far before `last_processed_ts` we still tolerate events (2 min).
    tolerance: Duration,
    max_size:  usize,

    // ── Layer 1 ───────────────────────────────────────────────────────────────
    /// id → time we first saw it.
    seen:  HashMap<String, DateTime<Utc>>,
    /// Insertion-order queue enabling cheap time-based and capacity eviction.
    order: VecDeque<(DateTime<Utc>, String)>,

    // ── Layer 2 ───────────────────────────────────────────────────────────────
    persist_path: Option<PathBuf>,

    // ── Metrics ───────────────────────────────────────────────────────────────
    /// Shared with the tenant task so it can emit structured log lines.
    pub metrics: Arc<DedupMetrics>,

    /// The timestamp of the last event we successfully wrote.
    /// Advance with `advance_cursor()` ONLY after a confirmed write.
    pub last_processed_ts: Option<DateTime<Utc>>,
}

impl DeduplicationEngine {
    /// Create a new engine.  Memory is empty; call [`load`] before the first poll.
    pub fn new(
        tenant:         String,
        window_minutes: u64,
        max_size:       usize,
        persist_path:   Option<PathBuf>,
        metrics:        Arc<DedupMetrics>,
    ) -> Self {
        Self {
            tenant,
            window:    Duration::minutes(window_minutes as i64),
            tolerance: Duration::minutes(2),
            max_size,
            seen:  HashMap::with_capacity(max_size.min(8_192)),
            order: VecDeque::new(),
            persist_path,
            metrics,
            last_processed_ts: None,
        }
    }

    // ── Layer 2: persistence ──────────────────────────────────────────────────

    /// Load persistent dedup state from disk into memory.
    ///
    /// - Only entries within the active window are loaded (stale ones dropped).
    /// - On a corrupt or missing file, falls back to a clean start with a warning.
    pub async fn load(&mut self) -> anyhow::Result<()> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None    => return Ok(()),
        };
        if !path.exists() {
            info!(tenant = %self.tenant, path = %path.display(),
                  "No dedup state file found -- starting fresh");
            return Ok(());
        }

        let raw = tokio::fs::read_to_string(&path).await
            .with_context(|| format!("reading dedup state: {}", path.display()))?;

        let state: PersistentDedupState = match serde_json::from_str(&raw) {
            Ok(s)  => s,
            Err(e) => {
                warn!(tenant = %self.tenant, error = %e,
                      "Corrupt dedup state file -- starting fresh");
                PersistentDedupState::default()
            }
        };

        let cutoff = Utc::now() - self.window;
        let mut loaded = 0usize;
        for entry in state.recent_ids {
            if entry.seen_at > cutoff && self.seen.len() < self.max_size {
                self.seen.insert(entry.id.clone(), entry.seen_at);
                self.order.push_back((entry.seen_at, entry.id));
                loaded += 1;
            }
        }
        self.last_processed_ts = state.last_processed_ts;

        info!(
            tenant   = %self.tenant,
            loaded,
            last_ts  = ?self.last_processed_ts,
            "dedup state loaded from disk"
        );
        Ok(())
    }

    /// Persist the current in-memory state to disk atomically.
    ///
    /// Uses `write → .tmp → rename` so a crash mid-write never produces a
    /// torn file.  Only entries within the active window are written.
    /// Call **after** a confirmed successful write batch.
    pub async fn persist(&self) -> anyhow::Result<()> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None    => return Ok(()),
        };

        let cutoff = Utc::now() - self.window;
        let recent_ids: Vec<SeenEntry> = self.order.iter()
            .filter(|(ts, _)| *ts > cutoff)
            .map(|(ts, id)| SeenEntry { id: id.clone(), seen_at: *ts })
            .collect();

        let count = recent_ids.len();
        let state = PersistentDedupState {
            last_processed_ts: self.last_processed_ts,
            recent_ids,
        };
        let json = serde_json::to_vec(&state)?;

        // Atomic write: .tmp then rename (prevents torn reads on crash)
        let tmp = path.with_extension("json.tmp");
        if let Some(parent) = tmp.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(&json).await?;
        file.flush().await?;
        drop(file);
        tokio::fs::rename(&tmp, &path).await?;

        debug!(tenant = %self.tenant, ids = count, path = %path.display(),
               "dedup state persisted");
        Ok(())
    }

    // ── Pre-filter: query-level ID pruning (before entity fetch) ─────────────

    /// Filter raw IDs returned by the query API against the in-memory cache.
    /// Returns only IDs **not** currently in the cache.
    ///
    /// Call this **before** `fetch_entities` to avoid wasting API quota on
    /// IDs we already know about.  This is a read-only operation.
    pub fn prefilter_ids(&self, ids: &[String]) -> Vec<String> {
        let mut new_ids = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(seen_at) = self.seen.get(id) {
                debug!(
                    tenant  = %self.tenant,
                    id      = %id,
                    seen_at = %seen_at,
                    "dedup_cache_hit (pre-filter query-level)"
                );
                self.metrics.record_duplicate();
            } else {
                new_ids.push(id.clone());
            }
        }
        new_ids
    }

    // ── Full event-level filter (Layer 1 + Layer 3) ───────────────────────────

    /// Run the full multi-layer filter on a batch of `CollectedEvent`s.
    ///
    /// For each event:
    /// 1. **Layer 3 — time guard**: reject if `event.timestamp < last_processed_ts - tolerance`.
    /// 2. **Layer 1 — cache check**: reject if ID is already in the in-memory cache.
    /// 3. **Insertion**: new IDs are inserted into the cache (with LRU eviction if full).
    ///
    /// Events that survive both checks are logged as `new_event_processed`.
    pub fn filter_events(&mut self, events: Vec<CollectedEvent>) -> Vec<CollectedEvent> {
        self.evict_expired();
        let now = Utc::now();

        events.into_iter().filter(|e| {
            // ── Layer 3: time-based guard ─────────────────────────────────────
            if let Some(last_ts) = self.last_processed_ts {
                let min_acceptable = last_ts - self.tolerance;
                if e.timestamp < min_acceptable {
                    debug!(
                        tenant      = %self.tenant,
                        id          = %e.id,
                        event_ts    = %e.timestamp,
                        min_accept  = %min_acceptable,
                        "duplicate_skipped (time-guard: event predates cursor)"
                    );
                    self.metrics.record_duplicate();
                    return false;
                }
            }

            // ── Layer 1: in-memory cache ──────────────────────────────────────
            if self.seen.contains_key(&e.id) {
                debug!(
                    tenant = %self.tenant,
                    id     = %e.id,
                    "duplicate_skipped (dedup_cache_hit)"
                );
                self.metrics.record_duplicate();
                return false;
            }

            // New event: insert into cache, evict oldest if at capacity
            if self.seen.len() >= self.max_size {
                if let Some((_, oldest_id)) = self.order.pop_front() {
                    self.seen.remove(&oldest_id);
                }
            }
            self.seen.insert(e.id.clone(), now);
            self.order.push_back((now, e.id.clone()));
            self.metrics.record_new();
            debug!(tenant = %self.tenant, id = %e.id, "new_event_processed");
            true
        }).collect()
    }

    // ── Write-level final safety check ───────────────────────────────────────

    /// Returns `true` if this ID has already been inserted into the cache.
    /// Use as a last-resort guard in concurrent-write scenarios.
    /// NOTE: do NOT call this after `filter_events` for the same batch —
    /// `filter_events` already performs this check and inserts on success.
    pub fn is_already_seen(&self, id: &str) -> bool {
        self.seen.contains_key(id)
    }

    // ── Cursor management ─────────────────────────────────────────────────────

    /// Advance the cursor to `ts`.
    /// ONLY call after a confirmed successful write.  Never decrements.
    pub fn advance_cursor(&mut self, ts: DateTime<Utc>) {
        if self.last_processed_ts.map_or(true, |prev| ts > prev) {
            self.last_processed_ts = Some(ts);
        }
    }

    /// The `since` timestamp to pass to the query API.
    ///
    /// Returns `last_processed_ts - tolerance` so the query window slightly
    /// overlaps the previous poll and never misses events at page boundaries.
    /// The in-memory cache handles the overlap — duplicates are cheap to skip.
    pub fn query_since(&self) -> Option<DateTime<Utc>> {
        self.last_processed_ts.map(|ts| ts - self.tolerance)
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    pub fn cache_size(&self) -> usize { self.seen.len() }

    // ── Private ───────────────────────────────────────────────────────────────

    fn evict_expired(&mut self) {
        let cutoff = Utc::now() - self.window;
        while let Some((ts, _)) = self.order.front() {
            if *ts < cutoff {
                let (_, id) = self.order.pop_front().unwrap();
                self.seen.remove(&id);
            } else {
                break;
            }
        }
    }
}
