use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Lock-free per-tenant deduplication counters.
/// Uses `Relaxed` ordering — these are diagnostic counters, not synchronisation points.
#[derive(Debug, Default)]
pub struct DedupMetrics {
    pub duplicates_skipped: AtomicU64,
    pub new_events:         AtomicU64,
}

impl DedupMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn record_duplicate(&self) {
        self.duplicates_skipped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_new(&self) {
        self.new_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DedupSnapshot {
        DedupSnapshot {
            duplicates_skipped: self.duplicates_skipped.load(Ordering::Relaxed),
            new_events:         self.new_events.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DedupSnapshot {
    pub duplicates_skipped: u64,
    pub new_events:         u64,
}
