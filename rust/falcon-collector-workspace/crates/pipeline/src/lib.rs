pub mod dedup;
pub mod metrics;
pub mod processor;
pub mod router;

pub use processor::process_events;
pub use router::split_by_source;
pub use metrics::{DedupMetrics, DedupSnapshot};
