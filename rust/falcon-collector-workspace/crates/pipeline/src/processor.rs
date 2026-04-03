use collector_core::CollectedEvent;

/// Enrich / normalise events before writing.
/// Runs synchronously (CPU-only); caller decides parallelism.
pub fn process_events(events: Vec<CollectedEvent>) -> Vec<CollectedEvent> {
    events
        // Future: add field normalization, severity mapping, etc.
        .into_iter()
        .collect()
}
