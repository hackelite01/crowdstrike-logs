use collector_core::{CollectedEvent, EventSource};

/// Route events by source type � useful when multiple outputs are configured.
pub fn split_by_source(events: Vec<CollectedEvent>)
    -> (Vec<CollectedEvent>, Vec<CollectedEvent>, Vec<CollectedEvent>)
{
    let mut alerts = Vec::new();
    let mut audits = Vec::new();
    let mut hosts  = Vec::new();
    for ev in events {
        match ev.source {
            EventSource::Alert      => alerts.push(ev),
            EventSource::AuditEvent => audits.push(ev),
            EventSource::Host       => hosts.push(ev),
        }
    }
    (alerts, audits, hosts)
}
