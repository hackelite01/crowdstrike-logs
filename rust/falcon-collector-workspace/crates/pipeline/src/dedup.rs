use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Duration, Utc};
use collector_core::CollectedEvent;

/// Sliding-window deduplication: drops events whose ID was seen
/// within the last `window_minutes`, capped at `max_size` entries.
pub struct SlidingWindowDedup {
    window: Duration,
    max_size: usize,
    seen: HashMap<String, DateTime<Utc>>,
    order: VecDeque<(DateTime<Utc>, String)>,
}

impl SlidingWindowDedup {
    pub fn new(window_minutes: u64, max_size: usize) -> Self {
        Self {
            window: Duration::minutes(window_minutes as i64),
            max_size,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Remove expired entries then filter `events`.
    pub fn filter(&mut self, events: Vec<CollectedEvent>) -> Vec<CollectedEvent> {
        self.evict_expired();
        let now = Utc::now();
        events.into_iter().filter(|e| {
            if self.seen.contains_key(&e.id) {
                return false;
            }
            // Evict oldest if at capacity
            if self.seen.len() >= self.max_size {
                if let Some((_, oldest_id)) = self.order.pop_front() {
                    self.seen.remove(&oldest_id);
                }
            }
            self.seen.insert(e.id.clone(), now);
            self.order.push_back((now, e.id.clone()));
            true
        }).collect()
    }

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
