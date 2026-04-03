pub mod collector;
pub mod error;

pub use collector::{
    CollectedEvent, Collector, CollectorCursor, EventSource, TenantCredentials, TenantId,
};
pub use error::CollectorError;
