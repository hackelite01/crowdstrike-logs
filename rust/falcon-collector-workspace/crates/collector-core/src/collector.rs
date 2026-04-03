use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CollectorError;

/// Opaque credentials -- never printed, never serialised to disk
#[derive(Clone)]
pub struct TenantCredentials {
    pub client_id: String,
    pub client_secret: Box<str>,
}

impl std::fmt::Debug for TenantCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Identity describing one tenant instance
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(pub String);

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single collected event (alert, audit event, host fact, ...)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedEvent {
    pub tenant: String,
    pub source: EventSource,
    pub timestamp: DateTime<Utc>,
    pub id: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Alert,
    AuditEvent,
    Host,
}

/// Common trait every per-source collector must implement
#[async_trait]
pub trait Collector: Send + Sync {
    /// Human-readable name (e.g. "alerts")
    fn name(&self) -> &str;

    /// Poll for new events since `since`. Returns events + new cursor.
    async fn collect(
        &mut self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<CollectedEvent>, CollectorError>;
}

/// Cursor persisted between runs so we do not re-fetch old data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectorCursor {
    pub last_event_time: Option<DateTime<Utc>>,
    pub offset: Option<String>,
}