use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Auth failed for tenant ''{tenant}'': {reason}")]
    Auth { tenant: String, reason: String },

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Tenant ''{0}'' shutdown requested")]
    Shutdown(String),

    #[error("{0}")]
    Other(String),
}