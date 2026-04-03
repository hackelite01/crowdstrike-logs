use serde::{Deserialize, Serialize};

/// Root config.toml � contains NO secrets
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,

    #[serde(default)]
    pub collection: CollectionConfig,

    #[serde(default)]
    pub supervisor: SupervisorConfig,

    #[serde(default)]
    pub outputs: OutputsConfig,
}

/// One tenant block � references secrets via env_prefix, never stores them
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TenantConfig {
    pub name: String,
    pub base_url: String,
    /// e.g. "FCT"  ? env vars FCT_CLIENT_ID / FCT_CLIENT_SECRET
    pub env_prefix: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectionConfig {
    #[serde(default = "default_poll_secs")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_batch")]
    pub batch_size: u32,
    /// Duration of the dedup window in minutes.
    /// IDs seen within this window are suppressed; entries older than this
    /// are evicted from both the in-memory cache and the persistent state file.
    #[serde(default = "default_dedup_minutes")]
    pub dedup_window_minutes: u64,
    /// Maximum in-memory dedup cache size per tenant (LRU eviction when full).
    /// Should be set high enough that the window never silently evicts live IDs.
    /// Default 100_000 handles ~100 alerts/s for a 5-minute window comfortably.
    #[serde(default = "default_dedup_lru_size")]
    pub dedup_lru_size: usize,
    /// Directory where per-tenant persistent dedup state files are stored.
    /// Files are named `dedup_<tenant>.json` and written atomically.
    #[serde(default = "default_dedup_state_dir")]
    pub dedup_state_dir: String,
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            poll_interval_seconds: default_poll_secs(),
            batch_size: default_batch(),
            dedup_window_minutes: default_dedup_minutes(),
            dedup_lru_size: default_dedup_lru_size(),
            dedup_state_dir: default_dedup_state_dir(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SupervisorConfig {
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    #[serde(default = "default_backoff_base")]
    pub restart_backoff_base_seconds: u64,
    #[serde(default = "default_backoff_max")]
    pub restart_backoff_max_seconds: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            max_restarts: default_max_restarts(),
            restart_backoff_base_seconds: default_backoff_base(),
            restart_backoff_max_seconds: default_backoff_max(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OutputsConfig {
    #[serde(default)]
    pub json_file: JsonFileConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonFileConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_dir")]
    pub directory: String,
}

impl Default for JsonFileConfig {
    fn default() -> Self {
        Self { enabled: true, directory: default_log_dir() }
    }
}

fn default_true()           -> bool   { true }
fn default_poll_secs()      -> u64    { 30 }
fn default_batch()          -> u32    { 100 }
fn default_dedup_minutes()  -> u64    { 5 }
fn default_dedup_lru_size() -> usize  { 100_000 }
fn default_dedup_state_dir() -> String { "state".to_string() }
fn default_log_dir()        -> String { "logs".to_string() }
fn default_max_restarts()   -> u32    { 10 }
fn default_backoff_base()   -> u64    { 10 }
fn default_backoff_max()    -> u64    { 120 }
