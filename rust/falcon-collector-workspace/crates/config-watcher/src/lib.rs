pub mod hot_reload;
pub mod schema;
pub mod watcher;

pub use hot_reload::HotReloadEvent;
pub use schema::{AppConfig, CollectionConfig, TenantConfig};
pub use watcher::start_watcher;

use std::path::Path;
use tracing::{info, warn};

/// Parse config.toml from `path`. Fails with a descriptive error.
pub fn load_config(path: &Path) -> anyhow::Result<AppConfig> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path.display(), e))?;

    let config: AppConfig = toml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("TOML parse error in '{}': {}", path.display(), e))?;

    info!(path = %path.display(), tenants = config.tenants.len(), "Config loaded");
    Ok(config)
}

/// Load .env from `path` -- best-effort (missing file is a warning, not an error)
pub fn load_dotenv(path: &Path) {
    match dotenvy::from_path(path) {
        Ok(_)  => info!(path = %path.display(), ".env loaded"),
        Err(e) => warn!(path = %path.display(), error = %e, ".env not found -- using shell env"),
    }
}

/// Resolve credentials for a tenant from environment variables.
/// Returns None and logs a warning if any variable is missing.
pub fn resolve_credentials(tenant: &TenantConfig) -> Option<collector_core::TenantCredentials> {
    let prefix = tenant.env_prefix.to_uppercase();
    let id_key  = format!("{}_CLIENT_ID",     prefix);
    let sec_key = format!("{}_CLIENT_SECRET", prefix);

    let client_id = match std::env::var(&id_key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            warn!(tenant = %tenant.name, var = %id_key, "Env var missing or empty -- skipping tenant");
            return None;
        }
    };

    let client_secret = match std::env::var(&sec_key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            warn!(tenant = %tenant.name, var = %sec_key, "Env var missing or empty -- skipping tenant");
            return None;
        }
    };

    // Only log client_id -- never log the secret
    info!(tenant = %tenant.name, client_id = %client_id, "Credentials resolved");

    Some(collector_core::TenantCredentials {
        client_id,
        client_secret: client_secret.into_boxed_str(),
    })
}
