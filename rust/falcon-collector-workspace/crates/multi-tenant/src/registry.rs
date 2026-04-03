use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, warn};

use config_watcher::schema::AppConfig;
use crate::tenant::{TenantHandle, spawn_tenant};

/// Thread-safe registry of all running tenant tasks.
/// DashMap allows concurrent reads without a global lock.
pub struct TenantRegistry {
    handles: DashMap<String, TenantHandle>,
}

impl TenantRegistry {
    pub fn new() -> Self {
        Self { handles: DashMap::new() }
    }

    /// Apply a new AppConfig: start new tenants, stop removed ones,
    /// restart changed ones. Untouched tenants keep running.
    pub async fn apply_config(&self, config: Arc<AppConfig>) {
        let new_names: std::collections::HashSet<String> = config
            .tenants
            .iter()
            .filter(|t| t.enabled)
            .map(|t| t.name.clone())
            .collect();

        // Stop removed tenants
        self.handles.retain(|name, _| {
            if !new_names.contains(name) {
                info!(tenant = %name, "Tenant removed from config � stopping");
                true // keep temporarily; we pop below
            } else {
                true
            }
        });
        let removed: Vec<String> = self.handles
            .iter()
            .filter(|e| !new_names.contains(e.key()))
            .map(|e| e.key().clone())
            .collect();
        for name in removed {
            if let Some((_, handle)) = self.handles.remove(&name) {
                handle.stop();
            }
        }

        // Start or restart tenants
        for tenant_cfg in config.tenants.iter().filter(|t| t.enabled) {
            let name = &tenant_cfg.name;

            let needs_restart = self.handles
                .get(name)
                .map(|h| &h.config != tenant_cfg)
                .unwrap_or(false);

            if needs_restart {
                info!(tenant = %name, "Tenant config changed � restarting");
                if let Some((_, old)) = self.handles.remove(name) {
                    old.stop();
                }
            }

            if !self.handles.contains_key(name) {
                match spawn_tenant(tenant_cfg.clone(), config.clone()).await {
                    Some(handle) => { self.handles.insert(name.clone(), handle); }
                    None => { warn!(tenant = %name, "Credentials missing � tenant not started"); }
                }
            }
        }
    }

    /// Gracefully stop all tenants
    pub fn shutdown_all(&self) {
        info!("Shutting down all tenants");
        self.handles.retain(|_, _| true); // iterate
        let names: Vec<String> = self.handles.iter().map(|e| e.key().clone()).collect();
        for name in names {
            if let Some((_, handle)) = self.handles.remove(&name) {
                handle.stop();
            }
        }
    }

    pub fn len(&self) -> usize { self.handles.len() }
}

impl Default for TenantRegistry {
    fn default() -> Self { Self::new() }
}
