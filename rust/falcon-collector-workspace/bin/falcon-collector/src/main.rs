use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config_watcher::{load_config, load_dotenv, start_watcher};
use config_watcher::hot_reload::HotReloadEvent;
use multi_tenant::TenantRegistry;

/// Resolve a relative path: tries cwd first, then walks up from the exe dir.
/// Absolute paths pass through unchanged.
fn resolve_path(rel: &str) -> PathBuf {
    let p = PathBuf::from(rel);
    if p.is_absolute() || p.exists() {
        return p;
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(|d| d.to_path_buf());
        for _ in 0..5 {
            if let Some(d) = dir {
                let candidate = d.join(rel);
                if candidate.exists() {
                    return candidate;
                }
                dir = d.parent().map(|p| p.to_path_buf());
            } else {
                break;
            }
        }
    }
    p
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("info")
            })
        )
        .init();

    let config_path = resolve_path(
        &std::env::var("FALCON_CONFIG").unwrap_or_else(|_| "config/default.toml".to_string())
    );
    let env_path = resolve_path(
        &std::env::var("FALCON_ENV").unwrap_or_else(|_| ".env".to_string())
    );

    info!(config = %config_path.display(), env = %env_path.display(), "Starting falcon-collector");

    load_dotenv(&env_path);
    let config = Arc::new(load_config(&config_path)?);

    let registry = Arc::new(TenantRegistry::new());
    registry.apply_config(config.clone()).await;
    info!(tenants = registry.len(), "Initial tenants started");

    let watch_dir = config_path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let env_dir   = env_path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let mut watch_paths = vec![watch_dir];
    if env_dir != watch_paths[0] { watch_paths.push(env_dir); }

    let mut reload_rx = start_watcher(watch_paths)?;

    let registry_shutdown = registry.clone();
    tokio::spawn(async move {
        wait_for_shutdown().await;
        info!("Shutdown signal -- stopping all tenants");
        registry_shutdown.shutdown_all();
        std::process::exit(0);
    });

    while let Some(event) = reload_rx.recv().await {
        match event {
            HotReloadEvent::ConfigChanged(path) => {
                info!(path = %path.display(), "Config changed -- reloading");
                match load_config(&config_path) {
                    Ok(c) => { registry.apply_config(Arc::new(c)).await; }
                    Err(e) => error!(error = %e, "Config reload failed"),
                }
            }
            HotReloadEvent::EnvChanged(path) => {
                info!(path = %path.display(), ".env changed -- restarting affected tenants");
                load_dotenv(&env_path);
                if let Ok(c) = load_config(&config_path) {
                    registry.apply_config(Arc::new(c)).await;
                }
            }
        }
    }

    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).unwrap();
        let mut int  = signal(SignalKind::interrupt()).unwrap();
        tokio::select! { _ = term.recv() => {} _ = int.recv() => {} }
    }
    #[cfg(not(unix))]
    { tokio::signal::ctrl_c().await.unwrap(); }
}