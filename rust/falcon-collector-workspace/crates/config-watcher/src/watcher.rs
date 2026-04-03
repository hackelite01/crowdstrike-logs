use std::path::PathBuf;
use std::time::Duration;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::hot_reload::HotReloadEvent;

/// Start a cross-platform file watcher.
/// Returns a channel receiver that yields HotReloadEvents.
///
/// Uses RecommendedWatcher:
///   Linux   ? inotify
///   Windows ? ReadDirectoryChangesW
pub fn start_watcher(watch_paths: Vec<PathBuf>) -> anyhow::Result<mpsc::Receiver<HotReloadEvent>> {
    let (tx, rx) = mpsc::channel::<HotReloadEvent>(64);
    let (std_tx, std_rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(std_tx, Config::default()
        .with_poll_interval(Duration::from_secs(2)))
        .map_err(|e| anyhow::anyhow!("Watcher init error: {e}"))?;

    for path in &watch_paths {
        watcher.watch(path, RecursiveMode::NonRecursive)
            .map_err(|e| anyhow::anyhow!("Watch '{}': {e}", path.display()))?;
        info!(path = %path.display(), "Watching path");
    }

    // Bridge std channel ? tokio channel in a blocking thread
    tokio::task::spawn_blocking(move || {
        let _watcher = watcher; // keep alive
        for result in std_rx {
            match result {
                Ok(event) if is_modify_or_create(&event.kind) => {
                    for path in event.paths {
                        if let Some(ev) = classify(&path) {
                            debug!(path = %path.display(), "Change detected");
                            if tx.blocking_send(ev).is_err() {
                                return; // receiver gone � shutdown
                            }
                        }
                    }
                }
                Err(e) => error!(error = %e, "Watcher error"),
                _ => {}
            }
        }
    });

    Ok(rx)
}

fn is_modify_or_create(kind: &EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_))
}

fn classify(path: &std::path::Path) -> Option<HotReloadEvent> {
    let name = path.file_name()?.to_string_lossy();
    if name.ends_with(".toml") {
        Some(HotReloadEvent::ConfigChanged(path.to_path_buf()))
    } else if name == ".env" {
        Some(HotReloadEvent::EnvChanged(path.to_path_buf()))
    } else {
        None
    }
}
