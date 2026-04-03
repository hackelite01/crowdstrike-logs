use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum HotReloadEvent {
    /// A .toml file was created or modified
    ConfigChanged(PathBuf),
    /// The .env file was created or modified
    EnvChanged(PathBuf),
}
