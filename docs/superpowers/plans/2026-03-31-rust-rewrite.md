# CrowdStrike Log Collector — Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Python CrowdStrike log collector to a production-grade Rust binary using a 4-crate Cargo workspace.

**Architecture:** `cs-state` → `cs-output` → `cs-collector` → `cs-main`. Tokio async runtime, bounded mpsc channel between collectors and dispatcher, CancellationToken shutdown, singleflight OAuth2, token-bucket rate limiter, two-layer event deduplication (in-memory HashSet + persisted `last_n_ids`).

**Tech Stack:** Rust 2021, tokio 1, reqwest 0.12 (rustls), serde/serde_json, toml 0.8, async-trait, thiserror, governor, clap 4, tracing + tracing-subscriber (JSON), chrono, tokio-util, wiremock (tests), tempfile (tests)

---

## File Map

| File | Responsibility |
|---|---|
| `Cargo.toml` | Workspace manifest |
| `config.toml` | Runtime config (TOML, replaces config.yaml) |
| `crates/cs-state/src/lib.rs` | `StateManager`, `SourceState`, `StateError` |
| `crates/cs-output/src/lib.rs` | `OutputHandler` trait, `OutputError`, re-exports |
| `crates/cs-output/src/json_file.rs` | `JsonFileOutput`: active file + daily UTC rotation |
| `crates/cs-output/src/http_post.rs` | `HttpPostOutput`: batched POST to SIEM |
| `crates/cs-output/src/dispatcher.rs` | `OutputDispatcher`: fan-out + DLQ writer |
| `crates/cs-collector/src/error.rs` | `CollectorError` |
| `crates/cs-collector/src/auth.rs` | `AuthManager`: singleflight OAuth2 token refresh |
| `crates/cs-collector/src/api_client.rs` | `ApiClient`: reqwest wrapper, rate-limit, retry |
| `crates/cs-collector/src/base.rs` | `CollectorTask` trait, `enrich_event`, `should_skip_event` |
| `crates/cs-collector/src/alerts.rs` | `AlertsCollector` |
| `crates/cs-collector/src/audit_events.rs` | `AuditEventsCollector` |
| `crates/cs-collector/src/hosts.rs` | `HostsCollector` |
| `crates/cs-collector/src/lib.rs` | Re-exports |
| `crates/cs-main/src/config.rs` | TOML config structs (serde) |
| `crates/cs-main/src/metrics.rs` | Structured heartbeat emitter |
| `crates/cs-main/src/main.rs` | Entry point, supervisor loop, shutdown |

---

## Task 1: Workspace Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `crates/cs-state/Cargo.toml`, `crates/cs-state/src/lib.rs`
- Create: `crates/cs-output/Cargo.toml`, `crates/cs-output/src/lib.rs`
- Create: `crates/cs-collector/Cargo.toml`, `crates/cs-collector/src/lib.rs`
- Create: `crates/cs-main/Cargo.toml`, `crates/cs-main/src/main.rs`

- [ ] **Step 1: Create workspace `Cargo.toml`**

```toml
[workspace]
members = [
    "crates/cs-state",
    "crates/cs-output",
    "crates/cs-collector",
    "crates/cs-main",
]
resolver = "2"

[workspace.dependencies]
tokio       = { version = "1", features = ["full"] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
thiserror   = "1"
tracing     = "0.1"
async-trait = "0.1"
chrono      = { version = "0.4", features = ["serde"] }
reqwest     = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

- [ ] **Step 2: Create `crates/cs-state/Cargo.toml`**

```toml
[package]
name    = "cs-state"
version = "0.1.0"
edition = "2021"

[dependencies]
serde      = { workspace = true }
serde_json = { workspace = true }
thiserror  = { workspace = true }
chrono     = { workspace = true }

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Create `crates/cs-output/Cargo.toml`**

```toml
[package]
name    = "cs-output"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { workspace = true }
serde_json  = { workspace = true }
thiserror   = { workspace = true }
tracing     = { workspace = true }
async-trait = { workspace = true }
chrono      = { workspace = true }
reqwest     = { workspace = true }

[dev-dependencies]
tempfile = "3"
tokio    = { workspace = true }
wiremock = "0.6"
```

- [ ] **Step 4: Create `crates/cs-collector/Cargo.toml`**

```toml
[package]
name    = "cs-collector"
version = "0.1.0"
edition = "2021"

[dependencies]
cs-state    = { path = "../cs-state" }
tokio       = { workspace = true }
reqwest     = { workspace = true }
serde       = { workspace = true }
serde_json  = { workspace = true }
async-trait = { workspace = true }
tracing     = { workspace = true }
thiserror   = { workspace = true }
chrono      = { workspace = true }
governor    = "0.6"

[dev-dependencies]
tokio    = { workspace = true }
wiremock = "0.6"
tempfile = "3"
```

- [ ] **Step 5: Create `crates/cs-main/Cargo.toml`**

```toml
[package]
name    = "cs-main"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "cs-collector"
path = "src/main.rs"

[dependencies]
cs-state     = { path = "../cs-state" }
cs-output    = { path = "../cs-output" }
cs-collector = { path = "../cs-collector" }
tokio        = { workspace = true }
tokio-util   = { version = "0.7", features = ["rt"] }
serde        = { workspace = true }
serde_json   = { workspace = true }
thiserror    = { workspace = true }
tracing      = { workspace = true }
tracing-subscriber = { version = "0.3", features = ["json", "fmt", "env-filter"] }
chrono       = { workspace = true }
toml         = "0.8"
clap         = { version = "4", features = ["derive"] }
dotenv       = "0.15"
regex        = "1"

[dev-dependencies]
tokio    = { workspace = true }
wiremock = "0.6"
tempfile = "3"
```

- [ ] **Step 6: Create stub `lib.rs` / `main.rs` for each crate**

`crates/cs-state/src/lib.rs`:
```rust
// stub
```

`crates/cs-output/src/lib.rs`:
```rust
// stub
```

`crates/cs-collector/src/lib.rs`:
```rust
// stub
```

`crates/cs-main/src/main.rs`:
```rust
fn main() {}
```

- [ ] **Step 7: Verify workspace compiles**

```bash
cargo check
```
Expected: no errors, 4 crates checked.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/
git commit -m "chore: scaffold Rust workspace with 4 crates"
```

---

## Task 2: cs-state — StateManager

**Files:**
- Modify: `crates/cs-state/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-state/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = StateManager::load(dir.path().join("state.json")).unwrap();
        let s = mgr.get("alerts");
        assert!(!s.last_timestamp.is_empty());
        assert!(s.last_id.is_empty());
        assert!(s.last_n_ids.is_empty());
    }

    #[test]
    fn update_and_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut mgr = StateManager::load(&path).unwrap();
        mgr.update("alerts", "2026-03-31T05:00:00Z", "id-1", &["id-1".to_string()], 500).unwrap();
        let mgr2 = StateManager::load(&path).unwrap();
        let s = mgr2.get("alerts");
        assert_eq!(s.last_timestamp, "2026-03-31T05:00:00Z");
        assert_eq!(s.last_id, "id-1");
        assert_eq!(s.last_n_ids, vec!["id-1"]);
    }

    #[test]
    fn last_n_ids_capped_at_window_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = StateManager::load(dir.path().join("state.json")).unwrap();
        let ids: Vec<String> = (0..600).map(|i| format!("id-{i}")).collect();
        mgr.update("alerts", "ts", "id-599", &ids, 500).unwrap();
        assert_eq!(mgr.get("alerts").last_n_ids.len(), 500);
    }

    #[test]
    fn multi_source_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut mgr = StateManager::load(&path).unwrap();
        mgr.update("alerts",       "2026-03-31T05:00:00Z", "a1", &[], 500).unwrap();
        mgr.update("audit_events", "2026-03-31T06:00:00Z", "b1", &[], 500).unwrap();
        assert_eq!(mgr.get("alerts").last_timestamp,       "2026-03-31T05:00:00Z");
        assert_eq!(mgr.get("audit_events").last_timestamp, "2026-03-31T06:00:00Z");
    }

    #[test]
    fn atomic_write_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut mgr = StateManager::load(&path).unwrap();
        mgr.update("alerts", "ts", "id", &[], 500).unwrap();
        assert!(!path.with_extension("tmp").exists());
        assert!(path.exists());
    }
}
```

- [ ] **Step 2: Run — expect compile errors (no implementation yet)**

```bash
cargo test -p cs-state 2>&1 | head -30
```

- [ ] **Step 3: Implement `cs-state/src/lib.rs`**

```rust
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceState {
    pub last_timestamp: String,
    pub last_id:        String,
    #[serde(default)]
    pub last_n_ids:     Vec<String>,
}

pub struct StateManager {
    path:  PathBuf,
    cache: HashMap<String, SourceState>,
}

impl StateManager {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let path = path.as_ref().to_path_buf();
        let cache = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str::<HashMap<String, SourceState>>(&raw)?
        } else {
            HashMap::new()
        };
        Ok(Self { path, cache })
    }

    pub fn get(&self, source: &str) -> SourceState {
        self.cache.get(source).cloned().unwrap_or_else(|| {
            let ts = (Utc::now() - Duration::hours(1))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            SourceState { last_timestamp: ts, ..Default::default() }
        })
    }

    pub fn update(
        &mut self,
        source:            &str,
        last_timestamp:    &str,
        last_id:           &str,
        recent_ids:        &[String],
        dedup_window_size: usize,
    ) -> Result<(), StateError> {
        let n = recent_ids.len();
        let ids = if n > dedup_window_size {
            recent_ids[n - dedup_window_size..].to_vec()
        } else {
            recent_ids.to_vec()
        };
        self.cache.insert(source.to_string(), SourceState {
            last_timestamp: last_timestamp.to_string(),
            last_id:        last_id.to_string(),
            last_n_ids:     ids,
        });
        self.flush()
    }

    fn flush(&self) -> Result<(), StateError> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.cache)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests — expect all pass**

```bash
cargo test -p cs-state
```
Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/cs-state/
git commit -m "feat(cs-state): StateManager with persisted dedup window"
```

---

## Task 3: cs-output — Trait, Error, and JsonFileOutput

**Files:**
- Modify: `crates/cs-output/src/lib.rs`
- Create: `crates/cs-output/src/json_file.rs`

- [ ] **Step 1: Write failing tests in `lib.rs`**

```rust
// At the bottom of crates/cs-output/src/lib.rs (after the module declarations)
#[cfg(test)]
mod tests {
    use super::*;
    use json_file::JsonFileOutput;
    use serde_json::json;

    #[tokio::test]
    async fn writes_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let out = JsonFileOutput::new(dir.path(), "FCT", 500);
        out.write(&json!({"id": "1"})).await.unwrap();
        out.close().await.unwrap();
        let active = dir.path().join("falcon_alerts_FCT.json");
        assert!(active.exists());
        let line = std::fs::read_to_string(&active).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["id"], "1");
    }

    #[tokio::test]
    async fn multiple_writes_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = JsonFileOutput::new(dir.path(), "FCT", 500);
        out.write(&json!({"id": "1"})).await.unwrap();
        out.write(&json!({"id": "2"})).await.unwrap();
        out.close().await.unwrap();
        let lines = std::fs::read_to_string(dir.path().join("falcon_alerts_FCT.json")).unwrap();
        assert_eq!(lines.trim().lines().count(), 2);
    }

    #[tokio::test]
    async fn date_rotation_renames_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = JsonFileOutput::new(dir.path(), "FCT", 500);

        out.write_with_date(&json!({"id": "1"}), "2026-03-31").await.unwrap();
        out.write_with_date(&json!({"id": "2"}), "2026-04-01").await.unwrap();
        out.close().await.unwrap();

        let dated = dir.path().join("falcon_alerts_FCT_2026-03-31.json");
        assert!(dated.exists());
        let day1: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&dated).unwrap().trim()
        ).unwrap();
        assert_eq!(day1["id"], "1");

        let active = dir.path().join("falcon_alerts_FCT.json");
        let day2: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&active).unwrap().trim()
        ).unwrap();
        assert_eq!(day2["id"], "2");
    }
}
```

- [ ] **Step 2: Implement `crates/cs-output/src/lib.rs`**

```rust
pub mod dispatcher;
pub mod http_post;
pub mod json_file;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP POST failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[async_trait]
pub trait OutputHandler: Send + Sync {
    fn name(&self) -> &str;
    fn is_enabled(&self) -> bool { true }
    async fn write(&self, event: &Value) -> Result<(), OutputError>;
    async fn close(&self) -> Result<(), OutputError>;
}
```

- [ ] **Step 3: Implement `crates/cs-output/src/json_file.rs`**

```rust
use std::path::{Path, PathBuf};
use std::sync::Arc;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::info;
use crate::{OutputError, OutputHandler};

struct Inner {
    handle:       Option<tokio::fs::File>,
    current_date: Option<String>,
}

pub struct JsonFileOutput {
    dir:         PathBuf,
    client_name: String,
    min_free_mb: u64,
    inner:       Arc<Mutex<Inner>>,
}

impl JsonFileOutput {
    pub fn new(dir: impl AsRef<Path>, client_name: &str, min_free_mb: u64) -> Self {
        Self {
            dir:         dir.as_ref().to_path_buf(),
            client_name: client_name.to_string(),
            min_free_mb,
            inner:       Arc::new(Mutex::new(Inner { handle: None, current_date: None })),
        }
    }

    fn active_path(&self) -> PathBuf {
        self.dir.join(format!("falcon_alerts_{}.json", self.client_name))
    }

    fn today_utc() -> String {
        Utc::now().format("%Y-%m-%d").to_string()
    }

    /// Exposed for testing: write with an explicit date string instead of today.
    pub async fn write_with_date(&self, event: &Value, date: &str) -> Result<(), OutputError> {
        self.write_inner(event, date).await
    }

    async fn write_inner(&self, event: &Value, today: &str) -> Result<(), OutputError> {
        let mut inner = self.inner.lock().await;

        // Rotate if date changed
        if inner.current_date.as_deref() != Some(today) {
            if let Some(mut h) = inner.handle.take() {
                h.flush().await?;
                h.shutdown().await?;
            }
            if let Some(prev_date) = &inner.current_date {
                let dated = self.dir.join(
                    format!("falcon_alerts_{}_{}.json", self.client_name, prev_date)
                );
                if self.active_path().exists() {
                    tokio::fs::rename(self.active_path(), &dated).await?;
                    info!("Rotated log to {}", dated.display());
                }
            }
            inner.current_date = Some(today.to_string());
        }

        // Open file if not already open
        if inner.handle.is_none() {
            inner.handle = Some(
                tokio::fs::OpenOptions::new()
                    .create(true).append(true)
                    .open(self.active_path()).await?
            );
        }

        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        inner.handle.as_mut().unwrap().write_all(line.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl OutputHandler for JsonFileOutput {
    fn name(&self) -> &str { "json_file" }

    async fn write(&self, event: &Value) -> Result<(), OutputError> {
        self.write_inner(event, &Self::today_utc()).await
    }

    async fn close(&self) -> Result<(), OutputError> {
        let mut inner = self.inner.lock().await;
        if let Some(mut h) = inner.handle.take() {
            h.flush().await?;
            h.shutdown().await?;
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p cs-output json_file
```
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/cs-output/
git commit -m "feat(cs-output): OutputHandler trait + JsonFileOutput with daily rotation"
```

---

## Task 4: cs-output — HttpPostOutput

**Files:**
- Create: `crates/cs-output/src/http_post.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-output/src/lib.rs` tests module:

```rust
#[cfg(test)]
mod http_tests {
    use super::http_post::HttpPostOutput;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn buffers_until_batch_size() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let out = HttpPostOutput::new(
            format!("{}/ingest", server.uri()),
            std::collections::HashMap::new(),
            2, // batch_size
        );
        out.write(&json!({"id": "1"})).await.unwrap(); // buffered
        out.write(&json!({"id": "2"})).await.unwrap(); // triggers flush
        server.verify().await;
    }

    #[tokio::test]
    async fn flushes_partial_batch_on_close() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let out = HttpPostOutput::new(
            format!("{}/ingest", server.uri()),
            std::collections::HashMap::new(),
            10,
        );
        out.write(&json!({"id": "1"})).await.unwrap();
        out.close().await.unwrap();
        server.verify().await;
    }
}
```

- [ ] **Step 2: Implement `crates/cs-output/src/http_post.rs`**

```rust
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;
use crate::{OutputError, OutputHandler};

pub struct HttpPostOutput {
    url:        String,
    headers:    HashMap<String, String>,
    batch_size: usize,
    buffer:     Arc<Mutex<Vec<Value>>>,
    client:     reqwest::Client,
}

impl HttpPostOutput {
    pub fn new(url: String, headers: HashMap<String, String>, batch_size: usize) -> Self {
        Self {
            url,
            headers,
            batch_size,
            buffer: Arc::new(Mutex::new(Vec::new())),
            client: reqwest::Client::new(),
        }
    }

    async fn flush_inner(&self, buf: &mut Vec<Value>) -> Result<(), OutputError> {
        if buf.is_empty() { return Ok(()); }
        let body: Vec<Value> = buf.drain(..).collect();
        let mut req = self.client.post(&self.url);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        req.json(&body).send().await?.error_for_status()?;
        Ok(())
    }
}

#[async_trait]
impl OutputHandler for HttpPostOutput {
    fn name(&self) -> &str { "http_post" }

    async fn write(&self, event: &Value) -> Result<(), OutputError> {
        let mut buf = self.buffer.lock().await;
        buf.push(event.clone());
        if buf.len() >= self.batch_size {
            self.flush_inner(&mut buf).await?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        let mut buf = self.buffer.lock().await;
        self.flush_inner(&mut buf).await
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p cs-output http_tests
```
Expected: `2 passed`

- [ ] **Step 4: Commit**

```bash
git add crates/cs-output/src/http_post.rs crates/cs-output/src/lib.rs
git commit -m "feat(cs-output): HttpPostOutput with batch flush"
```

---

## Task 5: cs-output — OutputDispatcher + DLQ

**Files:**
- Create: `crates/cs-output/src/dispatcher.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-output/src/lib.rs`:

```rust
#[cfg(test)]
mod dispatcher_tests {
    use super::*;
    use super::dispatcher::OutputDispatcher;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct CapturingHandler {
        name:    String,
        events:  Arc<Mutex<Vec<serde_json::Value>>>,
        enabled: bool,
    }
    #[async_trait::async_trait]
    impl OutputHandler for CapturingHandler {
        fn name(&self)       -> &str  { &self.name }
        fn is_enabled(&self) -> bool  { self.enabled }
        async fn write(&self, e: &serde_json::Value) -> Result<(), OutputError> {
            self.events.lock().unwrap().push(e.clone());
            Ok(())
        }
        async fn close(&self) -> Result<(), OutputError> { Ok(()) }
    }

    #[tokio::test]
    async fn fans_out_to_all_enabled_handlers() {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let events1 = Arc::new(Mutex::new(vec![]));
        let events2 = Arc::new(Mutex::new(vec![]));
        let handlers: Vec<Box<dyn OutputHandler>> = vec![
            Box::new(CapturingHandler { name: "h1".into(), events: events1.clone(), enabled: true }),
            Box::new(CapturingHandler { name: "h2".into(), events: events2.clone(), enabled: true }),
        ];
        let dir = tempfile::tempdir().unwrap();
        let dispatcher = OutputDispatcher::new(rx, handlers, dir.path().to_path_buf());
        let handle = tokio::spawn(dispatcher.run());
        tx.send(json!({"id":"1"})).await.unwrap();
        drop(tx);
        handle.await.unwrap();
        assert_eq!(events1.lock().unwrap().len(), 1);
        assert_eq!(events2.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn skips_disabled_handler() {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let events = Arc::new(Mutex::new(vec![]));
        let handlers: Vec<Box<dyn OutputHandler>> = vec![
            Box::new(CapturingHandler { name: "h1".into(), events: events.clone(), enabled: false }),
        ];
        let dir = tempfile::tempdir().unwrap();
        let dispatcher = OutputDispatcher::new(rx, handlers, dir.path().to_path_buf());
        let handle = tokio::spawn(dispatcher.run());
        tx.send(json!({"id":"1"})).await.unwrap();
        drop(tx);
        handle.await.unwrap();
        assert_eq!(events.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn write_failure_goes_to_dlq() {
        struct FailingHandler;
        #[async_trait::async_trait]
        impl OutputHandler for FailingHandler {
            fn name(&self) -> &str { "fail" }
            async fn write(&self, _: &serde_json::Value) -> Result<(), OutputError> {
                Err(OutputError::Io(std::io::Error::new(std::io::ErrorKind::Other, "boom")))
            }
            async fn close(&self) -> Result<(), OutputError> { Ok(()) }
        }
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let handlers: Vec<Box<dyn OutputHandler>> = vec![Box::new(FailingHandler)];
        let dir = tempfile::tempdir().unwrap();
        let dlq_path = dir.path().to_path_buf();
        let dispatcher = OutputDispatcher::new(rx, handlers, dlq_path.clone());
        let handle = tokio::spawn(dispatcher.run());
        tx.send(json!({"id":"1"})).await.unwrap();
        drop(tx);
        handle.await.unwrap();
        let dlq = dlq_path.join("failed_events.jsonl");
        assert!(dlq.exists());
        let line = std::fs::read_to_string(&dlq).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["event"]["id"], "1");
        assert!(v["error"].is_string());
        assert!(v["handler"].is_string());
        assert!(v["failed_at"].is_string());
    }
}
```

- [ ] **Step 2: Implement `crates/cs-output/src/dispatcher.rs`**

```rust
use chrono::Utc;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};
use crate::OutputHandler;

pub struct OutputDispatcher {
    rx:       Receiver<Value>,
    handlers: Vec<Box<dyn OutputHandler>>,
    dlq_dir:  PathBuf,
}

impl OutputDispatcher {
    pub fn new(
        rx:       Receiver<Value>,
        handlers: Vec<Box<dyn OutputHandler>>,
        dlq_dir:  PathBuf,
    ) -> Self {
        Self { rx, handlers, dlq_dir }
    }

    pub async fn run(mut self) {
        while let Some(event) = self.rx.recv().await {
            for handler in &self.handlers {
                if !handler.is_enabled() { continue; }
                if let Err(e) = handler.write(&event).await {
                    error!(handler = handler.name(), error = %e, "Write failed — routing to DLQ");
                    self.write_dlq(&event, handler.name(), &e.to_string()).await;
                }
            }
        }
        for handler in &self.handlers {
            if let Err(e) = handler.close().await {
                error!(handler = handler.name(), error = %e, "Close failed");
            }
        }
        info!("Dispatcher shut down");
    }

    async fn write_dlq(&self, event: &Value, handler: &str, error: &str) {
        let record = json!({
            "event":     event,
            "error":     error,
            "handler":   handler,
            "failed_at": Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });
        let dlq = self.dlq_dir.join("failed_events.jsonl");
        let line = format!("{}\n", serde_json::to_string(&record).unwrap_or_default());
        if let Err(e) = tokio::fs::OpenOptions::new()
            .create(true).append(true)
            .open(&dlq).await
            .and_then(|mut f| {
                use tokio::io::AsyncWriteExt;
                Box::pin(async move { f.write_all(line.as_bytes()).await })
            }).await
        {
            error!(error = %e, "DLQ write failed");
        }
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p cs-output dispatcher_tests
```
Expected: `3 passed`

- [ ] **Step 4: Commit**

```bash
git add crates/cs-output/src/dispatcher.rs crates/cs-output/src/lib.rs
git commit -m "feat(cs-output): OutputDispatcher with DLQ on write failure"
```

---

## Task 6: cs-collector — Error + AuthManager

**Files:**
- Create: `crates/cs-collector/src/error.rs`
- Create: `crates/cs-collector/src/auth.rs`
- Modify: `crates/cs-collector/src/lib.rs`

- [ ] **Step 1: Write failing auth tests**

Add to `crates/cs-collector/src/lib.rs`:

```rust
#[cfg(test)]
mod auth_tests {
    use crate::auth::AuthManager;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use serde_json::json;

    async fn mock_token_server(server: &MockServer, token: &str) {
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": token,
                "expires_in": 1799
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn fetches_token_on_first_call() {
        let server = MockServer::start().await;
        mock_token_server(&server, "tok-1").await;
        let auth = AuthManager::new(server.uri(), "id", "secret", 300);
        let tok = auth.get_token().await.unwrap();
        assert_eq!(tok, "tok-1");
    }

    #[tokio::test]
    async fn reuses_valid_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-1",
                "expires_in": 1799
            })))
            .expect(1) // must only be called once
            .mount(&server)
            .await;
        let auth = AuthManager::new(server.uri(), "id", "secret", 300);
        let _ = auth.get_token().await.unwrap();
        let tok = auth.get_token().await.unwrap();
        assert_eq!(tok, "tok-1");
        server.verify().await;
    }

    #[tokio::test]
    async fn singleflight_prevents_double_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(50))
                .set_body_json(json!({"access_token": "tok-1", "expires_in": 1799})))
            .expect(1)
            .mount(&server)
            .await;
        let auth = std::sync::Arc::new(AuthManager::new(server.uri(), "id", "secret", 300));
        let a1 = auth.clone();
        let a2 = auth.clone();
        let (t1, t2) = tokio::join!(
            tokio::spawn(async move { a1.get_token().await }),
            tokio::spawn(async move { a2.get_token().await }),
        );
        assert_eq!(t1.unwrap().unwrap(), "tok-1");
        assert_eq!(t2.unwrap().unwrap(), "tok-1");
        server.verify().await; // exactly 1 HTTP call
    }
}
```

- [ ] **Step 2: Create `crates/cs-collector/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Auth error: {0}")]
    Auth(String),
    #[error("Rate limited — retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("State error: {0}")]
    State(#[from] cs_state::StateError),
}
```

- [ ] **Step 3: Create `crates/cs-collector/src/auth.rs`**

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;
use crate::error::CollectorError;

struct TokenCache {
    token:      Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

pub struct AuthManager {
    base_url:               String,
    client_id:              String,
    client_secret:          String,
    refresh_buffer_seconds: i64,
    cache:                  Mutex<TokenCache>,
    refreshing:             AtomicBool,
    client:                 reqwest::Client,
}

impl AuthManager {
    pub fn new(
        base_url:               impl Into<String>,
        client_id:              impl Into<String>,
        client_secret:          impl Into<String>,
        refresh_buffer_seconds: u64,
    ) -> Self {
        Self {
            base_url:               base_url.into(),
            client_id:              client_id.into(),
            client_secret:          client_secret.into(),
            refresh_buffer_seconds: refresh_buffer_seconds as i64,
            cache:                  Mutex::new(TokenCache { token: None, expires_at: None }),
            refreshing:             AtomicBool::new(false),
            client:                 reqwest::Client::new(),
        }
    }

    pub async fn get_token(&self) -> Result<String, CollectorError> {
        loop {
            {
                let cache = self.cache.lock().await;
                if let (Some(tok), Some(exp)) = (&cache.token, cache.expires_at) {
                    if Utc::now() + Duration::seconds(self.refresh_buffer_seconds) < exp {
                        return Ok(tok.clone());
                    }
                }
            }

            // Singleflight guard
            if self.refreshing.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                continue;
            }

            let result = self.do_refresh().await;
            self.refreshing.store(false, Ordering::SeqCst);

            let (token, expires_in) = result?;
            let mut cache = self.cache.lock().await;
            cache.token      = Some(token.clone());
            cache.expires_at = Some(Utc::now() + Duration::seconds(expires_in));
            return Ok(token);
        }
    }

    async fn do_refresh(&self) -> Result<(String, i64), CollectorError> {
        let resp: serde_json::Value = self.client
            .post(format!("{}/oauth2/token", self.base_url))
            .form(&[("client_id", &self.client_id), ("client_secret", &self.client_secret)])
            .send().await?
            .json().await?;

        let token = resp["access_token"].as_str()
            .ok_or_else(|| CollectorError::Auth("missing access_token".into()))?
            .to_string();
        let expires_in = resp["expires_in"].as_i64().unwrap_or(1799);
        tracing::info!("Token refreshed, expires_in={}s", expires_in);
        Ok((token, expires_in))
    }

    pub async fn revoke(&self) {
        let cache = self.cache.lock().await;
        if let Some(tok) = &cache.token {
            let _ = self.client
                .post(format!("{}/oauth2/revoke", self.base_url))
                .form(&[
                    ("token",         tok.as_str()),
                    ("client_id",     &self.client_id),
                    ("client_secret", &self.client_secret),
                ])
                .send().await;
        }
    }
}
```

- [ ] **Step 4: Update `crates/cs-collector/src/lib.rs`**

```rust
pub mod auth;
pub mod error;
// remaining modules added in later tasks

pub use auth::AuthManager;
pub use error::CollectorError;
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p cs-collector auth_tests
```
Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add crates/cs-collector/
git commit -m "feat(cs-collector): CollectorError + AuthManager with singleflight refresh"
```

---

## Task 7: cs-collector — ApiClient

**Files:**
- Create: `crates/cs-collector/src/api_client.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-collector/src/lib.rs`:

```rust
#[cfg(test)]
mod api_tests {
    use crate::api_client::ApiClient;
    use crate::auth::AuthManager;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{header_exists, method, path};

    fn make_client(base_url: &str) -> ApiClient {
        let auth = Arc::new(AuthManager::new(base_url, "id", "secret", 300));
        ApiClient::new(auth, base_url, 100)
    }

    async fn mock_token(server: &MockServer) {
        Mock::given(method("POST")).and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok","expires_in":1799})))
            .mount(server).await;
    }

    #[tokio::test]
    async fn get_attaches_bearer_token() {
        let server = MockServer::start().await;
        mock_token(&server).await;
        Mock::given(method("GET"))
            .and(path("/some/path"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"resources":[]})))
            .mount(&server).await;
        let client = make_client(&server.uri());
        let resp: serde_json::Value = client.get("/some/path", &[]).await.unwrap();
        assert!(resp["resources"].is_array());
    }

    #[tokio::test]
    async fn retries_on_500_then_succeeds() {
        let server = MockServer::start().await;
        mock_token(&server).await;
        Mock::given(method("GET")).and(path("/retry"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(2)
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/retry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok":true})))
            .mount(&server).await;
        let client = make_client(&server.uri());
        let resp: serde_json::Value = client.get("/retry", &[]).await.unwrap();
        assert_eq!(resp["ok"], true);
    }

    #[tokio::test]
    async fn handles_429_with_retry_after_epoch_ms() {
        let server = MockServer::start().await;
        mock_token(&server).await;
        // RetryAfter = now + 100ms in epoch ms
        let retry_at = (chrono::Utc::now() + chrono::Duration::milliseconds(100))
            .timestamp_millis();
        Mock::given(method("GET")).and(path("/limited"))
            .respond_with(ResponseTemplate::new(429)
                .insert_header("X-RateLimit-RetryAfter", retry_at.to_string()))
            .up_to_n_times(1)
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/limited"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok":true})))
            .mount(&server).await;
        let client = make_client(&server.uri());
        let start = std::time::Instant::now();
        let resp: serde_json::Value = client.get("/limited", &[]).await.unwrap();
        assert!(start.elapsed().as_millis() >= 100);
        assert_eq!(resp["ok"], true);
    }
}
```

- [ ] **Step 2: Implement `crates/cs-collector/src/api_client.rs`**

```rust
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use serde_json::Value;
use tracing::warn;
use crate::auth::AuthManager;
use crate::error::CollectorError;

const MAX_RETRIES: u32 = 3;

pub struct ApiClient {
    auth:     Arc<AuthManager>,
    base_url: String,
    client:   reqwest::Client,
    limiter:  Arc<DefaultDirectRateLimiter>,
}

impl ApiClient {
    /// `requests_per_second`: shared token-bucket rate across all collectors.
    /// Pass the same `Arc<ApiClient>` to every collector so they share one limiter.
    pub fn new(auth: Arc<AuthManager>, base_url: &str, requests_per_second: u32) -> Self {
        let rps     = NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::new(100).unwrap());
        let limiter = Arc::new(RateLimiter::direct(Quota::per_second(rps)));
        Self {
            auth,
            base_url: base_url.trim_end_matches('/').to_string(),
            client:   reqwest::Client::new(),
            limiter,
        }
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value, CollectorError> {
        self.request(reqwest::Method::GET, path, params, None).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, CollectorError> {
        self.request(reqwest::Method::POST, path, &[], Some(body)).await
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path:   &str,
        params: &[(&str, String)],
        body:   Option<&Value>,
    ) -> Result<Value, CollectorError> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempts = 0u32;

        loop {
            // Proactive rate limiting — prevents burst amplification across collectors
            self.limiter.until_ready().await;

            let token = self.auth.get_token().await?;
            let mut req = self.client
                .request(method.clone(), &url)
                .bearer_auth(&token);

            if !params.is_empty() {
                req = req.query(params);
            }
            if let Some(b) = body {
                req = req.json(b);
            }

            let resp = req.send().await?;
            let status = resp.status();

            if status == 429 {
                let wait_ms = resp.headers()
                    .get("X-RateLimit-RetryAfter")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|epoch_ms| {
                        let now_ms = Utc::now().timestamp_millis();
                        (epoch_ms - now_ms).max(0) as u64
                    })
                    .unwrap_or(1000);
                warn!("Rate limited — waiting {}ms", wait_ms);
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                continue;
            }

            if status == 401 && attempts == 0 {
                // Force refresh by invalidating via re-entering get_token after next call
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if status.is_server_error() && attempts < MAX_RETRIES {
                attempts += 1;
                let backoff = 500 * 2u64.pow(attempts - 1);
                warn!(status = %status, attempt = attempts, "Server error — retrying in {}ms", backoff);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }

            let body = resp.error_for_status()?.json::<Value>().await?;
            return Ok(body);
        }
    }
}
```

- [ ] **Step 3: Update `crates/cs-collector/src/lib.rs`**

```rust
pub mod api_client;
pub mod auth;
pub mod error;

pub use api_client::ApiClient;
pub use auth::AuthManager;
pub use error::CollectorError;
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p cs-collector api_tests
```
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/cs-collector/src/api_client.rs crates/cs-collector/src/lib.rs
git commit -m "feat(cs-collector): ApiClient with retry, 429 handling, bearer auth"
```

---

## Task 8: cs-collector — Base Helpers + CollectorTask Trait

**Files:**
- Create: `crates/cs-collector/src/base.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-collector/src/lib.rs`:

```rust
#[cfg(test)]
mod base_tests {
    use crate::base::{enrich_event, should_skip_event};
    use serde_json::json;
    use std::collections::HashSet;

    fn seen(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn skip_if_in_seen_ids() {
        assert!(should_skip_event("2026-03-31T05:00:00Z", "id-1", "2026-03-30T00:00:00Z", "", &seen(&["id-1"])));
    }

    #[test]
    fn no_skip_if_newer_ts() {
        assert!(!should_skip_event("2026-03-31T05:00:01Z", "id-2", "2026-03-31T05:00:00Z", "id-1", &seen(&[])));
    }

    #[test]
    fn skip_if_older_ts() {
        assert!(should_skip_event("2026-03-30T00:00:00Z", "id-0", "2026-03-31T05:00:00Z", "id-1", &seen(&[])));
    }

    #[test]
    fn skip_same_ts_lower_id() {
        assert!(should_skip_event("2026-03-31T05:00:00Z", "id-0", "2026-03-31T05:00:00Z", "id-1", &seen(&[])));
    }

    #[test]
    fn no_skip_same_ts_higher_id() {
        assert!(!should_skip_event("2026-03-31T05:00:00Z", "id-2", "2026-03-31T05:00:00Z", "id-1", &seen(&[])));
    }

    #[test]
    fn enrich_adds_required_fields() {
        let event = json!({"id": "abc", "created_timestamp": "2026-03-31T05:00:00Z", "severity": 3});
        let enriched = enrich_event(event, "alerts", "FCT", "id");
        assert_eq!(enriched["_source"], "alerts");
        assert_eq!(enriched["_tag"], "FCT");
        assert_eq!(enriched["_event_id"], "abc");
        assert!(enriched["_ingest_timestamp"].is_string());
        assert_eq!(enriched["_source_timestamp"], "2026-03-31T05:00:00Z");
    }
}
```

- [ ] **Step 2: Implement `crates/cs-collector/src/base.rs`**

```rust
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use cs_state::StateManager;
use crate::error::CollectorError;

pub const COLLECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn should_skip_event(
    event_ts:  &str,
    event_id:  &str,
    last_ts:   &str,
    last_id:   &str,
    seen_ids:  &HashSet<String>,
) -> bool {
    if seen_ids.contains(event_id) { return true; }
    if event_ts > last_ts          { return false; }
    if event_ts == last_ts         { return event_id <= last_id; }
    true
}

pub fn enrich_event(mut event: Value, source: &str, tag: &str, id_field: &str) -> Value {
    let event_id   = event[id_field].as_str().unwrap_or("").to_string();
    let source_ts  = event["created_timestamp"].as_str().unwrap_or("").to_string();
    let obj        = event.as_object_mut().unwrap();
    obj.insert("_ingest_timestamp".into(),  json!(Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()));
    obj.insert("_source_timestamp".into(),  json!(source_ts));
    obj.insert("_source".into(),            json!(source));
    obj.insert("_tag".into(),               json!(tag));
    obj.insert("_collector_version".into(), json!(COLLECTOR_VERSION));
    obj.insert("_event_id".into(),          json!(event_id));
    event
}

#[async_trait]
pub trait CollectorTask: Send + Sync {
    fn source_name(&self)  -> &str;
    fn poll_interval(&self) -> Duration;

    async fn poll(
        &self,
        state: Arc<Mutex<StateManager>>,
        tx:    &mpsc::Sender<Value>,
    ) -> Result<(), CollectorError>;
}
```

- [ ] **Step 3: Update `crates/cs-collector/src/lib.rs`**

```rust
pub mod api_client;
pub mod auth;
pub mod base;
pub mod error;

pub use api_client::ApiClient;
pub use auth::AuthManager;
pub use base::CollectorTask;
pub use error::CollectorError;
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p cs-collector base_tests
```
Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/cs-collector/src/base.rs crates/cs-collector/src/lib.rs
git commit -m "feat(cs-collector): CollectorTask trait, enrich_event, should_skip_event"
```

---

## Task 9: cs-collector — AlertsCollector

**Files:**
- Create: `crates/cs-collector/src/alerts.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-collector/src/lib.rs`:

```rust
#[cfg(test)]
mod alerts_tests {
    use crate::alerts::AlertsCollector;
    use crate::api_client::ApiClient;
    use crate::auth::AuthManager;
    use crate::base::CollectorTask;
    use cs_state::StateManager;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    async fn setup(server: &MockServer) -> (Arc<ApiClient>, Arc<Mutex<StateManager>>) {
        // Mock OAuth
        Mock::given(method("POST")).and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok","expires_in":1799})))
            .mount(server).await;

        let auth = Arc::new(AuthManager::new(server.uri(), "id", "secret", 300));
        let api  = Arc::new(ApiClient::new(auth, &server.uri(), 100));
        let dir  = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::load(dir.path().join("state.json")).unwrap()
        ));
        (api, state)
    }

    #[tokio::test]
    async fn poll_enqueues_events() {
        let server = MockServer::start().await;
        let (api, state) = setup(&server).await;

        Mock::given(method("GET")).and(path("/alerts/queries/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": ["aid:a:alert:id-1", "aid:a:alert:id-2"],
                "meta": {"pagination": {}}
            })))
            .mount(&server).await;

        Mock::given(method("POST")).and(path("/alerts/entities/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [
                    {"id": "aid:a:alert:id-1", "created_timestamp": "2026-03-31T05:01:00Z", "severity": 3},
                    {"id": "aid:a:alert:id-2", "created_timestamp": "2026-03-31T05:02:00Z", "severity": 2}
                ]
            })))
            .mount(&server).await;

        let collector = AlertsCollector::new(api, "FCT",
            std::time::Duration::from_secs(30), 100, 5, 500, false,
            std::collections::HashSet::new());
        let (tx, mut rx) = mpsc::channel(10);
        collector.poll(state, &tx).await.unwrap();
        drop(tx);
        let mut events = vec![];
        while let Some(e) = rx.recv().await { events.push(e); }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["_source"], "alerts");
    }

    #[tokio::test]
    async fn poll_skips_duplicate_via_seen_ids() {
        let server = MockServer::start().await;
        let (api, state) = setup(&server).await;

        Mock::given(method("GET")).and(path("/alerts/queries/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": ["aid:a:alert:id-1"],
                "meta": {"pagination": {}}
            })))
            .mount(&server).await;

        Mock::given(method("POST")).and(path("/alerts/entities/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [{"id":"aid:a:alert:id-1","created_timestamp":"2026-03-31T05:00:00Z"}]
            })))
            .mount(&server).await;

        let mut seen = std::collections::HashSet::new();
        seen.insert("aid:a:alert:id-1".to_string());
        let collector = AlertsCollector::new(api, "FCT",
            std::time::Duration::from_secs(30), 100, 5, 500, false, seen);
        let (tx, mut rx) = mpsc::channel(10);
        collector.poll(state, &tx).await.unwrap();
        drop(tx);
        assert!(rx.recv().await.is_none()); // nothing enqueued
    }

    #[tokio::test]
    async fn poll_paginates() {
        let server = MockServer::start().await;
        let (api, state) = setup(&server).await;

        Mock::given(method("GET")).and(path("/alerts/queries/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": ["aid:a:alert:p1"],
                "meta": {"pagination": {"after": "cursor-abc"}}
            })))
            .up_to_n_times(1)
            .mount(&server).await;

        Mock::given(method("GET")).and(path("/alerts/queries/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": ["aid:a:alert:p2"],
                "meta": {"pagination": {}}
            })))
            .mount(&server).await;

        Mock::given(method("POST")).and(path("/alerts/entities/alerts/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [{"id":"aid:a:alert:p1","created_timestamp":"2026-03-31T05:01:00Z"},
                               {"id":"aid:a:alert:p2","created_timestamp":"2026-03-31T05:02:00Z"}]
            })))
            .mount(&server).await;

        let collector = AlertsCollector::new(api, "FCT",
            std::time::Duration::from_secs(30), 1, 5, 500, false,
            std::collections::HashSet::new());
        let (tx, mut rx) = mpsc::channel(10);
        collector.poll(state, &tx).await.unwrap();
        drop(tx);
        let mut count = 0;
        while rx.recv().await.is_some() { count += 1; }
        assert_eq!(count, 2);
    }
}
```

- [ ] **Step 2: Implement `crates/cs-collector/src/alerts.rs`**

```rust
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, Duration as CDuration, Utc};
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use cs_state::StateManager;
use crate::api_client::ApiClient;
use crate::base::{enrich_event, should_skip_event, CollectorTask};
use crate::error::CollectorError;

const QUERY_PATH:  &str = "/alerts/queries/alerts/v2";
const ENTITY_PATH: &str = "/alerts/entities/alerts/v2";
const TS_FIELD:    &str = "created_timestamp";
const ID_FIELD:    &str = "id";

pub struct AlertsCollector {
    api:                 Arc<ApiClient>,
    tag:                 String,
    poll_interval:       Duration,
    batch_size:          u32,
    dedup_window_min:    i64,
    dedup_window_size:   usize,
    checkpoint_per_page: bool,
    seen_ids:            Mutex<HashSet<String>>,
}

impl AlertsCollector {
    pub fn new(
        api:                 Arc<ApiClient>,
        tag:                 &str,
        poll_interval:       Duration,
        batch_size:          u32,
        dedup_window_min:    i64,
        dedup_window_size:   usize,
        checkpoint_per_page: bool,
        initial_seen:        HashSet<String>,
    ) -> Self {
        Self {
            api,
            tag:                 tag.to_string(),
            poll_interval,
            batch_size,
            dedup_window_min,
            dedup_window_size,
            checkpoint_per_page,
            seen_ids:            Mutex::new(initial_seen),
        }
    }
}

#[async_trait]
impl CollectorTask for AlertsCollector {
    fn source_name(&self)   -> &str      { "alerts" }
    fn poll_interval(&self) -> Duration  { self.poll_interval }

    async fn poll(
        &self,
        state: Arc<Mutex<StateManager>>,
        tx:    &mpsc::Sender<Value>,
    ) -> Result<(), CollectorError> {
        let src_state = { state.lock().await.get("alerts") };
        let last_ts   = src_state.last_timestamp.clone();
        let last_id   = src_state.last_id.clone();

        let window_start = DateTime::parse_from_rfc3339(&last_ts)
            .map(|dt| (dt.with_timezone(&Utc) - CDuration::minutes(self.dedup_window_min))
                .format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|_| last_ts.clone());

        let mut new_ts  = last_ts.clone();
        let mut new_id  = last_id.clone();
        let mut after: Option<String> = None;
        let mut seen    = self.seen_ids.lock().await;

        loop {
            let mut params = vec![
                ("filter", format!("created_timestamp:>='{}'", window_start)),
                ("sort",   "created_timestamp.asc".to_string()),
                ("limit",  self.batch_size.to_string()),
            ];
            if let Some(a) = &after {
                params.push(("after", a.clone()));
            }

            let qr = self.api.get(QUERY_PATH, &params.iter()
                .map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>()).await?;

            let ids: Vec<String> = qr["resources"].as_array().unwrap_or(&vec![])
                .iter().filter_map(|v| v.as_str().map(String::from)).collect();

            if !ids.is_empty() {
                let dr = self.api.post(ENTITY_PATH, &serde_json::json!({"composite_ids": ids})).await?;
                for event in dr["resources"].as_array().cloned().unwrap_or_default() {
                    let ets = event[TS_FIELD].as_str().unwrap_or("").to_string();
                    let eid = event[ID_FIELD].as_str().unwrap_or("").to_string();
                    if should_skip_event(&ets, &eid, &last_ts, &last_id, &seen) { continue; }
                    seen.insert(eid.clone());
                    let enriched = enrich_event(event, "alerts", &self.tag, ID_FIELD);
                    let _ = tx.send(enriched).await;
                    if ets > new_ts || (ets == new_ts && eid > new_id) {
                        new_ts = ets; new_id = eid;
                    }
                }
                if self.checkpoint_per_page {
                    let ids: Vec<String> = seen.iter().cloned().collect();
                    state.lock().await.update("alerts", &new_ts, &new_id, &ids, self.dedup_window_size)?;
                }
            }

            after = qr["meta"]["pagination"]["after"].as_str().map(String::from);
            if after.is_none() { break; }
        }

        // Trim seen_ids
        if seen.len() > self.dedup_window_size {
            let mut v: Vec<String> = seen.drain().collect();
            v.sort();
            *seen = v.split_off(v.len() - self.dedup_window_size).into_iter().collect();
        }

        let ids: Vec<String> = seen.iter().cloned().collect();
        state.lock().await.update("alerts", &new_ts, &new_id, &ids, self.dedup_window_size)?;

        tracing::info!(source = "alerts", last_ts = %new_ts, "Poll complete");
        Ok(())
    }
}
```

- [ ] **Step 3: Update `crates/cs-collector/src/lib.rs`**

```rust
pub mod alerts;
pub mod api_client;
pub mod auth;
pub mod base;
pub mod error;

pub use alerts::AlertsCollector;
pub use api_client::ApiClient;
pub use auth::AuthManager;
pub use base::CollectorTask;
pub use error::CollectorError;
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p cs-collector alerts_tests
```
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/cs-collector/src/alerts.rs crates/cs-collector/src/lib.rs
git commit -m "feat(cs-collector): AlertsCollector with sliding window + composite_ids"
```

---

## Task 10: cs-collector — AuditEventsCollector + HostsCollector

**Files:**
- Create: `crates/cs-collector/src/audit_events.rs`
- Create: `crates/cs-collector/src/hosts.rs`

- [ ] **Step 1: Write failing tests**

Add to `crates/cs-collector/src/lib.rs`:

```rust
#[cfg(test)]
mod audit_tests {
    use crate::audit_events::AuditEventsCollector;
    use crate::api_client::ApiClient;
    use crate::auth::AuthManager;
    use crate::base::CollectorTask;
    use cs_state::StateManager;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn audit_poll_enqueues_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok","expires_in":1799})))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/audit/v1/audits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [
                    {"id":"ev-1","created_timestamp":"2026-03-31T05:01:00Z","action":"login"}
                ],
                "meta": {"pagination": {"total": 1, "offset": 0}}
            })))
            .mount(&server).await;

        let auth  = Arc::new(AuthManager::new(server.uri(), "id", "secret", 300));
        let api   = Arc::new(ApiClient::new(auth, &server.uri(), 100));
        let dir   = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::load(dir.path().join("state.json")).unwrap()
        ));
        let collector = AuditEventsCollector::new(api, "FCT",
            std::time::Duration::from_secs(30), 100, 500);
        let (tx, mut rx) = mpsc::channel(10);
        collector.poll(state, &tx).await.unwrap();
        drop(tx);
        let event = rx.recv().await.unwrap();
        assert_eq!(event["_source"], "audit_events");
        assert_eq!(event["action"], "login");
    }
}

#[cfg(test)]
mod hosts_tests {
    use crate::hosts::HostsCollector;
    use crate::api_client::ApiClient;
    use crate::auth::AuthManager;
    use crate::base::CollectorTask;
    use cs_state::StateManager;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn hosts_poll_enqueues_event() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok","expires_in":1799})))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/devices/queries/devices/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": ["device-id-1"],
                "meta": {"pagination": {}}
            })))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/devices/entities/devices/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resources": [{"device_id":"device-id-1","hostname":"HOST1","modified_timestamp":"2026-03-31T05:01:00Z"}]
            })))
            .mount(&server).await;

        let auth  = Arc::new(AuthManager::new(server.uri(), "id", "secret", 300));
        let api   = Arc::new(ApiClient::new(auth, &server.uri(), 100));
        let dir   = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(
            StateManager::load(dir.path().join("state.json")).unwrap()
        ));
        let collector = HostsCollector::new(api, "FCT",
            std::time::Duration::from_secs(30), 100, 5, 500);
        let (tx, mut rx) = mpsc::channel(10);
        collector.poll(state, &tx).await.unwrap();
        drop(tx);
        let event = rx.recv().await.unwrap();
        assert_eq!(event["_source"], "hosts");
        assert_eq!(event["hostname"], "HOST1");
    }
}
```

- [ ] **Step 2: Implement `crates/cs-collector/src/audit_events.rs`**

```rust
// Audit events use offset pagination (not cursor) at /audit/v1/audits
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use cs_state::StateManager;
use crate::api_client::ApiClient;
use crate::base::{enrich_event, should_skip_event, CollectorTask};
use crate::error::CollectorError;

const AUDIT_PATH: &str = "/audit/v1/audits";
const TS_FIELD:   &str = "created_timestamp";
const ID_FIELD:   &str = "id";

pub struct AuditEventsCollector {
    api:               Arc<ApiClient>,
    tag:               String,
    poll_interval:     Duration,
    batch_size:        u32,
    dedup_window_size: usize,
    seen_ids:          Mutex<HashSet<String>>,
}

impl AuditEventsCollector {
    pub fn new(
        api:               Arc<ApiClient>,
        tag:               &str,
        poll_interval:     Duration,
        batch_size:        u32,
        dedup_window_size: usize,
    ) -> Self {
        Self {
            api,
            tag:               tag.to_string(),
            poll_interval,
            batch_size,
            dedup_window_size,
            seen_ids:          Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl CollectorTask for AuditEventsCollector {
    fn source_name(&self)   -> &str     { "audit_events" }
    fn poll_interval(&self) -> Duration { self.poll_interval }

    async fn poll(
        &self,
        state: Arc<Mutex<StateManager>>,
        tx:    &mpsc::Sender<Value>,
    ) -> Result<(), CollectorError> {
        let src   = { state.lock().await.get("audit_events") };
        let last_ts = src.last_timestamp.clone();
        let last_id = src.last_id.clone();

        let mut new_ts = last_ts.clone();
        let mut new_id = last_id.clone();
        let mut offset = 0u32;
        let mut seen   = self.seen_ids.lock().await;

        // Seed seen_ids from persisted last_n_ids on first poll
        if seen.is_empty() {
            for id in &src.last_n_ids { seen.insert(id.clone()); }
        }

        loop {
            let params = vec![
                ("sort",   "created_timestamp.asc".to_string()),
                ("limit",  self.batch_size.to_string()),
                ("offset", offset.to_string()),
            ];
            let resp = self.api.get(AUDIT_PATH, &params.iter()
                .map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>()).await?;

            let events = resp["resources"].as_array().cloned().unwrap_or_default();
            if events.is_empty() { break; }

            for event in &events {
                let ets = event[TS_FIELD].as_str().unwrap_or("").to_string();
                let eid = event[ID_FIELD].as_str().unwrap_or("").to_string();
                if should_skip_event(&ets, &eid, &last_ts, &last_id, &seen) { continue; }
                seen.insert(eid.clone());
                let enriched = enrich_event(event.clone(), "audit_events", &self.tag, ID_FIELD);
                let _ = tx.send(enriched).await;
                if ets > new_ts || (ets == new_ts && eid > new_id) {
                    new_ts = ets; new_id = eid;
                }
            }

            let total  = resp["meta"]["pagination"]["total"].as_u64().unwrap_or(0);
            offset    += events.len() as u32;
            if offset as u64 >= total { break; }
        }

        if seen.len() > self.dedup_window_size {
            let mut v: Vec<String> = seen.drain().collect();
            v.sort();
            *seen = v.split_off(v.len() - self.dedup_window_size).into_iter().collect();
        }

        let ids: Vec<String> = seen.iter().cloned().collect();
        state.lock().await.update("audit_events", &new_ts, &new_id, &ids, self.dedup_window_size)?;
        tracing::info!(source = "audit_events", last_ts = %new_ts, "Poll complete");
        Ok(())
    }
}
```

- [ ] **Step 3: Implement `crates/cs-collector/src/hosts.rs`**

```rust
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, Duration as CDuration, Utc};
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use cs_state::StateManager;
use crate::api_client::ApiClient;
use crate::base::{enrich_event, should_skip_event, CollectorTask};
use crate::error::CollectorError;

const QUERY_PATH:  &str = "/devices/queries/devices/v1";
const ENTITY_PATH: &str = "/devices/entities/devices/v2";
const TS_FIELD:    &str = "modified_timestamp";
const ID_FIELD:    &str = "device_id";

pub struct HostsCollector {
    api:               Arc<ApiClient>,
    tag:               String,
    poll_interval:     Duration,
    batch_size:        u32,
    dedup_window_min:  i64,
    dedup_window_size: usize,
    seen_ids:          Mutex<HashSet<String>>,
}

impl HostsCollector {
    pub fn new(
        api:               Arc<ApiClient>,
        tag:               &str,
        poll_interval:     Duration,
        batch_size:        u32,
        dedup_window_min:  i64,
        dedup_window_size: usize,
    ) -> Self {
        Self {
            api,
            tag: tag.to_string(),
            poll_interval,
            batch_size,
            dedup_window_min,
            dedup_window_size,
            seen_ids: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl CollectorTask for HostsCollector {
    fn source_name(&self)   -> &str     { "hosts" }
    fn poll_interval(&self) -> Duration { self.poll_interval }

    async fn poll(
        &self,
        state: Arc<Mutex<StateManager>>,
        tx:    &mpsc::Sender<Value>,
    ) -> Result<(), CollectorError> {
        let src     = { state.lock().await.get("hosts") };
        let last_ts = src.last_timestamp.clone();
        let last_id = src.last_id.clone();

        let window_start = DateTime::parse_from_rfc3339(&last_ts)
            .map(|dt| (dt.with_timezone(&Utc) - CDuration::minutes(self.dedup_window_min))
                .format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|_| last_ts.clone());

        let mut new_ts = last_ts.clone();
        let mut new_id = last_id.clone();
        let mut after: Option<String> = None;
        let mut seen   = self.seen_ids.lock().await;

        if seen.is_empty() {
            for id in &src.last_n_ids { seen.insert(id.clone()); }
        }

        loop {
            let mut params = vec![
                ("filter", format!("modified_timestamp:>='{}'", window_start)),
                ("sort",   "modified_timestamp.asc".to_string()),
                ("limit",  self.batch_size.to_string()),
            ];
            if let Some(a) = &after { params.push(("after", a.clone())); }

            let qr = self.api.get(QUERY_PATH, &params.iter()
                .map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>()).await?;

            let ids: Vec<String> = qr["resources"].as_array().unwrap_or(&vec![])
                .iter().filter_map(|v| v.as_str().map(String::from)).collect();

            if !ids.is_empty() {
                let id_params: Vec<(&str, String)> = ids.iter()
                    .map(|id| ("ids", id.clone())).collect();
                let dr = self.api.get(ENTITY_PATH, &id_params.iter()
                    .map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>()).await?;

                for event in dr["resources"].as_array().cloned().unwrap_or_default() {
                    let ets = event[TS_FIELD].as_str().unwrap_or("").to_string();
                    let eid = event[ID_FIELD].as_str().unwrap_or("").to_string();
                    if should_skip_event(&ets, &eid, &last_ts, &last_id, &seen) { continue; }
                    seen.insert(eid.clone());
                    let enriched = enrich_event(event, "hosts", &self.tag, ID_FIELD);
                    let _ = tx.send(enriched).await;
                    if ets > new_ts || (ets == new_ts && eid > new_id) {
                        new_ts = ets; new_id = eid;
                    }
                }
            }

            after = qr["meta"]["pagination"]["after"].as_str().map(String::from);
            if after.is_none() { break; }
        }

        if seen.len() > self.dedup_window_size {
            let mut v: Vec<String> = seen.drain().collect();
            v.sort();
            *seen = v.split_off(v.len() - self.dedup_window_size).into_iter().collect();
        }

        let ids: Vec<String> = seen.iter().cloned().collect();
        state.lock().await.update("hosts", &new_ts, &new_id, &ids, self.dedup_window_size)?;
        tracing::info!(source = "hosts", last_ts = %new_ts, "Poll complete");
        Ok(())
    }
}
```

- [ ] **Step 4: Update `crates/cs-collector/src/lib.rs`**

```rust
pub mod alerts;
pub mod api_client;
pub mod audit_events;
pub mod auth;
pub mod base;
pub mod error;
pub mod hosts;

pub use alerts::AlertsCollector;
pub use api_client::ApiClient;
pub use audit_events::AuditEventsCollector;
pub use auth::AuthManager;
pub use base::CollectorTask;
pub use error::CollectorError;
pub use hosts::HostsCollector;
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p cs-collector
```
Expected: all tests pass (audit_tests, hosts_tests + previous tasks)

- [ ] **Step 6: Commit**

```bash
git add crates/cs-collector/
git commit -m "feat(cs-collector): AuditEventsCollector + HostsCollector"
```

---

## Task 11: cs-main — Config + Metrics

**Files:**
- Create: `crates/cs-main/src/config.rs`
- Create: `crates/cs-main/src/metrics.rs`

- [ ] **Step 1: Implement `crates/cs-main/src/config.rs`**

```rust
use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub falcon:     FalconConfig,
    pub collection: CollectionConfig,
    pub outputs:    OutputsConfig,
    pub supervisor: SupervisorConfig,
    pub metrics:    MetricsConfig,
}

#[derive(Debug, Deserialize)]
pub struct FalconConfig {
    pub base_url:                     String,
    pub client_id:                    String,
    pub client_secret:                String,
    #[serde(default = "default_refresh_buffer")]
    pub token_refresh_buffer_seconds: u64,
}
fn default_refresh_buffer() -> u64 { 300 }

#[derive(Debug, Deserialize)]
pub struct CollectionConfig {
    pub tag:                     String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds:   u64,
    #[serde(default = "default_batch_size")]
    pub batch_size:              u32,
    #[serde(default)]
    pub checkpoint_per_page:     bool,
    #[serde(default = "default_dedup_window_minutes")]
    pub dedup_window_minutes:    i64,
    #[serde(default = "default_dedup_window_size")]
    pub dedup_window_size:       usize,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity:          usize,
    pub sources:                 SourcesConfig,
}
fn default_poll_interval()      -> u64   { 30 }
fn default_batch_size()         -> u32   { 100 }
fn default_dedup_window_minutes()-> i64  { 5 }
fn default_dedup_window_size()  -> usize { 500 }
fn default_queue_capacity()     -> usize { 10_000 }

#[derive(Debug, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default)] pub alerts:       SourceConfig,
    #[serde(default)] pub audit_events: SourceConfig,
    #[serde(default)] pub hosts:        SourceConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct SourceConfig {
    #[serde(default)] pub enabled:              bool,
    pub poll_interval_seconds:                  Option<u64>,
    pub batch_size:                             Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutputsConfig {
    #[serde(default)] pub json_file:  JsonFileConfig,
    #[serde(default)] pub http_post:  HttpPostConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct JsonFileConfig {
    #[serde(default)] pub enabled:          bool,
    #[serde(default = "default_logs_dir")] pub directory: String,
    #[serde(default = "default_min_free")]  pub min_free_disk_mb: u64,
}
fn default_logs_dir() -> String { "logs".into() }
fn default_min_free() -> u64    { 500 }

#[derive(Debug, Deserialize, Default)]
pub struct HttpPostConfig {
    #[serde(default)] pub enabled:    bool,
    #[serde(default)] pub url:        String,
    #[serde(default = "default_http_batch")] pub batch_size: usize,
    #[serde(default)] pub headers:    HashMap<String, String>,
}
fn default_http_batch() -> usize { 100 }

#[derive(Debug, Deserialize)]
pub struct SupervisorConfig {
    #[serde(default = "default_max_restarts")]       pub max_restarts:                u32,
    #[serde(default = "default_backoff_base")]       pub restart_backoff_base_seconds: u64,
    #[serde(default = "default_backoff_max")]        pub restart_backoff_max_seconds:  u64,
    #[serde(default = "default_recovery_seconds")]   pub restart_recovery_seconds:     u64,
}
impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            max_restarts:                10,
            restart_backoff_base_seconds: 10,
            restart_backoff_max_seconds:  120,
            restart_recovery_seconds:     300,
        }
    }
}
fn default_max_restarts()     -> u32 { 10 }
fn default_backoff_base()     -> u64 { 10 }
fn default_backoff_max()      -> u64 { 120 }
fn default_recovery_seconds() -> u64 { 300 }

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_seconds: u64,
}
impl Default for MetricsConfig {
    fn default() -> Self { Self { heartbeat_interval_seconds: 30 } }
}
fn default_heartbeat() -> u64 { 30 }

pub fn load(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    // Substitute env vars in raw TOML string
    let raw = std::fs::read_to_string(path)?;
    let substituted = substitute_env(&raw)?;
    Ok(toml::from_str(&substituted)?)
}

fn substitute_env(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let re = regex::Regex::new(r"\$\{([^}]+)\}").unwrap();
    let mut result = raw.to_string();
    for cap in re.captures_iter(raw) {
        let var = &cap[1];
        let val = std::env::var(var)
            .map_err(|_| format!("Environment variable '{}' is not set", var))?;
        result = result.replace(&cap[0], &val);
    }
    Ok(result)
}
```

> Note: Add `regex = "1"` to `cs-main/Cargo.toml` dependencies.

- [ ] **Step 2: Write config test**

Add to `crates/cs-main/src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_minimal_config() {
        let toml = r#"
[falcon]
base_url      = "https://api.us-2.crowdstrike.com"
client_id     = "test_id"
client_secret = "test_secret"

[collection]
tag = "FCT"

[collection.sources.alerts]
enabled = true

[collection.sources.audit_events]
enabled = false

[collection.sources.hosts]
enabled = false

[outputs.json_file]
enabled   = true
directory = "logs"

[supervisor]
[metrics]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.collection.tag, "FCT");
        assert!(cfg.collection.sources.alerts.enabled);
        assert_eq!(cfg.collection.dedup_window_minutes, 5);
    }
}
```

- [ ] **Step 3: Run test**

```bash
cargo test -p cs-main loads_minimal_config
```
Expected: `1 passed`

- [ ] **Step 4: Implement `crates/cs-main/src/metrics.rs`**

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use serde_json::json;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Default, Clone)]
pub struct CollectorMetrics {
    pub last_successful_poll: HashMap<String, String>,
    pub api_failures:         HashMap<String, u64>,
    pub collector_states:     HashMap<String, String>,
}

pub async fn heartbeat_loop(
    metrics:  Arc<Mutex<CollectorMetrics>>,
    queue_depth_fn: impl Fn() -> usize + Send + 'static,
    interval: Duration,
    token:    CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = ticker.tick() => {
                let m = metrics.lock().await.clone();
                let depth = queue_depth_fn();
                let all_ok = !m.collector_states.values().all(|s| s == "failed");
                info!(
                    heartbeat = true,
                    status = if all_ok { "ok" } else { "degraded" },
                    queue_depth = depth,
                    last_successful_poll = ?m.last_successful_poll,
                    api_failures = ?m.api_failures,
                    collector_states = ?m.collector_states,
                    timestamp = %Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                    "heartbeat"
                );
            }
        }
    }
}
```

- [ ] **Step 5: Commit**

```bash
git add crates/cs-main/src/config.rs crates/cs-main/src/metrics.rs
git commit -m "feat(cs-main): TOML config structs + structured heartbeat metrics"
```

---

## Task 12: cs-main — Supervisor + Entry Point

**Files:**
- Modify: `crates/cs-main/src/main.rs`

- [ ] **Step 1: Implement `crates/cs-main/src/main.rs`**

```rust
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::Parser;
use cs_collector::{AlertsCollector, ApiClient, AuditEventsCollector, AuthManager, CollectorTask, HostsCollector};
use cs_output::{dispatcher::OutputDispatcher, json_file::JsonFileOutput, http_post::HttpPostOutput, OutputHandler};
use cs_state::StateManager;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

mod config;
mod metrics;
use metrics::CollectorMetrics;

#[derive(Parser)]
#[command(name = "cs-collector", about = "CrowdStrike log collector")]
struct Cli {
    #[arg(long, value_name = "DATE", value_parser = parse_since,
          help = "Fetch from this date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ). Overrides saved state.")]
    from: Option<String>,

    #[arg(long, default_value = "config.toml")]
    config: String,
}

fn parse_since(s: &str) -> Result<String, String> {
    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
        return Ok(Utc.from_utc_datetime(&dt).format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&dt).format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).unwrap())
            .format("%Y-%m-%dT%H:%M:%SZ").to_string());
    }
    Err(format!("Cannot parse '{}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ", s))
}

#[derive(Debug, Clone, PartialEq)]
enum CollectorKind { Alerts, AuditEvents, Hosts }

struct CollectorHandle {
    kind:        CollectorKind,
    task:        JoinHandle<()>,
    tx:          mpsc::Sender<Value>,  // kept alive for restarts
    fail_count:  u32,
    last_ok:     Instant,
    failed:      bool,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = match config::load(&cli.config) {
        Ok(c)  => c,
        Err(e) => { error!("Config load failed: {}", e); std::process::exit(1); }
    };

    let state = Arc::new(Mutex::new(
        StateManager::load("state.json").expect("Failed to load state")
    ));

    // --from override
    if let Some(since) = &cli.from {
        let col = &cfg.collection;
        for src in ["alerts", "audit_events", "hosts"] {
            let enabled = match src {
                "alerts"       => col.sources.alerts.enabled,
                "audit_events" => col.sources.audit_events.enabled,
                "hosts"        => col.sources.hosts.enabled,
                _              => false,
            };
            if enabled {
                state.lock().await.update(src, since, "", &[], col.dedup_window_size)
                    .expect("State reset failed");
            }
        }
        info!(since = %since, "State reset via --from");
    }

    let auth = Arc::new(AuthManager::new(
        &cfg.falcon.base_url, &cfg.falcon.client_id, &cfg.falcon.client_secret,
        cfg.falcon.token_refresh_buffer_seconds,
    ));
    let api = Arc::new(ApiClient::new(auth.clone(), &cfg.falcon.base_url, 100));

    // Build output handlers
    let col = &cfg.collection;
    let mut handlers: Vec<Box<dyn OutputHandler>> = Vec::new();

    if cfg.outputs.json_file.enabled {
        std::fs::create_dir_all(&cfg.outputs.json_file.directory).ok();
        handlers.push(Box::new(JsonFileOutput::new(
            &cfg.outputs.json_file.directory,
            &col.tag,
            cfg.outputs.json_file.min_free_disk_mb,
        )));
    }
    if cfg.outputs.http_post.enabled {
        handlers.push(Box::new(HttpPostOutput::new(
            cfg.outputs.http_post.url.clone(),
            cfg.outputs.http_post.headers.clone(),
            cfg.outputs.http_post.batch_size,
        )));
    }

    let (tx, rx) = mpsc::channel::<Value>(col.queue_capacity);
    let dlq_dir  = PathBuf::from(cfg.outputs.json_file.directory.clone());
    let dispatcher = OutputDispatcher::new(rx, handlers, dlq_dir);
    let dispatcher_handle = tokio::spawn(dispatcher.run());

    let token   = CancellationToken::new();
    let metrics = Arc::new(Mutex::new(CollectorMetrics::default()));

    // Heartbeat
    {
        let m     = metrics.clone();
        let tok   = token.clone();
        let tx_c  = tx.clone();
        let interval = Duration::from_secs(cfg.metrics.heartbeat_interval_seconds);
        tokio::spawn(metrics::heartbeat_loop(
            m,
            move || tx_c.max_capacity() - tx_c.capacity(),
            interval,
            tok,
        ));
    }

    // Spawn collectors
    let sup_cfg = &cfg.supervisor;
    let mut handles: Vec<CollectorHandle> = Vec::new();

    // Spawn a collector task. initial_seen must be read from state BEFORE calling this.
    fn spawn_task(
        kind:         &CollectorKind,
        api:          Arc<ApiClient>,
        state:        Arc<Mutex<StateManager>>,
        tx:           mpsc::Sender<Value>,
        token:        CancellationToken,
        col:          &config::CollectionConfig,
        initial_seen: HashSet<String>,
    ) -> JoinHandle<()> {
        let pi  = Duration::from_secs(col.poll_interval_seconds);
        let bs  = col.batch_size;
        let dw  = col.dedup_window_minutes;
        let ds  = col.dedup_window_size;
        let cp  = col.checkpoint_per_page;
        let tag = col.tag.clone();
        match kind {
            CollectorKind::Alerts => {
                let c = AlertsCollector::new(api, &tag, pi, bs, dw, ds, cp, initial_seen);
                tokio::spawn(run_collector(c, state, tx, token))
            }
            CollectorKind::AuditEvents => {
                let c = AuditEventsCollector::new(api, &tag, pi, bs, ds);
                tokio::spawn(run_collector(c, state, tx, token))
            }
            CollectorKind::Hosts => {
                let c = HostsCollector::new(api, &tag, pi, bs, dw, ds);
                tokio::spawn(run_collector(c, state, tx, token))
            }
        }
    }

    for (kind, enabled, src_name) in [
        (CollectorKind::Alerts,      col.sources.alerts.enabled,       "alerts"),
        (CollectorKind::AuditEvents, col.sources.audit_events.enabled, "audit_events"),
        (CollectorKind::Hosts,       col.sources.hosts.enabled,        "hosts"),
    ] {
        if enabled {
            // Read initial seen_ids here (async context) — no block_on needed
            let initial_seen: HashSet<String> = state.lock().await
                .get(src_name).last_n_ids.into_iter().collect();
            let tx_clone = tx.clone();
            let jh = spawn_task(&kind, api.clone(), state.clone(),
                tx_clone.clone(), token.clone(), col, initial_seen);
            handles.push(CollectorHandle {
                kind, task: jh, tx: tx_clone,
                fail_count: 0, last_ok: Instant::now(), failed: false
            });
        }
    }
    drop(tx); // dispatcher closes when all per-handle tx clones are also dropped on shutdown

    info!("Started {} collector(s)", handles.len());

    // Signal handling
    let token_sig = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received");
        token_sig.cancel();
    });
    #[cfg(unix)]
    {
        let token_sig2 = token.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut s) = signal(SignalKind::terminate()) {
                s.recv().await;
                info!("SIGTERM received");
                token_sig2.cancel();
            }
        });
    }

    // Supervisor loop
    let backoff_base = sup_cfg.restart_backoff_base_seconds;
    let backoff_max  = sup_cfg.restart_backoff_max_seconds;
    let recovery_s   = sup_cfg.restart_recovery_seconds;
    let max_restarts = sup_cfg.max_restarts;
    let mut watch    = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = watch.tick() => {
                let mut all_failed = true;
                for h in handles.iter_mut() {
                    if h.failed { continue; }
                    all_failed = false;

                    if h.task.is_finished() {
                        h.fail_count += 1;
                        if h.fail_count >= max_restarts {
                            error!(source = ?h.kind, "Max restarts reached — marking FAILED");
                            h.failed = true;
                            continue;
                        }
                        let backoff = (backoff_base * 2u64.pow(h.fail_count - 1)).min(backoff_max);
                        warn!(source = ?h.kind, attempt = h.fail_count, "Collector died — restarting in {}s", backoff);
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        if token.is_cancelled() { break; }
                        let initial_seen: HashSet<String> = state.lock().await
                            .get(match &h.kind {
                                CollectorKind::Alerts      => "alerts",
                                CollectorKind::AuditEvents => "audit_events",
                                CollectorKind::Hosts       => "hosts",
                            })
                            .last_n_ids.into_iter().collect();
                        h.task = spawn_task(&h.kind, api.clone(), state.clone(),
                            h.tx.clone(), token.clone(), col, initial_seen);
                    } else if h.last_ok.elapsed() > Duration::from_secs(recovery_s) {
                        h.fail_count = 0;
                        h.last_ok    = Instant::now();
                    }
                }
                if all_failed {
                    error!("All collectors failed — exiting");
                    token.cancel();
                    break;
                }
            }
        }
    }

    for h in handles { let _ = h.task.await; }
    dispatcher_handle.await.ok();
    auth.revoke().await;
    info!("Shutdown complete");
}

async fn run_collector<C: CollectorTask>(
    collector: C,
    state:     Arc<Mutex<StateManager>>,
    tx:        mpsc::Sender<Value>,
    token:     CancellationToken,
) {
    let interval = collector.poll_interval();
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = async {
                if let Err(e) = collector.poll(state.clone(), &tx).await {
                    error!(source = collector.source_name(), error = %e, "Poll failed");
                }
                tokio::time::sleep(interval).await;
            } => continue,
        }
    }
    info!(source = collector.source_name(), "Collector stopped");
}
```

> **Important note on supervisor `tx` re-use:** The `tx` sender is dropped after spawning initial collectors so the dispatcher shuts down when all collectors exit. For restarts, store one `tx` clone per `CollectorHandle` before dropping the original. Replace the `panic!` line with `h.tx.clone()` after adding `tx: mpsc::Sender<Value>` to `CollectorHandle`.

- [ ] **Step 2: Build check**

```bash
cargo build 2>&1
```
Expected: compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add crates/cs-main/src/main.rs
git commit -m "feat(cs-main): supervisor loop, signal handling, --from flag, full wiring"
```

---

## Task 13: config.toml + Integration Smoke Test

**Files:**
- Create: `config.toml`
- Create: `crates/cs-main/tests/integration.rs`

- [ ] **Step 1: Create `config.toml`**

```toml
[falcon]
base_url      = "https://api.us-2.crowdstrike.com"
client_id     = "${CS_CLIENT_ID}"
client_secret = "${CS_CLIENT_SECRET}"
token_refresh_buffer_seconds = 300

[collection]
tag                   = "FCT"
poll_interval_seconds = 30
batch_size            = 100
checkpoint_per_page   = false
dedup_window_minutes  = 5
dedup_window_size     = 500
queue_capacity        = 10000

[collection.sources.alerts]
enabled = true

[collection.sources.audit_events]
enabled = true

[collection.sources.hosts]
enabled = true

[outputs.json_file]
enabled          = true
directory        = "logs"
min_free_disk_mb = 500

[outputs.http_post]
enabled = false

[supervisor]
max_restarts                 = 10
restart_backoff_base_seconds = 10
restart_backoff_max_seconds  = 120
restart_recovery_seconds     = 300

[metrics]
heartbeat_interval_seconds = 30
```

- [ ] **Step 2: Create integration test**

Create `crates/cs-main/tests/integration.rs`:

```rust
// Requires CS_CLIENT_ID and CS_CLIENT_SECRET env vars (real Falcon US-2 creds)
// Run: cargo test -p cs-main --test integration -- --ignored
// or: CS_CLIENT_ID=xxx CS_CLIENT_SECRET=yyy cargo test -p cs-main --test integration -- --ignored

use cs_collector::{AlertsCollector, ApiClient, AuthManager, CollectorTask};
use cs_state::StateManager;
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} must be set", key))
}

#[tokio::test]
#[ignore]
async fn alerts_returns_valid_events() {
    dotenv::dotenv().ok();
    let base_url      = "https://api.us-2.crowdstrike.com";
    let client_id     = require_env("CS_CLIENT_ID");
    let client_secret = require_env("CS_CLIENT_SECRET");

    let auth  = Arc::new(AuthManager::new(base_url, &client_id, &client_secret, 300));
    let api   = Arc::new(ApiClient::new(auth, base_url, 100));
    let dir   = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(
        StateManager::load(dir.path().join("state.json")).unwrap()
    ));

    // Reset to last 1 hour
    {
        let since = (Utc::now() - Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ").to_string();
        state.lock().await.update("alerts", &since, "", &[], 500).unwrap();
    }

    let collector = AlertsCollector::new(api, "integration-test",
        std::time::Duration::from_secs(30), 10, 5, 500, false,
        std::collections::HashSet::new());

    let (tx, mut rx) = mpsc::channel(100);
    collector.poll(state, &tx).await.expect("Poll should not error");
    drop(tx);

    let mut count = 0;
    while let Some(event) = rx.recv().await {
        assert!(event["_source"].as_str() == Some("alerts"));
        assert!(event["_ingest_timestamp"].is_string());
        assert!(event["_event_id"].is_string());
        count += 1;
        if count >= 5 { break; } // sample check, not exhaustive
    }
    // count may be 0 if no alerts in last hour — that is valid
    println!("Integration: received {} alert events", count);
}
```

- [ ] **Step 3: Run unit tests (all crates)**

```bash
cargo test
```
Expected: all non-ignored tests pass.

- [ ] **Step 4: Run integration test with real creds**

```bash
CS_CLIENT_ID=<your_id> CS_CLIENT_SECRET=<your_secret> \
  cargo test -p cs-main --test integration -- --ignored --nocapture
```
Expected: no errors, prints event count.

- [ ] **Step 5: Commit**

```bash
git add config.toml crates/cs-main/tests/
git commit -m "feat: config.toml + integration smoke test against real Falcon API"
```

---

## Task 14: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test
```
Expected: all non-ignored tests pass.

- [ ] **Step 2: Build release binary**

```bash
cargo build --release
```
Expected: `target/release/cs-collector` produced with no warnings.

- [ ] **Step 3: Smoke-run with --help**

```bash
./target/release/cs-collector --help
```
Expected:
```
CrowdStrike log collector

Usage: cs-collector [OPTIONS]

Options:
      --from <DATE>      Fetch from this date ...
      --config <CONFIG>  [default: config.toml]
  -h, --help             Print help
```

- [ ] **Step 4: Smoke-run --from flag (dry run with no config)**

```bash
CS_CLIENT_ID=x CS_CLIENT_SECRET=y \
  ./target/release/cs-collector --from 2026-03-30 --config /nonexistent 2>&1 | head -5
```
Expected: config load error (not a panic, clean exit).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: Rust rewrite complete — all tests passing, release binary verified"
```
