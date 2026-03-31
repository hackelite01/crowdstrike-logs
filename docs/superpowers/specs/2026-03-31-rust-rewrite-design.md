# CrowdStrike Log Collector — Rust Rewrite Design

**Date:** 2026-03-31  
**Status:** Approved  

---

## Overview

Full port of the Python CrowdStrike log collector to Rust. The rewrite targets production server deployment, using Tokio for async I/O, a Cargo workspace for clean crate boundaries, and a supervisor pattern for resilient collector lifecycle management.

The external delivery mechanism (rsyslog) reads the JSON file output — RELP is out of scope. Config moves from YAML to TOML.

---

## Workspace Structure

```
crowdstrike-logs/
├── Cargo.toml                  # workspace manifest
├── config.toml                 # runtime config (replaces config.yaml)
├── state.json                  # persisted collector state (unchanged format)
├── crates/
│   ├── cs-collector/           # lib: collector trait + all collectors + API client
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── auth.rs         # OAuth2 token manager
│   │       ├── api_client.rs   # reqwest wrapper: retry, rate-limit, 401 refresh
│   │       ├── base.rs         # CollectorTask trait, enrich_event, should_skip_event
│   │       ├── alerts.rs
│   │       ├── audit_events.rs
│   │       └── hosts.rs
│   ├── cs-output/              # lib: output trait + handlers + dispatcher
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── dispatcher.rs
│   │       ├── json_file.rs    # active file + daily date rotation
│   │       ├── syslog_tcp.rs
│   │       └── http_post.rs
│   ├── cs-state/               # lib: state manager
│   │   └── src/lib.rs
│   └── cs-main/                # binary: supervisor, config, metrics, entry point
│       └── src/
│           ├── main.rs
│           ├── config.rs       # serde TOML config structs
│           └── metrics.rs
```

---

## Key Dependencies

| Crate | Dependencies |
|---|---|
| `cs-collector` | `tokio`, `reqwest` (rustls-tls + json), `serde`/`serde_json`, `async-trait`, `tracing`, `thiserror` |
| `cs-output` | `tokio`, `serde_json`, `async-trait`, `tracing`, `thiserror`, `reqwest` |
| `cs-state` | `tokio`, `serde`/`serde_json`, `thiserror` |
| `cs-main` | all above, `toml`, `clap` v4, `tracing-subscriber` (JSON fmt), `dotenv`, `tokio::signal`, `tokio-util` (CancellationToken) |

**Notable choices:**
- `reqwest` with `rustls` — no OpenSSL, static-friendly binary
- `async-trait` — enables `dyn OutputHandler` and `dyn CollectorTask`
- `clap` v4 — replaces argparse, handles `--from DATE`
- `tracing-subscriber` with JSON formatter — structured logs matching current output
- No `async-std`, no `actix` — pure Tokio stack

---

## Architecture & Data Flow

```
main()
  ├── parse clap args (--from DATE)
  ├── load config.toml
  ├── if --from: reset state for enabled sources
  ├── build Arc<Mutex<StateManager>>
  ├── build output handlers → OutputDispatcher task
  ├── build MetricsEmitter task
  └── Supervisor loop
        ├── AlertsCollector task     ──┐
        ├── AuditEventsCollector task ─┤──► mpsc::channel<Value> ──► OutputDispatcher
        └── HostsCollector task     ──┘    (bounded, capacity cfg)       ├── JsonFileOutput
                                                                          ├── SyslogTcpOutput
                                                                          └── HttpPostOutput
```

**Supervisor:**
- Keeps `Vec<CollectorHandle>` where each handle stores `kind: CollectorKind` + `JoinHandle<()>`
- Polls handles each watchdog tick (`tokio::time::interval`)
- On `is_finished()`: checks result — if error/panic, restarts with exponential backoff (10s base, 120s max, resets after 300s uptime)
- On clean cancellation: skips restart

**Collector task loop:**
```
loop {
    select! {
        _ = cancellation_token.cancelled() => break,
        _ = async { poll().await; sleep(interval).await } => continue,
    }
}
```

**Shutdown sequence:**
1. SIGTERM/SIGINT → `CancellationToken::cancel()`
2. All collector tasks finish current poll → exit
3. All `mpsc::Sender` clones dropped → channel closes
4. Dispatcher drains remaining events → flushes handlers → exits
5. `main` awaits all handles → clean exit

**Hot-reload:** Dropped. Restart the process (systemd/Docker) to pick up config changes.

---

## Component Design

### `cs-state`

```rust
pub struct StateManager {
    path: PathBuf,
    cache: HashMap<String, SourceState>,
}

pub struct SourceState {
    pub last_timestamp: String,
    pub last_id: String,
}

impl StateManager {
    pub fn get(&self, source: &str) -> SourceState;       // default: now-1hr if missing
    pub fn update(&mut self, source: &str, ts: &str, id: &str) -> Result<(), StateError>;
    // atomic write: serialize to .tmp, rename to final path
}
```

Wrapped in `Arc<tokio::sync::Mutex<StateManager>>` in main. Never held across an `.await` point — callers clone needed data before releasing the lock.

### `cs-collector`

```rust
#[async_trait]
pub trait CollectorTask: Send {
    async fn poll(&self, state: Arc<Mutex<StateManager>>, tx: Sender<Value>) -> Result<(), CollectorError>;
    fn source_name(&self) -> &str;
    fn poll_interval(&self) -> Duration;
}
```

`ApiClient` wraps `reqwest::Client`:
- Attaches Bearer token (refreshed via `AuthManager` when near expiry)
- Handles 429 with `X-RateLimit-RetryAfter` (milliseconds since epoch)
- Retries 5xx up to 3 times with backoff
- Handles 401 by refreshing token once then retrying

Each collector (`AlertsCollector`, `AuditEventsCollector`, `HostsCollector`) implements `CollectorTask`. Pagination, deduplication (`should_skip_event`), and enrichment (`enrich_event`) logic mirrors the Python exactly.

**Alerts-specific:** POST body uses `composite_ids` key (not `ids`).

### `cs-output`

```rust
#[async_trait]
pub trait OutputHandler: Send + Sync {
    async fn write(&self, event: &Value) -> Result<(), OutputError>;
    async fn close(&self) -> Result<(), OutputError>;
    fn is_enabled(&self) -> bool;
}
```

`OutputDispatcher` holds `Vec<Box<dyn OutputHandler + Send + Sync>>`, receives from the bounded `mpsc` channel, and fans each event out to all enabled handlers. Handler errors are logged but do not stop other handlers.

**`JsonFileOutput`:**
- Active file: `falcon_alerts_{client_name}.json`
- `client_name` comes from `collection.tag` in `config.toml` (e.g. `"FCT"`)
- Daily rotation at UTC midnight: rename active file to `falcon_alerts_{client_name}_YYYY-MM-DD.json`, open fresh active file
- Uses `tokio::fs` for async file I/O
- Disk space check before each write

### `cs-main`

Config structs deserialised from `config.toml` via `serde`. `clap` v4 derives `--from DATE` argument. `CollectorKind` enum used by supervisor to restart the right collector type. Metrics emitted on interval via `tracing` structured log events.

---

## Error Handling

Each crate exposes a typed error enum via `thiserror`. Every error path emits a `tracing::error!` log with full context — nothing fails silently.

```rust
// cs-collector
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("HTTP request failed: {0}")] Http(#[from] reqwest::Error),
    #[error("Auth error: {0}")] Auth(String),
    #[error("Rate limited, retry after {retry_after_ms}ms")] RateLimited { retry_after_ms: u64 },
    #[error("Deserialize error: {0}")] Json(#[from] serde_json::Error),
}

// cs-output
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("IO error: {0}")] Io(#[from] std::io::Error),
    #[error("HTTP POST failed: {0}")] Http(#[from] reqwest::Error),
    #[error("Syslog error: {0}")] Syslog(String),
}

// cs-state
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("IO error: {0}")] Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")] Json(#[from] serde_json::Error),
}
```

**Recovery behaviour:**
- `Http` / `Json` in collector poll → log error, continue on next interval
- `RateLimited` → sleep `retry_after_ms`, retry same pagination page
- `OutputError` → log error, reconnect on next write (syslog TCP), skip write (file disk full)
- Task panic / unrecoverable exit → supervisor restarts with exponential backoff

---

## Testing Strategy

**Unit tests** (`#[cfg(test)]` in each crate):
- `cs-state`: save/load roundtrip, atomic write, default timestamp, multi-source isolation
- `cs-collector`: `should_skip_event`, `enrich_event`, pagination, rate-limit retry — using `wiremock` for HTTP mocking
- `cs-output`: `JsonFileOutput` write + date rotation + disk-full skip, syslog TCP framing, HTTP POST batching

**Integration tests** (`cs-main/tests/`):
- Full pipeline against real Falcon API (credentials provided via environment variables)
- Validates: auth → query → entity fetch → deduplication → file output

**Test dependencies:** `wiremock`, `tempfile`, `tokio::test`

**Not tested:** RELP (out of scope), Falcon API availability (real-creds integration test only)

---

## Out of Scope

- RELP output handler (rsyslog handles external forwarding)
- Config hot-reload (restart process via systemd/Docker)
- Windows service wrapper (Linux/Docker deployment assumed)
