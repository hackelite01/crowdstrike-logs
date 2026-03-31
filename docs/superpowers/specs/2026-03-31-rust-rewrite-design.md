# CrowdStrike Log Collector — Rust Rewrite Design

**Date:** 2026-03-31  
**Status:** Approved  

---

## Overview

Full port of the Python CrowdStrike log collector to Rust. The rewrite targets production server deployment, using Tokio for async I/O, a Cargo workspace for clean crate boundaries, and a supervisor pattern for resilient collector lifecycle management.

The external delivery mechanism (rsyslog) reads the JSON file output — RELP and direct syslog TCP are out of scope. Config moves from YAML to TOML.

---

## Workspace Structure

```
crowdstrike-logs/
├── Cargo.toml                  # workspace manifest
├── config.toml                 # runtime config (replaces config.yaml)
├── state.json                  # persisted collector state (unchanged format + last_n_ids)
├── crates/
│   ├── cs-collector/           # lib: collector trait + all collectors + API client
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── auth.rs         # OAuth2 token manager (singleflight refresh)
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
| `cs-collector` | `tokio`, `reqwest` (rustls-tls + json), `serde`/`serde_json`, `async-trait`, `tracing`, `thiserror`, `governor` (token bucket) |
| `cs-output` | `tokio`, `serde_json`, `async-trait`, `tracing`, `thiserror`, `reqwest` |
| `cs-state` | `tokio`, `serde`/`serde_json`, `thiserror` |
| `cs-main` | all above, `toml`, `clap` v4, `tracing-subscriber` (JSON fmt), `dotenv`, `tokio::signal`, `tokio-util` (CancellationToken) |

**Notable choices:**
- `reqwest` with `rustls` — no OpenSSL, static-friendly binary
- `async-trait` — enables `dyn OutputHandler` and `dyn CollectorTask`
- `clap` v4 — replaces argparse, handles `--from DATE`
- `tracing-subscriber` with JSON formatter — structured logs matching current output
- `governor` — token bucket rate limiter, single `Arc<RateLimiter>` shared across all collectors
- No `async-std`, no `actix` — pure Tokio stack

---

## Architecture & Data Flow

```
main()
  ├── parse clap args (--from DATE)
  ├── load config.toml
  ├── if --from: reset state for enabled sources
  ├── build Arc<Mutex<StateManager>>
  ├── build Arc<RateLimiter> (shared across all collectors)
  ├── build Arc<AuthManager> (singleflight token refresh)
  ├── build output handlers → OutputDispatcher task
  ├── build MetricsEmitter task (structured heartbeat)
  └── Supervisor loop
        ├── AlertsCollector task     ──┐
        ├── AuditEventsCollector task ─┤──► bounded mpsc::channel<Value> ──► OutputDispatcher
        └── HostsCollector task     ──┘    (capacity: config)                   ├── JsonFileOutput
                                                                                 ├── HttpPostOutput
                                                                                 └── DLQ (failed_events.jsonl)
```

**Supervisor:**
- Keeps `Vec<CollectorHandle>` where each handle stores `kind: CollectorKind` + `JoinHandle<()>` + `fail_count: u32` + `last_success: Instant`
- Polls handles each watchdog tick (`tokio::time::interval`)
- On `is_finished()` with error/panic: increment `fail_count`, restart with exponential backoff (10s base, 120s max, reset after 300s uptime)
- On `fail_count >= max_restarts` for a collector: mark as `FAILED`, log critical, **continue other collectors**
- Only exit the process when **all** collectors are in `FAILED` state — then log critical + exit (let systemd restart the service)
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
    pub last_timestamp: String,       // advance cursor
    pub last_id: String,              // tiebreaker within same timestamp
    pub last_n_ids: Vec<String>,      // persisted dedup window (last N event IDs)
}

impl StateManager {
    pub fn get(&self, source: &str) -> SourceState;
    // default: last_timestamp = now-1hr, last_id = "", last_n_ids = []
    pub fn update(&mut self, source: &str, ts: &str, id: &str, recent_ids: &[String]) -> Result<(), StateError>;
    // atomic write: serialize to .tmp, rename to final path
}
```

**Deduplication strategy (two-layer):**
- **In-memory:** `HashSet<String>` built from `last_n_ids` on startup, updated each poll. Survives restarts via persistence.
- **Sliding window query:** filter `created_timestamp >= last_ts - window_minutes` (configurable, default 5 min, safe 10 min). Catches late-arriving Falcon events.
- On restart: `last_n_ids` re-seeds the `HashSet` — no duplicate flood.
- `last_n_ids` capped at `dedup_window_size` (config, default 500). FIFO eviction — oldest IDs drop off as new ones are added.

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

**`ApiClient`** wraps `reqwest::Client`:
- Attaches Bearer token via `AuthManager`
- Checks `Arc<RateLimiter>` (token bucket) before every request — all collectors share one limiter, preventing rate limit amplification
- Handles 429 with `X-RateLimit-RetryAfter` (milliseconds since epoch)
- Retries 5xx up to 3 times with backoff
- Handles 401 by triggering token refresh (singleflight) then retrying once

**`AuthManager`** — singleflight token refresh:
```rust
struct AuthManager {
    token_cache: Mutex<TokenCache>,   // holds current token + expiry
    refreshing: AtomicBool,           // singleflight guard
}
// When token near expiry:
//   Thread 1 sets refreshing=true → performs refresh → stores new token → sets false
//   Thread 2 sees refreshing=true → waits (tokio::time::sleep loop) → reads new token
// Result: exactly one refresh in flight at a time, no redundant requests
```

Each collector (`AlertsCollector`, `AuditEventsCollector`, `HostsCollector`) implements `CollectorTask`. Pagination, deduplication, and enrichment logic mirrors the Python exactly.

**Event enrichment adds:**
- `_collected_at` — UTC timestamp when event was ingested (renamed from `_collected_at`, was implicit)
- `_source_timestamp` — original event timestamp from Falcon
- `_source` — collector name
- `_tag` — client name from config
- `_collector_version` — binary version
- `_event_id` — stable event identifier

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

`OutputDispatcher` holds `Vec<Box<dyn OutputHandler + Send + Sync>>`. On write failure for any handler, the event is written to the **DLQ** (`failed_events.jsonl`) with structured failure context:

```json
{
  "event": { "...original event..." },
  "error": "connection refused",
  "handler": "http_post",
  "failed_at": "2026-03-31T05:00:00Z"
}
```

DLQ writes are best-effort (errors logged, not re-queued).

**`JsonFileOutput`:**
- Active file: `falcon_alerts_{client_name}.json` (`client_name` = `collection.tag` from config)
- Daily rotation at UTC midnight: rename active file to `falcon_alerts_{client_name}_YYYY-MM-DD.json`, open fresh
- Write errors handled directly via `io::Error` — no pre-check race condition
- On write error: log + send to DLQ

### `cs-main`

Config structs deserialised from `config.toml` via `serde`. `clap` v4 derives `--from DATE` argument. `CollectorKind` enum used by supervisor to restart the right collector type.

**Structured heartbeat** (emitted every `heartbeat_interval_seconds`, default 30):
```json
{
  "status": "ok",
  "queue_depth": 42,
  "last_successful_poll": { "alerts": "2026-03-31T05:26:56Z", "audit_events": "...", "hosts": "..." },
  "api_failures": { "alerts": 0, "audit_events": 1, "hosts": 0 },
  "collector_states": { "alerts": "running", "audit_events": "running", "hosts": "failed" }
}
```

Systemd `WatchdogSec` uses `sd_notify` via `WATCHDOG_USEC` — process pings watchdog on each heartbeat. If heartbeat stops (stuck/deadlocked), systemd restarts the service.

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
- `OutputError` → log error, write to DLQ, continue
- Single collector task crash → supervisor restarts with backoff; others unaffected
- All collectors reach `max_restarts` → log critical + exit process (systemd restarts service)

---

## Testing Strategy

**Unit tests** (`#[cfg(test)]` in each crate):
- `cs-state`: save/load roundtrip, `last_n_ids` persistence, atomic write, default timestamp, multi-source isolation
- `cs-collector`: `should_skip_event`, `enrich_event`, sliding window query, dedup with persisted IDs, pagination, rate-limit retry — using `wiremock` for HTTP mocking
- `cs-output`: `JsonFileOutput` write + date rotation + write error → DLQ, HTTP POST batching, DLQ structured format

**Integration tests** (`cs-main/tests/`):
- Full pipeline against real Falcon API (credentials provided via environment variables)
- Validates: auth → query (sliding window) → entity fetch → deduplication → file output

**Test dependencies:** `wiremock`, `tempfile`, `tokio::test`

**Not tested:** RELP (out of scope), Falcon API availability (real-creds integration test only)

---

## Configuration Reference (`config.toml`)

```toml
[falcon]
base_url = "https://api.us-2.crowdstrike.com"
client_id = "${CS_CLIENT_ID}"
client_secret = "${CS_CLIENT_SECRET}"
token_refresh_buffer_seconds = 300

[collection]
tag = "FCT"                         # client_name used in output filenames
poll_interval_seconds = 30
batch_size = 100
checkpoint_per_page = false
dedup_window_minutes = 5            # sliding window lookback (safe: 10)
dedup_window_size = 500             # max IDs kept in last_n_ids per source

[collection.sources.alerts]
enabled = true
poll_interval_seconds = 30
batch_size = 100

[collection.sources.audit_events]
enabled = true

[collection.sources.hosts]
enabled = true

[outputs.json_file]
enabled = true
directory = "logs"
min_free_disk_mb = 500

[outputs.http_post]
enabled = false
url = "https://your-siem/ingest"
batch_size = 100
headers = { "Authorization" = "Bearer ${HTTP_TOKEN}" }

[supervisor]
max_restarts = 10
restart_backoff_base_seconds = 10
restart_backoff_max_seconds = 120
restart_recovery_seconds = 300

[metrics]
heartbeat_interval_seconds = 30
```

---

## Out of Scope

- RELP output handler (rsyslog handles external forwarding)
- Direct syslog TCP output (rsyslog reads JSON file)
- Config hot-reload (restart process via systemd/Docker)
- Windows service wrapper (Linux/Docker deployment assumed)
- Multi-tenant isolation (single tenant per instance; future work)
