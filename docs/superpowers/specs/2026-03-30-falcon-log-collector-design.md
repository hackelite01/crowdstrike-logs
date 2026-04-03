# CrowdStrike Falcon Log Collector — Design Spec

**Date:** 2026-03-30
**Status:** Approved
**Region:** US-2
**Platform:** Cross-platform (Windows + Ubuntu/Linux)

---

## 1. Overview

A production-grade, fault-tolerant Python log collection pipeline for CrowdStrike Falcon (US-2) that:

- Continuously polls Falcon REST APIs 24x7
- Stores logs locally as rotating NDJSON files
- Optionally forwards logs to any remote instance via Syslog TCP, RELP, or HTTP POST
- Resumes from last state on restart with **zero duplicate ingestion and zero log loss**
- Emits structured metrics for SOC observability
- Runs as a systemd service (Linux) or NSSM-managed service (Windows)

**Not in scope:** Direct OpenSearch/Wazuh integration. Downstream routing is handled by rsyslog/RELP on the receiving EC2 instance.

---

## 2. Architecture

### Data Flow

```
CrowdStrike Falcon API (US-2)
         │
    ┌────▼────────────────────────────┐
    │  Auth Manager (thread-safe)     │  OAuth2 token, lock + double-check refresh
    └────┬────────────────────────────┘
         │  shared token
    ┌────▼────────────────────────────┐    ┌─────────────────────────────┐
    │   Collector Threads (up to 4)   │    │  Global Rate-Limit Controller│
    │  - AlertsCollector              │◄───│  shared 429 gate (per API key│
    │  - AuditEventsCollector         │    │  not per thread)            │
    │  - HostsCollector               │    └─────────────────────────────┘
    │  - (reserved for future source) │
    └────┬────────────────────────────┘
         │  events → bounded Queue(maxsize=10000)
         │  block with timeout + warning if full
    ┌────▼────────────────────────────┐
    │       Output Dispatcher         │  fans out to all enabled outputs
    └────┬──────────┬────────┬────────┘
         │          │        │
    ┌────▼──┐  ┌────▼──┐  ┌──▼──────┐  ┌──────────┐
    │ JSON  │  │Syslog │  │  RELP   │  │HTTP POST │
    │ Files │  │  TCP  │  │(relppy) │  │(webhook) │
    └───────┘  └───────┘  └─────────┘  └──────────┘
         │
    ┌────▼──────────────────────────┐
    │  Metrics Logger (every 60s)   │  events/s, queue depth, errors, latency
    └───────────────────────────────┘
```

### API Deprecation Notes

> **IMPORTANT:** As of the spec date (2026-03-30), two CrowdStrike APIs are decommissioned:
>
> - `/detects/queries/detects/v1` and `/detects/entities/summaries/GET/v1` — **decommissioned September 30, 2025**. Replaced by the Alerts API.
> - `/incidents/queries/incidents/v1` and `/incidents/entities/incidents/GET/v1` — **decommissioned March 9, 2026**. Alerts covers incident-type events going forward.
>
> The implementation uses the **Alerts API** (`/alerts/queries/alerts/v2`) as the single source for both detection and incident events.

### Project Structure

```
crowdstrike-logs/
├── config.yaml               # active config (gitignored — contains secrets)
├── config.example.yaml       # committed to git, no secrets
├── .dockerignore             # excludes config.yaml, .env, state.json, logs/
├── requirements.txt
├── main.py                   # entry point, thread orchestration, watchdog
├── collector/
│   ├── __init__.py
│   ├── auth.py               # OAuth2 token manager (thread-safe, lock + double-check)
│   ├── api_client.py         # base HTTP client (retry, backoff, global rate-limit gate)
│   ├── alerts.py             # alerts collector (replaces detections + incidents)
│   ├── audit_events.py
│   └── hosts.py
├── state/
│   ├── __init__.py
│   └── manager.py            # atomic read/write of state.json
├── output/
│   ├── __init__.py
│   ├── base.py               # OutputHandler abstract base class
│   ├── json_file.py          # hourly/daily rotating NDJSON files + disk check
│   ├── syslog_tcp.py         # RFC 5424 syslog over TCP (with optional TLS)
│   ├── relp.py               # RELP via relppy (Python 3, cross-platform)
│   └── http_post.py          # HTTP POST / webhook
├── utils/
│   ├── __init__.py
│   ├── logger.py             # structured JSON logging to stderr
│   └── metrics.py            # in-process metrics counters + periodic log emitter
├── state.json                # runtime state (gitignored)
├── reload.trigger            # drop this file to trigger config reload
├── logs/                     # collected log files (gitignored)
└── .gitignore
```

---

## 3. Configuration

### config.yaml Schema

```yaml
falcon:
  client_id: "${FALCON_CLIENT_ID}"
  client_secret: "${FALCON_CLIENT_SECRET}"
  base_url: "https://api.us-2.crowdstrike.com"
  # Refresh token this many seconds before the expires_in value from the token response.
  # expires_in is read dynamically from the OAuth2 response — never hard-coded.
  token_refresh_buffer_seconds: 300

collection:
  poll_interval_seconds: 30
  tag: "forensiccybertech"          # injected into every event as _tag
  sources:
    alerts:
      enabled: true
      poll_interval_seconds: 30
      batch_size: 100
    audit_events:
      enabled: true
      poll_interval_seconds: 60
      batch_size: 200
    hosts:
      enabled: false
      poll_interval_seconds: 300
      batch_size: 500
      # Note: offset + limit must not exceed 10,000 (Falcon hard limit).
      # The collector uses timestamp-windowed FQL filters to avoid this ceiling.

queue:
  maxsize: 10000                    # bounded queue — producer blocks with warning if full
  full_warn_interval_seconds: 10    # how often to log a warning when queue is full

outputs:
  json_file:
    enabled: true
    directory: "./logs"
    rotation: hourly                # hourly | daily
    filename_prefix: "falcon"       # falcon_alerts_2026-03-30_14.json
    max_size_mb: 256                # rotate early if file exceeds this size
    min_free_disk_mb: 500           # disable file output temporarily if free disk < this

  syslog_tcp:
    enabled: false
    host: "10.0.1.50"
    port: 514
    facility: 16
    app_name: "falcon-collector"
    tls:
      enabled: false                # set true for production
      ca_cert: "/etc/ssl/certs/ca.pem"
      verify: true

  relp:
    enabled: false
    host: "10.0.1.50"
    port: 2514

  http_post:
    enabled: false
    url: "https://10.0.1.50:8080/ingest"
    headers:
      X-Api-Key: "${HTTP_INGEST_KEY}"
    batch_size: 50
    timeout_seconds: 10

metrics:
  enabled: true
  log_interval_seconds: 60          # emit metrics line to structured log every N seconds
```

### Credentials

Always passed via environment variables or a `.env` file (never hardcoded):

```env
FALCON_CLIENT_ID=your_client_id
FALCON_CLIENT_SECRET=your_client_secret
```

### Hot Config Reload (cross-platform)

```bash
# Linux
touch reload.trigger

# Windows CMD
echo. > reload.trigger
```

The watchdog checks for this file every 5 seconds, reloads config, then deletes the file. Rapid successive triggers collapse into a single reload — callers must wait for the trigger file to disappear before issuing another.

---

## 4. State Management

### state.json Format

Each source tracks both `last_timestamp` **and** `last_id` to handle events sharing the same timestamp (which Falcon can produce):

```json
{
  "alerts": {
    "last_timestamp": "2026-03-30T13:45:00.000Z",
    "last_id": "abc123def456"
  },
  "audit_events": {
    "last_timestamp": "2026-03-30T13:44:00.000Z",
    "last_id": "xyz789"
  },
  "hosts": {
    "last_timestamp": "2026-03-30T13:00:00.000Z",
    "last_id": "host-id-001"
  }
}
```

### Deduplication Logic (mandatory for correctness)

Query uses `sort=created_timestamp.asc` to guarantee ascending order. Skip condition on each fetched event:

```python
if event["created_timestamp"] == state["last_timestamp"] \
   and event["id"] <= state["last_id"]:
    continue  # already processed
```

After processing the full page:
- `last_timestamp` = newest `created_timestamp` seen this cycle
- `last_id` = ID of the event with that newest timestamp

This correctly handles:
- Multiple events at the exact same timestamp
- Crash/restart mid-page (re-fetches boundary events, skips via id comparison)

### Per-page Checkpointing (optional, reduces duplicate window)

By default, state is written once per poll cycle. For environments where crash-recovery duplicates are unacceptable, the implementation supports per-page checkpointing: state is written after each page of results rather than at the end of the cycle. This reduces the maximum duplicate window from `cycle_size * batch_size` events to `batch_size` events on restart.

Enabled via config:
```yaml
collection:
  checkpoint_per_page: false   # set true for minimal duplicate window
```

### Guarantees

- Written atomically: write to `state.json.tmp` **in the same directory** as `state.json`, then call `os.replace()` (ensures same filesystem volume on Windows).
- On first run, each source bootstraps from `now - 1 hour`.
- On restart, each collector resumes from its saved `last_timestamp` + `last_id`.
- A crash mid-write leaves the previous valid state intact.
- All timestamp comparisons use **Falcon-provided timestamps only** — local system clock is never used for filtering logic. Local time is used only for `_collected_at` enrichment and for `expires_in` token math. This makes the collector immune to system clock drift.

---

## 5. Pagination Strategy

All collectors use **timestamp-windowed FQL filters** with `sort=created_timestamp.asc` and the API's `after` cursor token to avoid the `offset + limit ≤ 10,000` hard ceiling.

Algorithm per poll cycle:

```
1. Build FQL filter: created_timestamp:>='<last_timestamp>'
2. Sort: created_timestamp.asc
3. Fetch page 1: limit=<batch_size>
4. For each event:
     if event.created_timestamp == last_timestamp AND event.id <= last_id:
         skip (already seen)
     else:
         enqueue event
5. If response has 'after' cursor → fetch next page with after=<cursor>
6. Repeat step 4-5 until no 'after' cursor (last page)
7. Update last_timestamp and last_id from final event seen
8. Write state (per-page or per-cycle depending on checkpoint_per_page config)
```

---

## 6. Event Enrichment

Every collected event gets these fields injected before output:

```json
{
  "_collected_at": "2026-03-30T14:00:01.123Z",
  "_source": "alerts",
  "_tag": "forensiccybertech",
  "_collector_version": "1.0.0",
  "_event_id": "<falcon_native_event_id>"
}
```

`_event_id` is the Falcon-native event ID (e.g., `composite_id` for alerts, device ID for hosts). Downstream systems (Wazuh, OpenSearch) use this field for **idempotent deduplication** — if the same event is received twice due to a retry, it can be deduplicated by `_event_id` on the receiving end.

All timestamps are normalized to ISO 8601 UTC.

---

## 7. Authentication

The auth manager (`collector/auth.py`) handles the full OAuth2 token lifecycle:

1. On startup, fetch a token via `POST /oauth2/token`
2. Read `expires_in` from the response — **never hard-code the token TTL**
3. Schedule refresh at `expires_in - token_refresh_buffer_seconds`
4. Token refresh uses a **lock + double-check pattern** to prevent multiple threads from triggering parallel refreshes:
   ```python
   if self._is_expiring():
       with self._lock:
           if self._is_expiring():   # re-check under lock
               self._do_refresh()
   ```
5. On 401 mid-poll: refresh token immediately (under lock) and retry the request once
6. On shutdown, revoke the token via `POST /oauth2/revoke` (compliance hygiene)

---

## 8. Error Handling & Reliability

### Retry Policy (per API call)

Exponential backoff with jitter: `sleep = base * 2^attempt + random(0, 1)`

| Attempt | Wait |
|---------|------|
| 1 | 2s |
| 2 | 4s |
| 3 | 8s |
| 4 | 16s |
| 5 | Log error, skip cycle |

### Rate Limit (HTTP 429) — Global Coordination

Falcon's rate limit is **per API key** (global), not per thread. A single shared `RateLimitController` in `api_client.py` coordinates all threads:

- When any thread receives a 429: it acquires the shared lock, sets a global `retry_after` timestamp, then waits
- All other threads check this shared timestamp before making requests and wait if it has not elapsed
- `X-RateLimit-RetryAfter` is a **Unix epoch timestamp** — correct sleep calculation:
  ```python
  retry_after_epoch = int(response.headers["X-RateLimit-RetryAfter"])
  sleep_duration = max(0, retry_after_epoch - time.time())
  time.sleep(sleep_duration + 0.5)  # 0.5s safety margin
  ```

### Bounded Output Queue

The internal event queue is **bounded** to prevent memory exhaustion when outputs are slow:

```python
queue = Queue(maxsize=10000)   # configurable via queue.maxsize in config.yaml
```

Producer (collector threads) behaviour when queue is full:
- Attempt `queue.put(event, timeout=5)`
- If still full after 5s: log a WARNING and retry (do **not** drop the event)
- Log warning at most once per `queue.full_warn_interval_seconds` to avoid log flooding

### Disk Failure Handling

Before each write to the JSON file output, `json_file.py` checks available disk space:

```python
free_mb = shutil.disk_usage(log_dir).free / (1024 * 1024)
if free_mb < config.min_free_disk_mb:
    log.warning("Low disk space (%d MB free) — disabling file output temporarily", free_mb)
    self.disabled = True
    return
```

The file output re-enables itself automatically on the next successful space check. Other outputs (Syslog, RELP, HTTP) continue unaffected. This handles:
- Disk full
- Permission errors (caught as `OSError`, logged, output disabled temporarily)
- Corrupt filesystem operations (caught as `OSError`)

### Error Taxonomy

| Condition | Behaviour |
|---|---|
| Token fetch fails | Retry 3x with backoff, then halt thread + log CRITICAL |
| 401 mid-poll | Refresh token under lock, retry request once |
| Network timeout | Retry with backoff |
| HTTP 400/404 | Log error, skip cycle (not retryable) |
| HTTP 429 | Global rate-limit gate: all threads wait for RetryAfter epoch, then retry |
| HTTP 500/503 | Retry with backoff |
| State write fails | Log CRITICAL, keep running (in-memory state still valid) |
| Output write fails | Log error, keep collecting — ingestion never blocked by output failure |
| Disk full | Disable file output temporarily; resume when space recovers |
| Queue full | Block producer with timeout + WARNING log; never drop events |
| Thread crash | Watchdog restarts thread with exponential backoff (10s → 20s → 40s, cap 120s) |

### Thread Watchdog

`main.py` runs a watchdog loop every 30 seconds:
- If `not thread.is_alive()`: wait `restart_delay`, then restart
- `restart_delay` starts at 10s, doubles per consecutive restart, capped at 120s
- Resets to 10s after thread survives 5 consecutive minutes
- State is reloaded from `state.json` on restart

---

## 9. Observability & Metrics

`utils/metrics.py` maintains thread-safe counters per source. Every `metrics.log_interval_seconds` (default: 60s), a structured metrics line is emitted to the log:

```json
{
  "level": "INFO",
  "type": "metrics",
  "timestamp": "2026-03-30T14:01:00Z",
  "alerts": {"events_collected": 142, "api_latency_ms_avg": 320, "errors": 0},
  "audit_events": {"events_collected": 28, "api_latency_ms_avg": 210, "errors": 0},
  "hosts": {"events_collected": 0, "api_latency_ms_avg": 0, "errors": 0},
  "queue_depth": 12,
  "output": {
    "json_file": {"written": 170, "failed": 0},
    "syslog_tcp": {"sent": 0, "failed": 0},
    "relp": {"sent": 0, "failed": 0},
    "http_post": {"sent": 0, "failed": 0}
  }
}
```

These metrics lines are parseable by any log aggregator (Logstash, Vector, Fluentd) and allow SOC operators to detect:
- Rate drops (possible API issue or rate-limiting)
- Output failures
- Queue build-up (outputs slower than ingestion)

---

## 10. Output Handlers

### JSON File
- Format: NDJSON (one JSON object per line)
- Filename: `logs/falcon_alerts_2026-03-30_14.json`
- Rotation: time-based (hourly or daily) OR size-based (`max_size_mb`), whichever comes first
- Disk space checked before every write; output auto-disabled/re-enabled based on `min_free_disk_mb`
- No auto-deletion — archiving is operator responsibility

### Syslog TCP (RFC 5424)
- Event JSON serialized as MSG field
- TLS via `ssl.SSLContext` (Python 3.x — `ssl.wrap_socket()` removed in Python 3.12, must not be used):
  ```python
  ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  ctx.load_verify_locations(ca_cert_path)
  ctx.verify_mode = ssl.CERT_REQUIRED
  wrapped = ctx.wrap_socket(sock, server_hostname=host)
  ```
- Auto-reconnects on socket drop
- **Recommendation:** enable TLS in production

### RELP
- Uses `relppy` (PyPI: `relppy`) — pure Python 3, cross-platform, no C library dependency
- ACK-based — retries unacknowledged events
- Guarantees no silent loss in transit

### HTTP POST
- Batched: `{"events": [...]}`
- Each event includes `_event_id` for downstream idempotent deduplication
- Retries on non-2xx with backoff
- Configurable headers for API key / bearer token auth
- **Recommendation:** use `https://` URLs in production

---

## 11. Cross-Platform Compatibility

| Concern | Solution |
|---|---|
| File paths | `pathlib.Path` throughout — never string concatenation |
| Config reload | `reload.trigger` file watch (no SIGHUP dependency) |
| Signal handling | `SIGTERM` (Linux) + `CTRL_C_EVENT` (Windows) abstracted in `main.py` |
| Atomic state write | `os.replace()` with temp file **in the same directory** as target |
| Service management | systemd (Linux) / NSSM with `.env` file (Windows) |
| RELP library | `relppy` — pure Python 3, no native library required |
| Disk space check | `shutil.disk_usage()` — works on both platforms |
| Time/clock | Falcon timestamps used for filtering; local clock only for `_collected_at` + token expiry |

---

## 12. Deployment

### Linux — systemd

```ini
# /etc/systemd/system/falcon-collector.service
[Unit]
Description=CrowdStrike Falcon Log Collector
After=network.target

[Service]
Type=simple
User=falcon
WorkingDirectory=/opt/falcon-collector
ExecStart=/opt/falcon-collector/venv/bin/python main.py
Restart=on-failure
RestartSec=10
EnvironmentFile=/opt/falcon-collector/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable falcon-collector
sudo systemctl start falcon-collector
```

### Windows — NSSM

```cmd
nssm install falcon-collector "C:\falcon-collector\venv\Scripts\python.exe" main.py
nssm set falcon-collector AppDirectory C:\falcon-collector
icacls C:\falcon-collector\.env /inheritance:r /grant "SYSTEM:(R)" /grant "Administrators:(R)"
nssm start falcon-collector
```

`main.py` must call `load_dotenv()` as its **first substantive action**:
```python
from dotenv import load_dotenv
load_dotenv()  # must come before any os.environ access
```

Do **not** use `AppEnvironmentExtra` — it stores values in the registry in plaintext.

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
# Install into base image's system Python (no venv needed inside Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Drop root — create user before COPY so files are owned correctly
RUN useradd --create-home --shell /bin/bash falcon
COPY --chown=falcon:falcon . .
USER falcon
CMD ["python", "main.py"]
```

`.dockerignore`:
```
config.yaml
.env
state.json
logs/
*.pyc
__pycache__/
```

```bash
docker run -d \
  --name falcon-collector \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/state.json:/app/state.json \
  -v $(pwd)/config.yaml:/app/config.yaml \
  --env-file .env \
  --restart unless-stopped \
  falcon-collector
```

### Local Dev

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
pip install -r requirements.txt
cp config.example.yaml config.yaml
# fill in credentials in .env
python main.py
```

---

## 13. Dependencies (requirements.txt)

```
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
relppy>=0.3.0
```

---

## 14. API Endpoints Reference

| Source | Query Endpoint | Detail Endpoint | Notes |
|---|---|---|---|
| Alerts | `GET /alerts/queries/alerts/v2` | `POST /alerts/entities/alerts/GET/v2` | Replaces deprecated Detections and Incidents APIs |
| Audit Events | `GET /audit-events/queries/events/v1` | `GET /audit-events/entities/events/v1` | **Verify path against Falcon console API Explorer before implementation.** May require Streaming API (`/sensors/entities/datafeed/v2`) if REST endpoint unavailable. |
| Hosts | `GET /devices/queries/devices/v1` | `POST /devices/entities/devices/GET/v2` | Use timestamp-windowed FQL to avoid 10,000-record offset ceiling |

**Deprecated (do not use):**

| Endpoint | Decommission Date |
|---|---|
| `/detects/queries/detects/v1` | September 30, 2025 |
| `/detects/entities/summaries/GET/v1` | September 30, 2025 |
| `/incidents/queries/incidents/v1` | March 9, 2026 |
| `/incidents/entities/incidents/GET/v1` | March 9, 2026 |

All active endpoints use FQL `filter`, `sort=created_timestamp.asc`, `limit`, and `after` (cursor) for pagination.

---

## 15. Security Notes

- Credentials **never** hardcoded — always via env vars or `.env` (gitignored)
- On Windows, `.env` ACL restricted via `icacls` — do not use NSSM `AppEnvironmentExtra`
- `config.yaml` gitignored; only `config.example.yaml` committed
- `state.json` and `logs/` gitignored
- `.dockerignore` excludes `config.yaml`, `.env`, `state.json`, `logs/`
- Docker container runs as non-root `falcon` user with `--chown` on all files
- Collector exposes no listening port — all connections are outbound only
- Enable TLS for Syslog TCP and use `https://` for HTTP POST in production
- Token revoked via `POST /oauth2/revoke` on clean shutdown
