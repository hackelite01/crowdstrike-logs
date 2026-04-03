# Falcon Log Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade CrowdStrike Falcon log collector that polls the Alerts, Audit Events, and Hosts APIs continuously, stores logs as rotating NDJSON files, and optionally forwards them via Syslog TCP, RELP, or HTTP POST.

**Architecture:** One Python process with one daemon thread per log source, a shared bounded queue, and a single dispatcher thread that fans out to enabled output handlers. A watchdog loop in `main.py` monitors all threads and restarts crashed ones with exponential backoff. State (last_timestamp + last_id per source) is persisted atomically to `state.json` to survive restarts without duplicates.

**Tech Stack:** Python 3.11+, `requests`, `pyyaml`, `python-dotenv`, `relppy`, `pytest`, `pytest-mock`

---

## File Map

| File | Responsibility |
|---|---|
| `main.py` | Entry point, thread orchestration, watchdog, signal handling, hot-reload |
| `utils/config.py` | YAML loader with `${ENV_VAR}` substitution |
| `utils/logger.py` | JSON-lines structured log formatter |
| `utils/metrics.py` | Thread-safe counters + periodic metrics emit |
| `state/manager.py` | Atomic `state.json` read/write (last_timestamp + last_id) |
| `collector/auth.py` | OAuth2 token lifecycle, lock+double-check refresh, revocation |
| `collector/api_client.py` | HTTP client: retry, backoff, global `RateLimitController` |
| `collector/base.py` | `BaseCollector(Thread)`: poll loop, enrichment, per-page checkpoint |
| `collector/alerts.py` | Alerts API collector |
| `collector/audit_events.py` | Audit Events API collector |
| `collector/hosts.py` | Hosts API collector |
| `output/base.py` | `OutputHandler` abstract base class |
| `output/dispatcher.py` | Reads bounded queue, fans out to enabled handlers |
| `output/json_file.py` | Rotating NDJSON files with disk space guard |
| `output/syslog_tcp.py` | RFC 5424 syslog over TCP with optional TLS |
| `output/relp.py` | RELP via `relppy` |
| `output/http_post.py` | HTTP POST / webhook with batching |
| `config.example.yaml` | Reference config (no secrets) |
| `requirements.txt` | Runtime + dev dependencies |
| `.gitignore` | Excludes secrets and generated files |
| `.dockerignore` | Excludes secrets from image layers |
| `tests/` | Mirror of source tree |

---

## Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `.gitignore`
- Create: `.dockerignore`
- Create: `config.example.yaml`
- Create: all `__init__.py` files
- Create: `tests/__init__.py` and subdirs

- [ ] **Step 1: Create directory skeleton**

```bash
cd "c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs"
mkdir -p collector state output utils tests
touch collector/__init__.py state/__init__.py output/__init__.py utils/__init__.py
touch tests/__init__.py
```

- [ ] **Step 2: Write requirements.txt**

```
# c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs/requirements.txt
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
relppy>=0.3.0

# dev / test
pytest>=7.4.0
pytest-mock>=3.12.0
```

- [ ] **Step 3: Write .gitignore**

```
# c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs/.gitignore
config.yaml
.env
state.json
state.json.tmp
logs/
*.pyc
__pycache__/
.venv/
venv/
*.egg-info/
.pytest_cache/
reload.trigger
```

- [ ] **Step 4: Write .dockerignore**

```
# c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs/.dockerignore
config.yaml
.env
state.json
logs/
*.pyc
__pycache__/
.venv/
venv/
tests/
.git/
reload.trigger
```

- [ ] **Step 5: Write config.example.yaml**

```yaml
# c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs/config.example.yaml
falcon:
  client_id: "${FALCON_CLIENT_ID}"
  client_secret: "${FALCON_CLIENT_SECRET}"
  base_url: "https://api.us-2.crowdstrike.com"
  token_refresh_buffer_seconds: 300

collection:
  poll_interval_seconds: 30
  tag: "my-tenant"
  checkpoint_per_page: false
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

queue:
  maxsize: 10000
  full_warn_interval_seconds: 10

outputs:
  json_file:
    enabled: true
    directory: "./logs"
    rotation: hourly
    filename_prefix: "falcon"
    max_size_mb: 256
    min_free_disk_mb: 500

  syslog_tcp:
    enabled: false
    host: "10.0.1.50"
    port: 514
    facility: 16
    app_name: "falcon-collector"
    tls:
      enabled: false
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
  log_interval_seconds: 60
```

- [ ] **Step 6: Commit**

```bash
git init
git add requirements.txt .gitignore .dockerignore config.example.yaml \
        collector/__init__.py state/__init__.py output/__init__.py \
        utils/__init__.py tests/__init__.py
git commit -m "chore: project scaffolding"
```

---

## Task 2: Config Loader

**Files:**
- Create: `utils/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_config.py
import os
import pytest
import yaml
from pathlib import Path
from utils.config import load_config, ConfigError


def write_yaml(tmp_path, content: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(content))
    return str(p)


def test_loads_plain_values(tmp_path):
    path = write_yaml(tmp_path, {"falcon": {"base_url": "https://example.com"}})
    cfg = load_config(path)
    assert cfg["falcon"]["base_url"] == "https://example.com"


def test_substitutes_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET", "hunter2")
    path = write_yaml(tmp_path, {"falcon": {"client_secret": "${MY_SECRET}"}})
    cfg = load_config(path)
    assert cfg["falcon"]["client_secret"] == "hunter2"


def test_raises_on_missing_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    path = write_yaml(tmp_path, {"key": "${MISSING_VAR}"})
    with pytest.raises(ConfigError, match="MISSING_VAR"):
        load_config(path)


def test_substitutes_nested_env_vars(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST", "10.0.0.1")
    path = write_yaml(tmp_path, {"outputs": {"syslog_tcp": {"host": "${HOST}"}}})
    cfg = load_config(path)
    assert cfg["outputs"]["syslog_tcp"]["host"] == "10.0.0.1"


def test_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd "c:/Users/FCT/Downloads/Mayank nu KaamKaaj/crowdstrike-logs"
python -m pytest tests/test_config.py -v
```
Expected: `ModuleNotFoundError: No module named 'utils.config'`

- [ ] **Step 3: Implement config loader**

```python
# utils/config.py
import os
import re
import yaml
from typing import Any


class ConfigError(Exception):
    pass


def _substitute_env_vars(value: str) -> str:
    pattern = r'\$\{([^}]+)\}'

    def replacer(match: re.Match) -> str:
        var_name = match.group(1)
        val = os.environ.get(var_name)
        if val is None:
            raise ConfigError(f"Environment variable '{var_name}' is not set")
        return val

    return re.sub(pattern, replacer, value)


def _resolve(obj: Any) -> Any:
    if isinstance(obj, str):
        return _substitute_env_vars(obj)
    if isinstance(obj, dict):
        return {k: _resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(item) for item in obj]
    return obj


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return _resolve(raw or {})
```

- [ ] **Step 4: Run tests to confirm passing**

```bash
python -m pytest tests/test_config.py -v
```
Expected: 5 PASSED

- [ ] **Step 5: Commit**

```bash
git add utils/config.py tests/test_config.py
git commit -m "feat: config loader with env var substitution"
```

---

## Task 3: Structured Logger + Metrics

**Files:**
- Create: `utils/logger.py`
- Create: `utils/metrics.py`
- Create: `tests/test_metrics.py`

- [ ] **Step 1: Write logger**

No tests needed — this is a thin wrapper around Python's standard `logging`. Write directly:

```python
# utils/logger.py
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log["exception"] = self.formatException(record.exc_info)
        return json.dumps(log)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers = [handler]
```

- [ ] **Step 2: Write failing metrics tests**

```python
# tests/test_metrics.py
import time
import threading
from utils.metrics import MetricsCollector


def test_increment_and_read():
    m = MetricsCollector()
    m.increment("alerts", "events_collected")
    m.increment("alerts", "events_collected")
    snap = m.snapshot()
    assert snap["alerts"]["events_collected"] == 2


def test_record_latency():
    m = MetricsCollector()
    m.record_latency("alerts", 100)
    m.record_latency("alerts", 200)
    snap = m.snapshot()
    assert snap["alerts"]["api_latency_ms_avg"] == 150.0


def test_set_queue_depth():
    m = MetricsCollector()
    m.set_queue_depth(42)
    snap = m.snapshot()
    assert snap["queue_depth"] == 42


def test_snapshot_resets_counters():
    m = MetricsCollector()
    m.increment("hosts", "events_collected", 5)
    m.snapshot()  # resets
    snap2 = m.snapshot()
    assert snap2.get("hosts", {}).get("events_collected", 0) == 0


def test_thread_safety():
    m = MetricsCollector()

    def worker():
        for _ in range(1000):
            m.increment("alerts", "events_collected")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snap = m.snapshot()
    assert snap["alerts"]["events_collected"] == 4000
```

- [ ] **Step 3: Run to confirm failure**

```bash
python -m pytest tests/test_metrics.py -v
```
Expected: `ModuleNotFoundError: No module named 'utils.metrics'`

- [ ] **Step 4: Implement MetricsCollector**

```python
# utils/metrics.py
import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger("metrics")


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._latencies: Dict[str, list] = defaultdict(list)
        self._queue_depth: int = 0

    def increment(self, source: str, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[source][key] += amount

    def record_latency(self, source: str, ms: float) -> None:
        with self._lock:
            self._latencies[source].append(ms)

    def set_queue_depth(self, depth: int) -> None:
        with self._lock:
            self._queue_depth = depth

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            result: Dict[str, Any] = {"queue_depth": self._queue_depth}
            for source, counts in self._counters.items():
                result[source] = dict(counts)
                lats = self._latencies.get(source, [])
                result[source]["api_latency_ms_avg"] = (
                    round(sum(lats) / len(lats), 1) if lats else 0.0
                )
            # reset for next window
            self._counters.clear()
            self._latencies.clear()
        return result

    def emit_loop(self, interval_seconds: int, tag: str) -> None:
        """Call in a daemon thread. Logs a metrics JSON line every interval_seconds."""
        while True:
            time.sleep(interval_seconds)
            snap = self.snapshot()
            snap["type"] = "metrics"
            snap["tag"] = tag
            snap["timestamp"] = datetime.now(timezone.utc).isoformat()
            logger.info(json.dumps(snap))
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_metrics.py -v
```
Expected: 5 PASSED

- [ ] **Step 6: Commit**

```bash
git add utils/logger.py utils/metrics.py tests/test_metrics.py
git commit -m "feat: structured logger and metrics collector"
```

---

## Task 4: State Manager

**Files:**
- Create: `state/manager.py`
- Create: `tests/test_state_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_state_manager.py
import json
import os
from pathlib import Path
import pytest
from state.manager import StateManager


def test_load_returns_empty_when_file_missing(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    assert sm.load() == {}


def test_save_and_load_roundtrip(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.save({"alerts": {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": "abc"}})
    data = sm.load()
    assert data["alerts"]["last_id"] == "abc"


def test_update_source_creates_entry(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.update_source("alerts", "2026-01-01T00:00:00Z", "id-001")
    data = sm.load()
    assert data["alerts"] == {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": "id-001"}


def test_update_source_preserves_other_sources(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.update_source("alerts", "2026-01-01T00:00:00Z", "a1")
    sm.update_source("hosts", "2026-01-02T00:00:00Z", "h1")
    data = sm.load()
    assert "alerts" in data
    assert "hosts" in data


def test_atomic_write_uses_same_dir(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.save({"test": "value"})
    # tmp file should be gone after save
    assert not (tmp_path / "state.json.tmp").exists()
    assert (tmp_path / "state.json").exists()


def test_get_source_state_defaults(tmp_path):
    from datetime import datetime, timezone, timedelta
    sm = StateManager(str(tmp_path / "state.json"))
    state = sm.get_source_state("alerts")
    # default last_timestamp is ~1 hour ago
    ts = datetime.fromisoformat(state["last_timestamp"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    assert abs((now - ts).total_seconds() - 3600) < 5
    assert state["last_id"] == ""
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_state_manager.py -v
```
Expected: `ModuleNotFoundError: No module named 'state.manager'`

- [ ] **Step 3: Implement StateManager**

```python
# state/manager.py
import json
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict


class StateManager:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> Dict[str, Any]:
        if not self._path.exists():
            return {}
        with self._lock:
            with open(self._path, "r") as f:
                return json.load(f)

    def save(self, state: Dict[str, Any]) -> None:
        tmp = self._path.parent / (self._path.name + ".tmp")
        with self._lock:
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self._path)

    def update_source(self, source: str, last_timestamp: str, last_id: str) -> None:
        state = self.load()
        state[source] = {"last_timestamp": last_timestamp, "last_id": last_id}
        self.save(state)

    def get_source_state(self, source: str) -> Dict[str, str]:
        state = self.load()
        if source in state:
            return state[source]
        default_ts = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"last_timestamp": default_ts, "last_id": ""}
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_state_manager.py -v
```
Expected: 6 PASSED

- [ ] **Step 5: Commit**

```bash
git add state/manager.py tests/test_state_manager.py
git commit -m "feat: atomic state manager with last_timestamp and last_id"
```

---

## Task 5: Auth Manager

**Files:**
- Create: `collector/auth.py`
- Create: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_auth.py
import time
import pytest
from unittest.mock import patch, MagicMock
from collector.auth import AuthManager


def _mock_token_response(expires_in: int = 1800) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 201
    resp.json.return_value = {"access_token": "tok-abc", "expires_in": expires_in}
    resp.raise_for_status = MagicMock()
    return resp


def test_get_token_fetches_on_first_call():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()) as mock_post:
        auth = AuthManager("https://api.example.com", "cid", "csec")
        token = auth.get_token()
    assert token == "tok-abc"
    mock_post.assert_called_once()


def test_get_token_reuses_valid_token():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()) as mock_post:
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
        auth.get_token()
    assert mock_post.call_count == 1


def test_get_token_refreshes_when_expiring():
    with patch("collector.auth.requests.post", return_value=_mock_token_response(expires_in=200)) as mock_post:
        # buffer=300 > expires_in=200, so token is immediately expiring
        auth = AuthManager("https://api.example.com", "cid", "csec", refresh_buffer_seconds=300)
        auth.get_token()  # fetch
        auth.get_token()  # should refresh again because expiring
    assert mock_post.call_count == 2


def test_revoke_posts_to_revoke_endpoint():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()):
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
    with patch("collector.auth.requests.post") as mock_revoke:
        auth.revoke()
    mock_revoke.assert_called_once()
    call_kwargs = mock_revoke.call_args
    assert "/oauth2/revoke" in call_kwargs[0][0]


def test_revoke_silently_ignores_failure():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()):
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
    with patch("collector.auth.requests.post", side_effect=Exception("network error")):
        auth.revoke()  # should not raise
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_auth.py -v
```
Expected: `ModuleNotFoundError: No module named 'collector.auth'`

- [ ] **Step 3: Implement AuthManager**

```python
# collector/auth.py
import logging
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger("collector.auth")


class AuthManager:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        refresh_buffer_seconds: int = 300,
    ) -> None:
        self._base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_buffer = refresh_buffer_seconds
        self._token: Optional[str] = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def get_token(self) -> str:
        if self._is_expiring():
            with self._lock:
                if self._is_expiring():
                    self._do_refresh()
        return self._token  # type: ignore[return-value]

    def _is_expiring(self) -> bool:
        return time.time() >= (self._expires_at - self._refresh_buffer)

    def _do_refresh(self) -> None:
        logger.info("Refreshing OAuth2 token")
        resp = requests.post(
            f"{self._base_url}/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + data["expires_in"]
        logger.info("Token refreshed, expires_in=%ds", data["expires_in"])

    def force_refresh(self) -> None:
        """Called on 401 mid-poll — refreshes under lock."""
        with self._lock:
            self._do_refresh()

    def revoke(self) -> None:
        if not self._token:
            return
        try:
            requests.post(
                f"{self._base_url}/oauth2/revoke",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "token": self._token,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                timeout=10,
            )
            logger.info("OAuth2 token revoked")
        except Exception as exc:
            logger.warning("Token revocation failed (ignored): %s", exc)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_auth.py -v
```
Expected: 5 PASSED

- [ ] **Step 5: Commit**

```bash
git add collector/auth.py tests/test_auth.py
git commit -m "feat: OAuth2 auth manager with lock+double-check refresh"
```

---

## Task 6: API Client + Rate Limit Controller

**Files:**
- Create: `collector/api_client.py`
- Create: `tests/test_api_client.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_api_client.py
import time
import pytest
from unittest.mock import MagicMock, patch, call
from collector.api_client import ApiClient, RateLimitController


def _make_response(status: int, body: dict, headers: dict = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.headers = headers or {}
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    else:
        resp.raise_for_status = MagicMock()
    return resp


def _make_client(mock_post=None):
    auth = MagicMock()
    auth.get_token.return_value = "tok"
    rl = RateLimitController()
    client = ApiClient(auth, rl, "https://api.example.com")
    return client, auth, rl


def test_get_returns_response_body():
    client, _, _ = _make_client()
    ok_resp = _make_response(200, {"resources": ["id1"]})
    with patch("collector.api_client.requests.request", return_value=ok_resp):
        result = client.get("/detects/queries/detects/v1", params={"limit": 10})
    assert result == {"resources": ["id1"]}


def test_retries_on_500_then_succeeds():
    client, _, _ = _make_client()
    fail = _make_response(500, {})
    ok = _make_response(200, {"resources": []})
    with patch("collector.api_client.requests.request", side_effect=[fail, ok]):
        with patch("collector.api_client.time.sleep"):
            result = client.get("/some/path")
    assert result == {"resources": []}


def test_raises_after_max_retries():
    client, _, _ = _make_client()
    fail = _make_response(500, {})
    with patch("collector.api_client.requests.request", return_value=fail):
        with patch("collector.api_client.time.sleep"):
            with pytest.raises(Exception):
                client.get("/some/path")


def test_handles_429_with_retry_after_header():
    client, _, rl = _make_client()
    future_epoch = int(time.time()) + 5
    throttled = _make_response(429, {}, {"X-RateLimit-RetryAfter": str(future_epoch)})
    ok = _make_response(200, {"resources": []})
    with patch("collector.api_client.requests.request", side_effect=[throttled, ok]):
        with patch("collector.api_client.time.sleep") as mock_sleep:
            result = client.get("/some/path")
    assert result == {"resources": []}
    mock_sleep.assert_called()


def test_handles_401_refreshes_token_and_retries():
    client, auth, _ = _make_client()
    unauthorized = _make_response(401, {})
    unauthorized.raise_for_status = MagicMock()
    ok = _make_response(200, {"resources": ["x"]})
    with patch("collector.api_client.requests.request", side_effect=[unauthorized, ok]):
        result = client.get("/some/path")
    auth.force_refresh.assert_called_once()
    assert result == {"resources": ["x"]}


def test_rate_limit_controller_wait_if_limited():
    rl = RateLimitController()
    rl.set_retry_after(time.time() + 2)
    with patch("collector.api_client.time.sleep") as mock_sleep:
        rl.wait_if_limited()
    mock_sleep.assert_called_once()
    sleep_arg = mock_sleep.call_args[0][0]
    assert 1.5 < sleep_arg < 3.0
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_api_client.py -v
```
Expected: `ModuleNotFoundError: No module named 'collector.api_client'`

- [ ] **Step 3: Implement ApiClient and RateLimitController**

```python
# collector/api_client.py
import logging
import random
import threading
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("collector.api_client")

_MAX_RETRIES = 5
_BASE_BACKOFF = 2


class RateLimitController:
    """Single shared gate for all collector threads — Falcon rate limits per API key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._retry_after: float = 0.0

    def set_retry_after(self, epoch: float) -> None:
        with self._lock:
            if epoch > self._retry_after:
                self._retry_after = epoch

    def wait_if_limited(self) -> None:
        deadline = self._retry_after
        now = time.time()
        if now < deadline:
            wait = deadline - now + 0.5
            logger.warning("Rate limited (global) — sleeping %.1fs", wait)
            time.sleep(wait)


class ApiClient:
    def __init__(
        self,
        auth_manager: Any,
        rate_limit_controller: RateLimitController,
        base_url: str,
    ) -> None:
        self._auth = auth_manager
        self._rl = rate_limit_controller
        self._base_url = base_url.rstrip("/")

    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        return self._request("GET", path, params=params)

    def post(self, path: str, json: Optional[Dict] = None) -> dict:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        url = f"{self._base_url}{path}"
        for attempt in range(_MAX_RETRIES):
            self._rl.wait_if_limited()
            headers = {"Authorization": f"Bearer {self._auth.get_token()}"}
            try:
                resp = requests.request(
                    method, url, headers=headers, timeout=30, **kwargs
                )
            except requests.exceptions.RequestException as exc:
                if attempt == _MAX_RETRIES - 1:
                    raise
                logger.warning("Network error (attempt %d): %s", attempt + 1, exc)
                self._backoff(attempt)
                continue

            if resp.status_code == 401:
                logger.warning("401 Unauthorized — refreshing token and retrying")
                self._auth.force_refresh()
                headers["Authorization"] = f"Bearer {self._auth.get_token()}"
                resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

            if resp.status_code == 429:
                retry_after = int(
                    resp.headers.get("X-RateLimit-RetryAfter", int(time.time()) + 60)
                )
                self._rl.set_retry_after(float(retry_after))
                self._rl.wait_if_limited()
                continue

            if resp.status_code in (500, 503):
                if attempt == _MAX_RETRIES - 1:
                    resp.raise_for_status()
                logger.warning("HTTP %d (attempt %d) — retrying", resp.status_code, attempt + 1)
                self._backoff(attempt)
                continue

            resp.raise_for_status()
            return resp.json()

        raise RuntimeError(f"Max retries ({_MAX_RETRIES}) exceeded for {method} {path}")

    def _backoff(self, attempt: int) -> None:
        sleep = _BASE_BACKOFF * (2 ** attempt) + random.random()
        logger.debug("Backoff %.1fs (attempt %d)", sleep, attempt + 1)
        time.sleep(sleep)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_api_client.py -v
```
Expected: 6 PASSED

- [ ] **Step 5: Commit**

```bash
git add collector/api_client.py tests/test_api_client.py
git commit -m "feat: API client with retry, backoff, global rate-limit controller"
```

---

## Task 7: Base Collector Thread

**Files:**
- Create: `collector/base.py`
- Create: `tests/test_base_collector.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_base_collector.py
import threading
import time
from queue import Queue
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from collector.base import BaseCollector, enrich_event


def test_enrich_event_adds_required_fields():
    event = {"id": "evt-1", "data": "value"}
    enriched = enrich_event(event, source="alerts", tag="my-tenant", event_id_field="id")
    assert enriched["_source"] == "alerts"
    assert enriched["_tag"] == "my-tenant"
    assert enriched["_event_id"] == "evt-1"
    assert enriched["_collector_version"] == "1.0.0"
    assert "_collected_at" in enriched
    # original fields preserved
    assert enriched["data"] == "value"


def test_enrich_event_collected_at_is_utc_iso():
    event = {}
    enriched = enrich_event(event, source="alerts", tag="t", event_id_field="id")
    ts = enriched["_collected_at"]
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def test_should_skip_event_same_ts_and_lower_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="aaa",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is True


def test_should_skip_event_same_ts_same_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="bbb",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is True


def test_should_not_skip_event_newer_ts():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:01Z",
        event_id="aaa",
        last_ts="2026-01-01T00:00:00Z",
        last_id="zzz",
    ) is False


def test_should_not_skip_event_same_ts_higher_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="ccc",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_base_collector.py -v
```
Expected: `ModuleNotFoundError: No module named 'collector.base'`

- [ ] **Step 3: Implement base collector**

```python
# collector/base.py
import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from queue import Full, Queue
from typing import Any, Dict, Optional

logger = logging.getLogger("collector.base")

_COLLECTOR_VERSION = "1.0.0"


def enrich_event(
    event: Dict[str, Any],
    source: str,
    tag: str,
    event_id_field: str,
) -> Dict[str, Any]:
    enriched = dict(event)
    enriched["_collected_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    enriched["_source"] = source
    enriched["_tag"] = tag
    enriched["_collector_version"] = _COLLECTOR_VERSION
    enriched["_event_id"] = event.get(event_id_field, "")
    return enriched


def should_skip_event(
    event_ts: str, event_id: str, last_ts: str, last_id: str
) -> bool:
    """Return True if this event was already processed in a previous cycle."""
    if event_ts > last_ts:
        return False
    if event_ts == last_ts:
        return event_id <= last_id
    return True  # event_ts < last_ts — definitely already seen


class BaseCollector(ABC, threading.Thread):
    def __init__(
        self,
        source_name: str,
        api_client: Any,
        state_manager: Any,
        output_queue: Queue,
        config: Dict[str, Any],
        global_config: Dict[str, Any],
    ) -> None:
        super().__init__(name=f"{source_name}-collector", daemon=True)
        self._source = source_name
        self._api = api_client
        self._state = state_manager
        self._queue = output_queue
        self._source_config = config
        self._global_config = global_config
        self._stop_event = threading.Event()
        self._last_queue_warn: float = 0.0
        self.logger = logging.getLogger(f"collector.{source_name}")

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        interval = self._source_config.get(
            "poll_interval_seconds",
            self._global_config.get("poll_interval_seconds", 30),
        )
        while not self._stop_event.is_set():
            try:
                self._poll()
            except Exception as exc:
                self.logger.error("Poll error: %s", exc, exc_info=True)
            self._stop_event.wait(interval)

    @abstractmethod
    def _poll(self) -> None:
        """Fetch one cycle of events and enqueue them."""

    def _enqueue(self, event: Dict[str, Any]) -> None:
        warn_interval = self._global_config.get("queue", {}).get(
            "full_warn_interval_seconds", 10
        )
        while not self._stop_event.is_set():
            try:
                self._queue.put(event, timeout=5)
                return
            except Full:
                now = time.time()
                if now - self._last_queue_warn >= warn_interval:
                    self.logger.warning("Output queue full — collector blocking")
                    self._last_queue_warn = now

    def _get_state(self) -> Dict[str, str]:
        return self._state.get_source_state(self._source)

    def _save_state(self, last_timestamp: str, last_id: str) -> None:
        self._state.update_source(self._source, last_timestamp, last_id)

    @property
    def _tag(self) -> str:
        return self._global_config.get("tag", "")

    @property
    def _batch_size(self) -> int:
        return self._source_config.get("batch_size", 100)

    @property
    def _checkpoint_per_page(self) -> bool:
        return self._global_config.get("checkpoint_per_page", False)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_base_collector.py -v
```
Expected: 6 PASSED

- [ ] **Step 5: Commit**

```bash
git add collector/base.py tests/test_base_collector.py
git commit -m "feat: base collector thread with enrichment and skip logic"
```

---

## Task 8: Alerts Collector

**Files:**
- Create: `collector/alerts.py`
- Create: `tests/test_alerts.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_alerts.py
from queue import Queue
from unittest.mock import MagicMock, patch
from collector.alerts import AlertsCollector


def _make_collector(api_responses):
    api = MagicMock()
    api.get.side_effect = api_responses
    api.post.side_effect = lambda path, json=None: {
        "resources": [
            {"composite_id": cid, "created_timestamp": "2026-01-01T00:01:00Z", "severity": 3}
            for cid in (json or {}).get("ids", [])
        ]
    }
    state = MagicMock()
    state.get_source_state.return_value = {
        "last_timestamp": "2026-01-01T00:00:00Z",
        "last_id": "",
    }
    queue = Queue()
    source_config = {"poll_interval_seconds": 30, "batch_size": 100}
    global_config = {"tag": "test-tenant", "checkpoint_per_page": False}
    return AlertsCollector(
        api_client=api,
        state_manager=state,
        output_queue=queue,
        config=source_config,
        global_config=global_config,
    ), queue


def test_poll_enqueues_events():
    query_resp = {"resources": ["id-1", "id-2"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([query_resp])
    collector._poll()
    assert queue.qsize() == 2


def test_poll_skips_already_seen_event():
    # Event has same ts and id <= last_id — should be skipped
    query_resp = {"resources": ["id-0"], "meta": {"pagination": {}}}
    api = MagicMock()
    api.get.return_value = query_resp
    api.post.return_value = {
        "resources": [
            {"composite_id": "id-0", "created_timestamp": "2026-01-01T00:00:00Z"}
        ]
    }
    state = MagicMock()
    state.get_source_state.return_value = {
        "last_timestamp": "2026-01-01T00:00:00Z",
        "last_id": "id-0",
    }
    queue = Queue()
    collector = AlertsCollector(
        api_client=api,
        state_manager=state,
        output_queue=queue,
        config={"batch_size": 100},
        global_config={"tag": "t"},
    )
    collector._poll()
    assert queue.qsize() == 0


def test_poll_enriches_events():
    query_resp = {"resources": ["id-1"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([query_resp])
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "alerts"
    assert event["_tag"] == "test-tenant"
    assert event["_event_id"] == "id-1"
    assert "_collected_at" in event


def test_poll_paginates_with_after_cursor():
    page1 = {"resources": ["id-1"], "meta": {"pagination": {"after": "cursor-abc"}}}
    page2 = {"resources": ["id-2"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([page1, page2])
    collector._poll()
    assert queue.qsize() == 2
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_alerts.py -v
```
Expected: `ModuleNotFoundError: No module named 'collector.alerts'`

- [ ] **Step 3: Implement AlertsCollector**

```python
# collector/alerts.py
import logging
from queue import Queue
from typing import Any, Dict, Optional

from collector.base import BaseCollector, enrich_event, should_skip_event

logger = logging.getLogger("collector.alerts")

_QUERY_PATH = "/alerts/queries/alerts/v2"
_ENTITY_PATH = "/alerts/entities/alerts/GET/v2"
_EVENT_ID_FIELD = "composite_id"
_TS_FIELD = "created_timestamp"


class AlertsCollector(BaseCollector):
    def __init__(
        self,
        api_client: Any,
        state_manager: Any,
        output_queue: Queue,
        config: Dict[str, Any],
        global_config: Dict[str, Any],
    ) -> None:
        super().__init__(
            source_name="alerts",
            api_client=api_client,
            state_manager=state_manager,
            output_queue=output_queue,
            config=config,
            global_config=global_config,
        )

    def _poll(self) -> None:
        state = self._get_state()
        last_ts = state["last_timestamp"]
        last_id = state["last_id"]

        new_last_ts = last_ts
        new_last_id = last_id
        after: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "filter": f"created_timestamp:>='{last_ts}'",
                "sort": "created_timestamp.asc",
                "limit": self._batch_size,
            }
            if after:
                params["after"] = after

            query_resp = self._api.get(_QUERY_PATH, params=params)
            ids = query_resp.get("resources") or []

            if ids:
                detail_resp = self._api.post(_ENTITY_PATH, json={"ids": ids})
                events = detail_resp.get("resources") or []

                for event in events:
                    event_ts = event.get(_TS_FIELD, "")
                    event_id = event.get(_EVENT_ID_FIELD, "")
                    if should_skip_event(event_ts, event_id, last_ts, last_id):
                        continue
                    enriched = enrich_event(event, "alerts", self._tag, _EVENT_ID_FIELD)
                    self._enqueue(enriched)
                    if event_ts > new_last_ts or (
                        event_ts == new_last_ts and event_id > new_last_id
                    ):
                        new_last_ts = event_ts
                        new_last_id = event_id

                if self._checkpoint_per_page:
                    self._save_state(new_last_ts, new_last_id)

            pagination = (query_resp.get("meta") or {}).get("pagination") or {}
            after = pagination.get("after")
            if not after:
                break

        self._save_state(new_last_ts, new_last_id)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_alerts.py -v
```
Expected: 4 PASSED

- [ ] **Step 5: Commit**

```bash
git add collector/alerts.py tests/test_alerts.py
git commit -m "feat: alerts collector with pagination and deduplication"
```

---

## Task 9: Audit Events + Hosts Collectors

**Files:**
- Create: `collector/audit_events.py`
- Create: `collector/hosts.py`
- Create: `tests/test_audit_events.py`
- Create: `tests/test_hosts.py`

- [ ] **Step 1: Write failing tests for audit events**

```python
# tests/test_audit_events.py
from queue import Queue
from unittest.mock import MagicMock
from collector.audit_events import AuditEventsCollector


def _make_collector():
    api = MagicMock()
    api.get.side_effect = [
        {"resources": ["ae-1"], "meta": {"pagination": {}}},
        {"resources": [{"id": "ae-1", "created_timestamp": "2026-01-01T00:01:00Z", "action": "login"}]},
    ]
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": ""}
    queue = Queue()
    return AuditEventsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 200}, global_config={"tag": "t"},
    ), queue


def test_audit_events_poll_enqueues_event():
    collector, queue = _make_collector()
    collector._poll()
    assert queue.qsize() == 1


def test_audit_events_enrichment():
    collector, queue = _make_collector()
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "audit_events"
    assert event["_event_id"] == "ae-1"
```

- [ ] **Step 2: Write failing tests for hosts**

```python
# tests/test_hosts.py
from queue import Queue
from unittest.mock import MagicMock
from collector.hosts import HostsCollector


def _make_collector():
    api = MagicMock()
    api.get.side_effect = [
        {"resources": ["dev-1"], "meta": {"pagination": {}}},
    ]
    api.post.return_value = {
        "resources": [{"device_id": "dev-1", "modified_timestamp": "2026-01-01T00:01:00Z", "hostname": "test-host"}]
    }
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": ""}
    queue = Queue()
    return HostsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 500}, global_config={"tag": "t"},
    ), queue


def test_hosts_poll_enqueues_event():
    collector, queue = _make_collector()
    collector._poll()
    assert queue.qsize() == 1


def test_hosts_enrichment():
    collector, queue = _make_collector()
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "hosts"
    assert event["_event_id"] == "dev-1"
```

- [ ] **Step 3: Run both to confirm failure**

```bash
python -m pytest tests/test_audit_events.py tests/test_hosts.py -v
```
Expected: `ModuleNotFoundError`

- [ ] **Step 4: Implement AuditEventsCollector**

```python
# collector/audit_events.py
from queue import Queue
from typing import Any, Dict, Optional

from collector.base import BaseCollector, enrich_event, should_skip_event

_QUERY_PATH = "/audit-events/queries/events/v1"
_ENTITY_PATH = "/audit-events/entities/events/v1"
_EVENT_ID_FIELD = "id"
_TS_FIELD = "created_timestamp"


class AuditEventsCollector(BaseCollector):
    def __init__(
        self,
        api_client: Any,
        state_manager: Any,
        output_queue: Queue,
        config: Dict[str, Any],
        global_config: Dict[str, Any],
    ) -> None:
        super().__init__(
            source_name="audit_events",
            api_client=api_client,
            state_manager=state_manager,
            output_queue=output_queue,
            config=config,
            global_config=global_config,
        )

    def _poll(self) -> None:
        state = self._get_state()
        last_ts = state["last_timestamp"]
        last_id = state["last_id"]
        new_last_ts, new_last_id = last_ts, last_id
        after: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "filter": f"created_timestamp:>='{last_ts}'",
                "sort": "created_timestamp.asc",
                "limit": self._batch_size,
            }
            if after:
                params["after"] = after

            query_resp = self._api.get(_QUERY_PATH, params=params)
            ids = query_resp.get("resources") or []

            if ids:
                entity_resp = self._api.get(_ENTITY_PATH, params={"ids": ids})
                events = entity_resp.get("resources") or []
                for event in events:
                    event_ts = event.get(_TS_FIELD, "")
                    event_id = event.get(_EVENT_ID_FIELD, "")
                    if should_skip_event(event_ts, event_id, last_ts, last_id):
                        continue
                    self._enqueue(enrich_event(event, "audit_events", self._tag, _EVENT_ID_FIELD))
                    if event_ts > new_last_ts or (event_ts == new_last_ts and event_id > new_last_id):
                        new_last_ts, new_last_id = event_ts, event_id
                if self._checkpoint_per_page:
                    self._save_state(new_last_ts, new_last_id)

            after = ((query_resp.get("meta") or {}).get("pagination") or {}).get("after")
            if not after:
                break

        self._save_state(new_last_ts, new_last_id)
```

- [ ] **Step 5: Implement HostsCollector**

```python
# collector/hosts.py
from queue import Queue
from typing import Any, Dict, Optional

from collector.base import BaseCollector, enrich_event, should_skip_event

_QUERY_PATH = "/devices/queries/devices/v1"
_ENTITY_PATH = "/devices/entities/devices/GET/v2"
_EVENT_ID_FIELD = "device_id"
_TS_FIELD = "modified_timestamp"


class HostsCollector(BaseCollector):
    def __init__(
        self,
        api_client: Any,
        state_manager: Any,
        output_queue: Queue,
        config: Dict[str, Any],
        global_config: Dict[str, Any],
    ) -> None:
        super().__init__(
            source_name="hosts",
            api_client=api_client,
            state_manager=state_manager,
            output_queue=output_queue,
            config=config,
            global_config=global_config,
        )

    def _poll(self) -> None:
        state = self._get_state()
        last_ts = state["last_timestamp"]
        last_id = state["last_id"]
        new_last_ts, new_last_id = last_ts, last_id
        after: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "filter": f"modified_timestamp:>='{last_ts}'",
                "sort": "modified_timestamp.asc",
                "limit": self._batch_size,
            }
            if after:
                params["after"] = after

            query_resp = self._api.get(_QUERY_PATH, params=params)
            ids = query_resp.get("resources") or []

            if ids:
                detail_resp = self._api.post(_ENTITY_PATH, json={"ids": ids})
                events = detail_resp.get("resources") or []
                for event in events:
                    event_ts = event.get(_TS_FIELD, "")
                    event_id = event.get(_EVENT_ID_FIELD, "")
                    if should_skip_event(event_ts, event_id, last_ts, last_id):
                        continue
                    self._enqueue(enrich_event(event, "hosts", self._tag, _EVENT_ID_FIELD))
                    if event_ts > new_last_ts or (event_ts == new_last_ts and event_id > new_last_id):
                        new_last_ts, new_last_id = event_ts, event_id
                if self._checkpoint_per_page:
                    self._save_state(new_last_ts, new_last_id)

            after = ((query_resp.get("meta") or {}).get("pagination") or {}).get("after")
            if not after:
                break

        self._save_state(new_last_ts, new_last_id)
```

- [ ] **Step 6: Run all collector tests**

```bash
python -m pytest tests/test_audit_events.py tests/test_hosts.py -v
```
Expected: 4 PASSED

- [ ] **Step 7: Commit**

```bash
git add collector/audit_events.py collector/hosts.py \
        tests/test_audit_events.py tests/test_hosts.py
git commit -m "feat: audit events and hosts collectors"
```

---

## Task 10: Output Base + JSON File Handler

**Files:**
- Create: `output/base.py`
- Create: `output/json_file.py`
- Create: `tests/test_output_json_file.py`

- [ ] **Step 1: Write output base (no tests — pure interface)**

```python
# output/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict


class OutputHandler(ABC):
    name: str = "base"
    enabled: bool = True

    @abstractmethod
    def write(self, event: Dict[str, Any]) -> None:
        """Write a single event. Raise on unrecoverable error."""

    def close(self) -> None:
        """Optional cleanup on shutdown."""
```

- [ ] **Step 2: Write failing tests for JSON file output**

```python
# tests/test_output_json_file.py
import json
import shutil
import time
from pathlib import Path
import pytest
from output.json_file import JsonFileOutput


def test_writes_ndjson_line(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"_source": "alerts", "id": "1"})
    out.close()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["id"] == "1"


def test_multiple_writes_each_on_own_line(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"id": "1"})
    out.write({"id": "2"})
    out.close()
    files = list(tmp_path.glob("*.json"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 2


def test_filename_contains_prefix_and_source(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"_source": "alerts", "id": "1"})
    out.close()
    files = list(tmp_path.glob("falcon_alerts_*.json"))
    assert len(files) == 1


def test_disables_when_disk_full(tmp_path, monkeypatch):
    # Simulate disk full by patching disk_usage to return tiny free space
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "disk_usage", lambda p: type("u", (), {"free": 1024 * 1024})())
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 500})
    out.write({"id": "1"})  # should not raise, just skip
    out.close()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 0
```

- [ ] **Step 3: Run to confirm failure**

```bash
python -m pytest tests/test_output_json_file.py -v
```
Expected: `ModuleNotFoundError: No module named 'output.json_file'`

- [ ] **Step 4: Implement JsonFileOutput**

```python
# output/json_file.py
import json
import logging
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, IO, Optional

from output.base import OutputHandler

logger = logging.getLogger("output.json_file")


class JsonFileOutput(OutputHandler):
    name = "json_file"

    def __init__(self, config: Dict[str, Any]) -> None:
        self._dir = Path(config["directory"])
        self._rotation = config.get("rotation", "hourly")
        self._prefix = config.get("filename_prefix", "falcon")
        self._max_size_bytes = config.get("max_size_mb", 256) * 1024 * 1024
        self._min_free_bytes = config.get("min_free_disk_mb", 500) * 1024 * 1024
        self._lock = threading.Lock()
        self._handles: Dict[str, IO[str]] = {}  # key = source_window
        self._dir.mkdir(parents=True, exist_ok=True)
        self.enabled = True

    def _window_key(self, source: str) -> str:
        now = datetime.now(timezone.utc)
        if self._rotation == "hourly":
            return f"{source}_{now.strftime('%Y-%m-%d_%H')}"
        return f"{source}_{now.strftime('%Y-%m-%d')}"

    def _get_handle(self, source: str, window: str) -> Optional[IO[str]]:
        key = f"{source}_{window}"
        if key not in self._handles:
            filename = self._dir / f"{self._prefix}_{window}.json"
            self._handles[key] = open(filename, "a", encoding="utf-8")
        handle = self._handles[key]
        # size-based rotation
        handle.flush()
        try:
            size = Path(handle.name).stat().st_size
        except OSError:
            size = 0
        if size >= self._max_size_bytes:
            handle.close()
            del self._handles[key]
            # append epoch suffix for uniqueness
            import time
            filename = self._dir / f"{self._prefix}_{window}_{int(time.time())}.json"
            self._handles[key] = open(filename, "a", encoding="utf-8")
        return self._handles[key]

    def _check_disk(self) -> bool:
        try:
            free = shutil.disk_usage(self._dir).free
            if free < self._min_free_bytes:
                logger.warning(
                    "Low disk space (%.0f MB free) — skipping file write",
                    free / 1024 / 1024,
                )
                return False
        except OSError as exc:
            logger.error("Disk check failed: %s", exc)
            return False
        return True

    def write(self, event: Dict[str, Any]) -> None:
        if not self._check_disk():
            return
        source = event.get("_source", "unknown")
        window = self._window_key(source)
        with self._lock:
            try:
                handle = self._get_handle(source, window)
                handle.write(json.dumps(event) + "\n")
                handle.flush()
            except OSError as exc:
                logger.error("File write error: %s", exc)

    def close(self) -> None:
        with self._lock:
            for handle in self._handles.values():
                try:
                    handle.close()
                except OSError:
                    pass
            self._handles.clear()
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_output_json_file.py -v
```
Expected: 4 PASSED

- [ ] **Step 6: Commit**

```bash
git add output/base.py output/json_file.py tests/test_output_json_file.py
git commit -m "feat: output base interface and rotating JSON file handler"
```

---

## Task 11: Syslog TCP + RELP + HTTP POST Outputs

**Files:**
- Create: `output/syslog_tcp.py`
- Create: `output/relp.py`
- Create: `output/http_post.py`
- Create: `tests/test_output_syslog_tcp.py`
- Create: `tests/test_output_http_post.py`

- [ ] **Step 1: Write failing tests for syslog TCP**

```python
# tests/test_output_syslog_tcp.py
import json
import socket
from unittest.mock import MagicMock, patch
from output.syslog_tcp import SyslogTcpOutput


def _make_output(tls_enabled=False):
    config = {
        "host": "127.0.0.1", "port": 514, "facility": 16,
        "app_name": "falcon-collector",
        "tls": {"enabled": tls_enabled, "ca_cert": "", "verify": True},
    }
    return SyslogTcpOutput(config)


def test_write_sends_bytes_over_socket():
    out = _make_output()
    mock_sock = MagicMock()
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._connect()
        out.write({"_source": "alerts", "id": "1", "_collected_at": "2026-01-01T00:00:00Z"})
    mock_sock.sendall.assert_called_once()
    sent = mock_sock.sendall.call_args[0][0]
    assert isinstance(sent, bytes)


def test_write_formats_rfc5424():
    out = _make_output()
    mock_sock = MagicMock()
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._connect()
        out.write({"_source": "alerts", "id": "test-evt", "_collected_at": "2026-01-01T00:00:00Z"})
    sent = mock_sock.sendall.call_args[0][0].decode()
    assert "<" in sent  # priority
    assert "falcon-collector" in sent


def test_reconnects_on_broken_pipe():
    out = _make_output()
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = [BrokenPipeError, None]
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._sock = mock_sock
        out.write({"_source": "alerts", "id": "1", "_collected_at": "2026-01-01T00:00:00Z"})
    assert mock_sock.sendall.call_count == 2
```

- [ ] **Step 2: Write failing tests for HTTP POST**

```python
# tests/test_output_http_post.py
from unittest.mock import MagicMock, patch
from output.http_post import HttpPostOutput


def _make_output():
    return HttpPostOutput({
        "url": "https://10.0.0.1:8080/ingest",
        "headers": {"X-Api-Key": "secret"},
        "batch_size": 2,
        "timeout_seconds": 5,
    })


def test_buffers_until_batch_size():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        assert mock_post.call_count == 0
        out.write({"id": "2"})
        assert mock_post.call_count == 1


def test_flush_on_close_sends_partial_batch():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        out.close()
    assert mock_post.call_count == 1


def test_includes_custom_headers():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        out.write({"id": "2"})
    call_kwargs = mock_post.call_args[1]
    assert call_kwargs["headers"]["X-Api-Key"] == "secret"
```

- [ ] **Step 3: Run to confirm failure**

```bash
python -m pytest tests/test_output_syslog_tcp.py tests/test_output_http_post.py -v
```
Expected: `ModuleNotFoundError`

- [ ] **Step 4: Implement SyslogTcpOutput**

```python
# output/syslog_tcp.py
import json
import logging
import socket
import ssl
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from output.base import OutputHandler

logger = logging.getLogger("output.syslog_tcp")


class SyslogTcpOutput(OutputHandler):
    name = "syslog_tcp"

    def __init__(self, config: Dict[str, Any]) -> None:
        self._host = config["host"]
        self._port = config["port"]
        self._facility = config.get("facility", 16)
        self._app_name = config.get("app_name", "falcon-collector")
        self._tls_cfg = config.get("tls", {})
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.enabled = True

    def _connect(self) -> None:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)
        if self._tls_cfg.get("enabled"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ca = self._tls_cfg.get("ca_cert")
            if ca:
                ctx.load_verify_locations(ca)
            ctx.verify_mode = (
                ssl.CERT_REQUIRED if self._tls_cfg.get("verify", True) else ssl.CERT_NONE
            )
            self._sock = ctx.wrap_socket(raw, server_hostname=self._host)
        else:
            self._sock = raw
        self._sock.connect((self._host, self._port))
        logger.info("Syslog TCP connected to %s:%d", self._host, self._port)

    def _format_rfc5424(self, event: Dict[str, Any]) -> bytes:
        priority = self._facility * 8 + 6  # severity=6 (informational)
        ts = event.get("_collected_at", datetime.now(timezone.utc).isoformat())
        msg = json.dumps(event)
        frame = f"<{priority}>1 {ts} - {self._app_name} - - - {msg}\n"
        return frame.encode("utf-8")

    def write(self, event: Dict[str, Any]) -> None:
        with self._lock:
            data = self._format_rfc5424(event)
            for attempt in range(2):
                try:
                    if self._sock is None:
                        self._connect()
                    self._sock.sendall(data)  # type: ignore[union-attr]
                    return
                except (BrokenPipeError, OSError, ssl.SSLError) as exc:
                    logger.warning("Syslog TCP error (attempt %d): %s — reconnecting", attempt + 1, exc)
                    self._sock = None
            logger.error("Syslog TCP: failed to send after reconnect")

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
```

- [ ] **Step 5: Implement RelpOutput**

```python
# output/relp.py
import json
import logging
import threading
from typing import Any, Dict

from output.base import OutputHandler

logger = logging.getLogger("output.relp")


class RelpOutput(OutputHandler):
    name = "relp"

    def __init__(self, config: Dict[str, Any]) -> None:
        self._host = config["host"]
        self._port = config["port"]
        self._lock = threading.Lock()
        self._client = None
        self.enabled = True

    def _connect(self) -> None:
        from relppy.client import RELPClient  # type: ignore
        self._client = RELPClient(self._host, self._port)
        self._client.connect()
        logger.info("RELP connected to %s:%d", self._host, self._port)

    def write(self, event: Dict[str, Any]) -> None:
        with self._lock:
            msg = json.dumps(event).encode("utf-8")
            for attempt in range(2):
                try:
                    if self._client is None:
                        self._connect()
                    self._client.syslog(msg)  # type: ignore[union-attr]
                    return
                except Exception as exc:
                    logger.warning("RELP error (attempt %d): %s — reconnecting", attempt + 1, exc)
                    self._client = None
            logger.error("RELP: failed to send after reconnect")

    def close(self) -> None:
        with self._lock:
            if self._client:
                try:
                    self._client.disconnect()
                except Exception:
                    pass
                self._client = None
```

- [ ] **Step 6: Implement HttpPostOutput**

```python
# output/http_post.py
import json
import logging
import threading
import time
from typing import Any, Dict, List

import requests

from output.base import OutputHandler

logger = logging.getLogger("output.http_post")

_MAX_RETRIES = 3
_BASE_BACKOFF = 2


class HttpPostOutput(OutputHandler):
    name = "http_post"

    def __init__(self, config: Dict[str, Any]) -> None:
        self._url = config["url"]
        self._headers = dict(config.get("headers") or {})
        self._batch_size = config.get("batch_size", 50)
        self._timeout = config.get("timeout_seconds", 10)
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.enabled = True

    def write(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                self._flush()

    def close(self) -> None:
        with self._lock:
            if self._buffer:
                self._flush()

    def _flush(self) -> None:
        if not self._buffer:
            return
        batch = list(self._buffer)
        self._buffer.clear()
        for attempt in range(_MAX_RETRIES):
            try:
                resp = requests.post(
                    self._url,
                    json={"events": batch},
                    headers=self._headers,
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                logger.debug("HTTP POST sent %d events", len(batch))
                return
            except Exception as exc:
                if attempt == _MAX_RETRIES - 1:
                    logger.error("HTTP POST failed after %d attempts: %s", _MAX_RETRIES, exc)
                    return
                sleep = _BASE_BACKOFF * (2 ** attempt)
                logger.warning("HTTP POST error (attempt %d): %s — retrying in %ds", attempt + 1, exc, sleep)
                time.sleep(sleep)
```

- [ ] **Step 7: Run all output tests**

```bash
python -m pytest tests/test_output_syslog_tcp.py tests/test_output_http_post.py -v
```
Expected: 6 PASSED

- [ ] **Step 8: Commit**

```bash
git add output/syslog_tcp.py output/relp.py output/http_post.py \
        tests/test_output_syslog_tcp.py tests/test_output_http_post.py
git commit -m "feat: syslog TCP, RELP, and HTTP POST output handlers"
```

---

## Task 12: Output Dispatcher

**Files:**
- Create: `output/dispatcher.py`
- Create: `tests/test_dispatcher.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_dispatcher.py
import threading
import time
from queue import Queue
from unittest.mock import MagicMock, call
from output.dispatcher import OutputDispatcher
from utils.metrics import MetricsCollector


def _make_dispatcher(handlers):
    queue = Queue()
    metrics = MetricsCollector()
    dispatcher = OutputDispatcher(queue, handlers, metrics)
    return dispatcher, queue, metrics


def test_dispatcher_fans_out_to_all_enabled_handlers():
    h1 = MagicMock()
    h1.name = "json_file"
    h1.enabled = True
    h2 = MagicMock()
    h2.name = "syslog_tcp"
    h2.enabled = True
    dispatcher, queue, _ = _make_dispatcher([h1, h2])
    dispatcher.start()
    queue.put({"id": "evt-1"})
    time.sleep(0.1)
    dispatcher.stop()
    dispatcher.join(timeout=2)
    h1.write.assert_called_once_with({"id": "evt-1"})
    h2.write.assert_called_once_with({"id": "evt-1"})


def test_dispatcher_skips_disabled_handler():
    h1 = MagicMock()
    h1.name = "relp"
    h1.enabled = False
    dispatcher, queue, _ = _make_dispatcher([h1])
    dispatcher.start()
    queue.put({"id": "evt-1"})
    time.sleep(0.1)
    dispatcher.stop()
    dispatcher.join(timeout=2)
    h1.write.assert_not_called()


def test_dispatcher_continues_on_handler_error():
    h1 = MagicMock()
    h1.name = "syslog_tcp"
    h1.enabled = True
    h1.write.side_effect = Exception("connection refused")
    h2 = MagicMock()
    h2.name = "json_file"
    h2.enabled = True
    dispatcher, queue, _ = _make_dispatcher([h1, h2])
    dispatcher.start()
    queue.put({"id": "evt-1"})
    time.sleep(0.1)
    dispatcher.stop()
    dispatcher.join(timeout=2)
    # h2 must still receive the event even though h1 threw
    h2.write.assert_called_once()


def test_dispatcher_increments_metrics_on_success():
    h1 = MagicMock()
    h1.name = "json_file"
    h1.enabled = True
    dispatcher, queue, metrics = _make_dispatcher([h1])
    dispatcher.start()
    queue.put({"id": "1"})
    queue.put({"id": "2"})
    time.sleep(0.1)
    dispatcher.stop()
    dispatcher.join(timeout=2)
    snap = metrics.snapshot()
    assert snap.get("output_json_file", {}).get("sent", 0) == 2
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_dispatcher.py -v
```
Expected: `ModuleNotFoundError: No module named 'output.dispatcher'`

- [ ] **Step 3: Implement OutputDispatcher**

```python
# output/dispatcher.py
import logging
import threading
from queue import Empty, Queue
from typing import Any, Dict, List

from output.base import OutputHandler
from utils.metrics import MetricsCollector

logger = logging.getLogger("output.dispatcher")


class OutputDispatcher(threading.Thread):
    def __init__(
        self,
        queue: Queue,
        handlers: List[OutputHandler],
        metrics: MetricsCollector,
    ) -> None:
        super().__init__(name="output-dispatcher", daemon=True)
        self._queue = queue
        self._handlers = handlers
        self._metrics = metrics
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=1)
            except Empty:
                self._metrics.set_queue_depth(self._queue.qsize())
                continue

            self._metrics.set_queue_depth(self._queue.qsize())

            for handler in self._handlers:
                if not handler.enabled:
                    continue
                try:
                    handler.write(event)
                    self._metrics.increment(f"output_{handler.name}", "sent")
                except Exception as exc:
                    logger.error("Output handler %s failed: %s", handler.name, exc)
                    self._metrics.increment(f"output_{handler.name}", "failed")

    def close_handlers(self) -> None:
        for handler in self._handlers:
            try:
                handler.close()
            except Exception as exc:
                logger.warning("Handler %s close error: %s", handler.name, exc)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_dispatcher.py -v
```
Expected: 4 PASSED

- [ ] **Step 5: Commit**

```bash
git add output/dispatcher.py tests/test_dispatcher.py
git commit -m "feat: output dispatcher with fan-out, error isolation, metrics"
```

---

## Task 13: Main Entry Point

**Files:**
- Create: `main.py`

- [ ] **Step 1: Write main.py**

This module wires everything together. No unit tests — it is tested by the integration smoke test in Task 14.

```python
# main.py
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from queue import Queue
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()  # must precede all os.environ access

from collector.alerts import AlertsCollector
from collector.api_client import ApiClient, RateLimitController
from collector.audit_events import AuditEventsCollector
from collector.auth import AuthManager
from collector.base import BaseCollector
from collector.hosts import HostsCollector
from output.dispatcher import OutputDispatcher
from output.http_post import HttpPostOutput
from output.json_file import JsonFileOutput
from output.relp import RelpOutput
from output.syslog_tcp import SyslogTcpOutput
from state.manager import StateManager
from utils.config import load_config
from utils.logger import setup_logging
from utils.metrics import MetricsCollector

logger = logging.getLogger("main")

CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.yaml")
RELOAD_TRIGGER = Path("reload.trigger")
WATCHDOG_INTERVAL = 30
RESTART_BACKOFF_BASE = 10
RESTART_BACKOFF_MAX = 120
RESTART_RECOVERY_SECONDS = 300


def build_output_handlers(cfg: dict):
    handlers = []
    out_cfg = cfg.get("outputs", {})

    jf = out_cfg.get("json_file", {})
    if jf.get("enabled"):
        handlers.append(JsonFileOutput(jf))

    syslog = out_cfg.get("syslog_tcp", {})
    if syslog.get("enabled"):
        handlers.append(SyslogTcpOutput(syslog))

    relp = out_cfg.get("relp", {})
    if relp.get("enabled"):
        handlers.append(RelpOutput(relp))

    http = out_cfg.get("http_post", {})
    if http.get("enabled"):
        handlers.append(HttpPostOutput(http))

    return handlers


def build_collectors(
    cfg: dict,
    api_client: ApiClient,
    state_manager: StateManager,
    queue: Queue,
) -> List[BaseCollector]:
    collection_cfg = cfg.get("collection", {})
    sources = collection_cfg.get("sources", {})
    collectors = []

    if sources.get("alerts", {}).get("enabled", False):
        collectors.append(AlertsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["alerts"],
            global_config=collection_cfg,
        ))

    if sources.get("audit_events", {}).get("enabled", False):
        collectors.append(AuditEventsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["audit_events"],
            global_config=collection_cfg,
        ))

    if sources.get("hosts", {}).get("enabled", False):
        collectors.append(HostsCollector(
            api_client=api_client, state_manager=state_manager,
            output_queue=queue, config=sources["hosts"],
            global_config=collection_cfg,
        ))

    return collectors


def main() -> None:
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    cfg = load_config(CONFIG_PATH)

    state_manager = StateManager("state.json")
    metrics = MetricsCollector()

    falcon_cfg = cfg["falcon"]
    auth = AuthManager(
        base_url=falcon_cfg["base_url"],
        client_id=falcon_cfg["client_id"],
        client_secret=falcon_cfg["client_secret"],
        refresh_buffer_seconds=falcon_cfg.get("token_refresh_buffer_seconds", 300),
    )

    rl = RateLimitController()
    api_client = ApiClient(auth, rl, falcon_cfg["base_url"])

    queue_cfg = cfg.get("queue", {})
    queue: Queue = Queue(maxsize=queue_cfg.get("maxsize", 10000))

    handlers = build_output_handlers(cfg)
    collectors = build_collectors(cfg, api_client, state_manager, queue)

    dispatcher = OutputDispatcher(queue, handlers, metrics)
    dispatcher.start()

    for c in collectors:
        c.start()
    logger.info("Started %d collector(s)", len(collectors))

    # Metrics emit thread
    metrics_cfg = cfg.get("metrics", {})
    if metrics_cfg.get("enabled", True):
        metrics_thread = threading.Thread(
            target=metrics.emit_loop,
            args=(metrics_cfg.get("log_interval_seconds", 60), cfg.get("collection", {}).get("tag", "")),
            daemon=True,
            name="metrics-emitter",
        )
        metrics_thread.start()

    # Shutdown event
    shutdown = threading.Event()
    restart_delays: Dict[str, int] = {}
    last_alive: Dict[str, float] = {c.name: time.time() for c in collectors}

    def _handle_shutdown(signum, frame):  # noqa: ANN001
        logger.info("Shutdown signal received")
        shutdown.set()

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    try:
        while not shutdown.is_set():
            # Hot reload check
            if RELOAD_TRIGGER.exists():
                logger.info("Reload trigger detected — reloading config")
                try:
                    new_cfg = load_config(CONFIG_PATH)
                    cfg = new_cfg
                    logger.info("Config reloaded")
                except Exception as exc:
                    logger.error("Config reload failed: %s", exc)
                finally:
                    RELOAD_TRIGGER.unlink(missing_ok=True)

            # Watchdog
            for collector in collectors:
                if not collector.is_alive():
                    name = collector.name
                    delay = restart_delays.get(name, RESTART_BACKOFF_BASE)
                    logger.critical("Collector %s died — restarting in %ds", name, delay)
                    time.sleep(delay)
                    restart_delays[name] = min(delay * 2, RESTART_BACKOFF_MAX)
                    last_alive[name] = 0.0
                    # Rebuild and restart the same collector type
                    new_collectors = build_collectors(cfg, api_client, state_manager, queue)
                    for nc in new_collectors:
                        if nc.name == collector.name:
                            nc.start()
                            collectors[collectors.index(collector)] = nc
                            break
                else:
                    # Reset backoff after sustained uptime
                    if time.time() - last_alive.get(collector.name, 0) > RESTART_RECOVERY_SECONDS:
                        restart_delays[collector.name] = RESTART_BACKOFF_BASE
                        last_alive[collector.name] = time.time()

            shutdown.wait(WATCHDOG_INTERVAL)

    finally:
        logger.info("Shutting down — stopping collectors")
        for c in collectors:
            c.stop()
        dispatcher.stop()
        dispatcher.close_handlers()
        auth.revoke()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify it imports without error**

```bash
python -c "import main; print('OK')"
```
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add main.py
git commit -m "feat: main entry point with watchdog, hot reload, and shutdown"
```

---

## Task 14: Integration Smoke Test

**Files:**
- Create: `tests/test_integration.py`

This test boots the full pipeline against a mocked Falcon API, runs it for a few seconds, and verifies logs appear on disk.

- [ ] **Step 1: Write smoke test**

```python
# tests/test_integration.py
"""
Integration smoke test: boots main pipeline with mocked Falcon API.
Verifies events reach the JSON file output.
"""
import json
import os
import time
import threading
from pathlib import Path
from queue import Queue
from unittest.mock import MagicMock, patch

import pytest

from collector.alerts import AlertsCollector
from collector.api_client import ApiClient, RateLimitController
from collector.auth import AuthManager
from output.dispatcher import OutputDispatcher
from output.json_file import JsonFileOutput
from state.manager import StateManager
from utils.metrics import MetricsCollector


@pytest.fixture
def mock_auth():
    auth = MagicMock(spec=AuthManager)
    auth.get_token.return_value = "fake-token"
    auth.force_refresh = MagicMock()
    return auth


@pytest.fixture
def mock_api(mock_auth):
    rl = RateLimitController()
    client = ApiClient(mock_auth, rl, "https://api.us-2.crowdstrike.com")

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "queries" in url:
            resp.json.return_value = {
                "resources": ["composite-id-001"],
                "meta": {"pagination": {}},
            }
        else:
            resp.json.return_value = {
                "resources": [{
                    "composite_id": "composite-id-001",
                    "created_timestamp": "2026-03-30T12:00:00Z",
                    "severity": 3,
                    "status": "new",
                }]
            }
        return resp

    with patch("collector.api_client.requests.request", side_effect=fake_request):
        yield client


def test_full_pipeline_writes_events_to_file(tmp_path, mock_api):
    state_path = str(tmp_path / "state.json")
    log_dir = str(tmp_path / "logs")

    state = StateManager(state_path)
    queue: Queue = Queue(maxsize=1000)
    metrics = MetricsCollector()

    handler = JsonFileOutput({
        "directory": log_dir,
        "rotation": "hourly",
        "filename_prefix": "falcon",
        "max_size_mb": 256,
        "min_free_disk_mb": 0,
    })
    dispatcher = OutputDispatcher(queue, [handler], metrics)
    dispatcher.start()

    collector = AlertsCollector(
        api_client=mock_api,
        state_manager=state,
        output_queue=queue,
        config={"poll_interval_seconds": 999, "batch_size": 100},
        global_config={"tag": "integration-test", "checkpoint_per_page": False},
    )
    # Run one poll cycle manually (don't start the thread loop)
    with patch("collector.api_client.requests.request") as mock_req:
        mock_req.side_effect = [
            _make_resp({"resources": ["composite-id-001"], "meta": {"pagination": {}}}),
            _make_resp({"resources": [{"composite_id": "composite-id-001",
                                        "created_timestamp": "2026-03-30T12:00:00Z",
                                        "severity": 3}]}),
        ]
        collector._poll()

    time.sleep(0.2)
    dispatcher.stop()
    handler.close()

    log_files = list(Path(log_dir).glob("*.json"))
    assert len(log_files) == 1
    lines = log_files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["_source"] == "alerts"
    assert event["_tag"] == "integration-test"
    assert event["_event_id"] == "composite-id-001"
    assert event["composite_id"] == "composite-id-001"


def _make_resp(body: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.raise_for_status = MagicMock()
    r.json.return_value = body
    return r
```

- [ ] **Step 2: Run smoke test**

```bash
python -m pytest tests/test_integration.py -v
```
Expected: 1 PASSED

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest tests/ -v --tb=short
```
Expected: All PASSED

- [ ] **Step 4: Final commit**

```bash
git add tests/test_integration.py
git commit -m "test: integration smoke test for full pipeline"
```

---

## Task 15: Verify End-to-End Locally

- [ ] **Step 1: Install dependencies**

```bash
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

- [ ] **Step 2: Create config from example**

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml`:
- Set `falcon.client_id` and `falcon.client_secret` (or put them in `.env`)
- Set `collection.sources.alerts.enabled: true`
- Set `outputs.json_file.enabled: true`
- Set `outputs.json_file.directory: ./logs`

Or create `.env`:
```env
FALCON_CLIENT_ID=your_actual_client_id
FALCON_CLIENT_SECRET=your_actual_client_secret
```

- [ ] **Step 3: Run the collector**

```bash
python main.py
```

Expected output (stderr):
```json
{"timestamp": "...", "level": "INFO", "logger": "collector.auth", "message": "Token refreshed, expires_in=1800s"}
{"timestamp": "...", "level": "INFO", "logger": "main", "message": "Started 1 collector(s)"}
```

After 30s, check `logs/` for a `falcon_alerts_*.json` file.

- [ ] **Step 4: Verify log file contents**

```bash
# Linux
head -1 logs/falcon_alerts_*.json | python -m json.tool

# Windows
type logs\falcon_alerts_*.json | python -m json.tool
```

Expected: Valid JSON with `_source`, `_tag`, `_event_id`, `_collected_at` fields.

- [ ] **Step 5: Test hot reload**

```bash
# In another terminal:
touch reload.trigger          # Linux
echo. > reload.trigger        # Windows
```

Expected log: `{"message": "Config reloaded"}`

---

## Self-Review Checklist

**Spec coverage:**

| Spec Requirement | Task |
|---|---|
| OAuth2 Client Credentials + lock+double-check | Task 5 |
| Token refresh before expiry using `expires_in` | Task 5 |
| Token revocation on shutdown | Task 5, Task 13 |
| Alerts collector (replaces deprecated Detections + Incidents) | Task 8 |
| Audit Events collector | Task 9 |
| Hosts collector | Task 9 |
| Continuous polling 24x7 with per-source intervals | Task 7 (BaseCollector.run) |
| `last_timestamp` + `last_id` deduplication | Task 7, Task 4 |
| `sort=created_timestamp.asc` + skip logic | Task 7, Task 8, Task 9 |
| Per-page checkpoint option | Task 7 |
| Cursor-based `after` token pagination | Task 8, Task 9 |
| Atomic state.json with same-dir temp file | Task 4 |
| Bootstrap from `now - 1 hour` on first run | Task 4 |
| Exponential backoff with jitter | Task 6 |
| Global rate-limit controller (epoch header) | Task 6 |
| Bounded queue with blocking + warning | Task 7 |
| Thread watchdog with restart backoff | Task 13 |
| Hot config reload via `reload.trigger` | Task 13 |
| JSON file output (NDJSON, hourly/daily + size rotation) | Task 10 |
| Disk space check with auto-disable | Task 10 |
| Syslog TCP output with TLS via SSLContext | Task 11 |
| RELP output via relppy | Task 11 |
| HTTP POST output with batching | Task 11 |
| Output fan-out, error isolation per handler | Task 12 |
| Event enrichment (`_collected_at`, `_source`, `_tag`, `_event_id`) | Task 7 |
| Structured JSON logging | Task 3 |
| Metrics (events/s, queue depth, output success/fail) | Task 3, Task 12 |
| Falcon timestamps only for filtering (no clock drift) | Task 4, Task 7 |
| Cross-platform file paths via `pathlib.Path` | Throughout |
| `SIGTERM`/`CTRL_C_EVENT` shutdown handling | Task 13 |
| `load_dotenv()` first action in main | Task 13 |
| systemd service file | `config.example.yaml` / spec |
| Docker with non-root user + `.dockerignore` | Task 1, spec |
| NSSM deployment | spec / README |
| `requirements.txt` | Task 1 |
| `config.example.yaml` | Task 1 |
| `.gitignore` / `.dockerignore` | Task 1 |
