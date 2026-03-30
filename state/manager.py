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
        self._cache: Dict[str, Any] = self._load_raw()

    def _load_raw(self) -> Dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def load(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._cache)

    def save(self, state: Dict[str, Any]) -> None:
        tmp = self._path.parent / (self._path.name + ".tmp")
        with self._lock:
            self._cache = dict(state)
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self._path)

    def update_source(self, source: str, last_timestamp: str, last_id: str) -> None:
        tmp = self._path.parent / (self._path.name + ".tmp")
        with self._lock:
            self._cache[source] = {"last_timestamp": last_timestamp, "last_id": last_id}
            with open(tmp, "w") as f:
                json.dump(self._cache, f, indent=2)
            os.replace(tmp, self._path)

    def get_source_state(self, source: str) -> Dict[str, str]:
        with self._lock:
            if source in self._cache:
                return dict(self._cache[source])
        default_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        return {"last_timestamp": default_ts, "last_id": ""}
