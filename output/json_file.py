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
        self._client_name = config.get("client_name", "client")
        self._min_free_bytes = config.get("min_free_disk_mb", 500) * 1024 * 1024
        self._lock = threading.Lock()
        self._handle: Optional[IO[str]] = None
        self._current_date: Optional[str] = None
        self._active_path = self._dir / f"falcon_alerts_{self._client_name}.json"
        self._dir.mkdir(parents=True, exist_ok=True)
        self.enabled = True

    def _today_utc(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _rotate_if_needed(self) -> None:
        today = self._today_utc()
        if self._current_date is None:
            self._current_date = today

        if today != self._current_date:
            if self._handle:
                self._handle.close()
                self._handle = None
            if self._active_path.exists():
                dated = self._dir / f"falcon_alerts_{self._client_name}_{self._current_date}.json"
                self._active_path.rename(dated)
                logger.info("Rotated active log to %s", dated.name)
            self._current_date = today

        if self._handle is None:
            self._handle = open(self._active_path, "a", encoding="utf-8")

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
        with self._lock:
            if not self._check_disk():
                return
            try:
                self._rotate_if_needed()
                self._handle.write(json.dumps(event) + "\n")
                self._handle.flush()
            except OSError as exc:
                logger.error("File write error: %s", exc)

    def close(self) -> None:
        with self._lock:
            if self._handle:
                try:
                    self._handle.close()
                except OSError:
                    pass
                self._handle = None
