import json
import logging
import shutil
import threading
import time
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

    def _get_handle(self, source: str, window: str) -> IO[str]:
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
        source = event.get("_source", "unknown")
        window = self._window_key(source)
        with self._lock:
            if not self._check_disk():
                return
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
