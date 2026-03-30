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
