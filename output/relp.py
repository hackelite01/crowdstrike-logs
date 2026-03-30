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
