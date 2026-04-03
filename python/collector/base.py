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
            self.logger.info("Polling %s", self._source)
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
