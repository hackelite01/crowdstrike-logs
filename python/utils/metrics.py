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
            # Get all sources from both counters and latencies
            all_sources = set(self._counters.keys()) | set(self._latencies.keys())
            for source in all_sources:
                result[source] = dict(self._counters.get(source, {}))
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
