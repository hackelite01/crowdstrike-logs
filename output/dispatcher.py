import logging
import threading
from queue import Empty, Queue
from typing import List

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

            self._queue.task_done()

    def close_handlers(self) -> None:
        for handler in self._handlers:
            try:
                handler.close()
            except Exception as exc:
                logger.warning("Handler %s close error: %s", handler.name, exc)
