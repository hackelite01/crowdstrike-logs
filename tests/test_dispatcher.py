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
