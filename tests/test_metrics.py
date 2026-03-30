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
