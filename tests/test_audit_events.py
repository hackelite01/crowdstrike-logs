from queue import Queue
from unittest.mock import MagicMock
from collector.audit_events import AuditEventsCollector


def _make_collector():
    api = MagicMock()
    api.get.side_effect = [
        {"resources": ["ae-1"], "meta": {"pagination": {}}},
        {"resources": [{"id": "ae-1", "created_timestamp": "2026-01-01T00:01:00Z", "action": "login"}]},
    ]
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": ""}
    queue = Queue()
    return AuditEventsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 200}, global_config={"tag": "t"},
    ), queue


def test_audit_events_poll_enqueues_event():
    collector, queue = _make_collector()
    collector._poll()
    assert queue.qsize() == 1


def test_audit_events_enrichment():
    collector, queue = _make_collector()
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "audit_events"
    assert event["_event_id"] == "ae-1"
