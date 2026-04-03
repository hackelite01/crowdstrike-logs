from queue import Queue
from unittest.mock import MagicMock
from collector.audit_events import AuditEventsCollector


def _make_collector():
    api = MagicMock()
    # query returns IDs with offset-based pagination meta
    api.get.side_effect = [
        {"resources": ["ae-1"], "meta": {"pagination": {"total": 1, "offset": 0, "limit": 200}}},
        {"resources": [{"id": "ae-1", "timestamp": "2026-01-01T00:01:00Z", "action": "token_create", "actor": "user@example.com"}]},
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


def test_audit_events_uses_offset_pagination():
    api = MagicMock()
    # page 1: 2 results, total=3
    api.get.side_effect = [
        {"resources": ["ae-1", "ae-2"], "meta": {"pagination": {"total": 3, "offset": 0, "limit": 2}}},
        {"resources": [
            {"id": "ae-1", "timestamp": "2026-01-01T00:01:00Z", "action": "token_create"},
            {"id": "ae-2", "timestamp": "2026-01-01T00:02:00Z", "action": "token_delete"},
        ]},
        # page 2: 1 result, offset=2, total=3
        {"resources": ["ae-3"], "meta": {"pagination": {"total": 3, "offset": 2, "limit": 2}}},
        {"resources": [
            {"id": "ae-3", "timestamp": "2026-01-01T00:03:00Z", "action": "token_create"},
        ]},
    ]
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": ""}
    queue = Queue()
    collector = AuditEventsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 2}, global_config={"tag": "t"},
    )
    collector._poll()
    assert queue.qsize() == 3


def test_audit_events_skips_already_seen():
    api = MagicMock()
    api.get.side_effect = [
        {"resources": ["ae-1"], "meta": {"pagination": {"total": 1, "offset": 0, "limit": 200}}},
        {"resources": [{"id": "ae-1", "timestamp": "2026-01-01T00:00:00Z", "action": "token_create"}]},
    ]
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": "ae-1"}
    queue = Queue()
    collector = AuditEventsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 200}, global_config={"tag": "t"},
    )
    collector._poll()
    assert queue.qsize() == 0
