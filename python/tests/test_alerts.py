from queue import Queue
from unittest.mock import MagicMock, patch
from collector.alerts import AlertsCollector


def _make_collector(api_responses):
    api = MagicMock()
    api.get.side_effect = api_responses
    api.post.side_effect = lambda path, json=None: {
        "resources": [
            {"id": cid, "composite_id": f"{cid}:xyz", "created_timestamp": "2026-01-01T00:01:00Z", "severity": 3}
            for cid in (json or {}).get("composite_ids", [])
        ]
    }
    state = MagicMock()
    state.get_source_state.return_value = {
        "last_timestamp": "2026-01-01T00:00:00Z",
        "last_id": "",
    }
    queue = Queue()
    source_config = {"poll_interval_seconds": 30, "batch_size": 100}
    global_config = {"tag": "test-tenant", "checkpoint_per_page": False}
    return AlertsCollector(
        api_client=api,
        state_manager=state,
        output_queue=queue,
        config=source_config,
        global_config=global_config,
    ), queue


def test_poll_enqueues_events():
    query_resp = {"resources": ["id-1", "id-2"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([query_resp])
    collector._poll()
    assert queue.qsize() == 2


def test_poll_skips_already_seen_event():
    # Event has same ts and id <= last_id — should be skipped
    query_resp = {"resources": ["id-0"], "meta": {"pagination": {}}}
    api = MagicMock()
    api.get.return_value = query_resp
    api.post.return_value = {
        "resources": [
            {"id": "id-0", "composite_id": "id-0:xyz", "created_timestamp": "2026-01-01T00:00:00Z"}
        ]
    }
    state = MagicMock()
    state.get_source_state.return_value = {
        "last_timestamp": "2026-01-01T00:00:00Z",
        "last_id": "id-0",
    }
    queue = Queue()
    collector = AlertsCollector(
        api_client=api,
        state_manager=state,
        output_queue=queue,
        config={"batch_size": 100},
        global_config={"tag": "t"},
    )
    collector._poll()
    assert queue.qsize() == 0


def test_poll_enriches_events():
    query_resp = {"resources": ["id-1"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([query_resp])
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "alerts"
    assert event["_tag"] == "test-tenant"
    assert event["_event_id"] == "id-1"
    assert "_collected_at" in event


def test_poll_paginates_with_after_cursor():
    page1 = {"resources": ["id-1"], "meta": {"pagination": {"after": "cursor-abc"}}}
    page2 = {"resources": ["id-2"], "meta": {"pagination": {}}}
    collector, queue = _make_collector([page1, page2])
    collector._poll()
    assert queue.qsize() == 2
