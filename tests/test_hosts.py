from queue import Queue
from unittest.mock import MagicMock
from collector.hosts import HostsCollector


def _make_collector():
    api = MagicMock()
    api.get.side_effect = [
        {"resources": ["dev-1"], "meta": {"pagination": {}}},
    ]
    api.post.return_value = {
        "resources": [{"device_id": "dev-1", "modified_timestamp": "2026-01-01T00:01:00Z", "hostname": "test-host"}]
    }
    state = MagicMock()
    state.get_source_state.return_value = {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": ""}
    queue = Queue()
    return HostsCollector(
        api_client=api, state_manager=state, output_queue=queue,
        config={"batch_size": 500}, global_config={"tag": "t"},
    ), queue


def test_hosts_poll_enqueues_event():
    collector, queue = _make_collector()
    collector._poll()
    assert queue.qsize() == 1


def test_hosts_enrichment():
    collector, queue = _make_collector()
    collector._poll()
    event = queue.get_nowait()
    assert event["_source"] == "hosts"
    assert event["_event_id"] == "dev-1"
