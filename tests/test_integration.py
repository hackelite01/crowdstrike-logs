# tests/test_integration.py
"""
Integration smoke test: boots main pipeline with mocked Falcon API.
Verifies events reach the JSON file output.
"""
import json
import os
import time
import threading
from pathlib import Path
from queue import Queue
from unittest.mock import MagicMock, patch

import pytest

from collector.alerts import AlertsCollector
from collector.api_client import ApiClient, RateLimitController
from collector.auth import AuthManager
from output.dispatcher import OutputDispatcher
from output.json_file import JsonFileOutput
from state.manager import StateManager
from utils.metrics import MetricsCollector


@pytest.fixture
def mock_auth():
    auth = MagicMock(spec=AuthManager)
    auth.get_token.return_value = "fake-token"
    auth.force_refresh = MagicMock()
    return auth


@pytest.fixture
def mock_api(mock_auth):
    rl = RateLimitController()
    client = ApiClient(mock_auth, rl, "https://api.us-2.crowdstrike.com")

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if "queries" in url:
            resp.json.return_value = {
                "resources": ["composite-id-001"],
                "meta": {"pagination": {}},
            }
        else:
            resp.json.return_value = {
                "resources": [{
                    "composite_id": "composite-id-001",
                    "created_timestamp": "2026-03-30T12:00:00Z",
                    "severity": 3,
                    "status": "new",
                }]
            }
        return resp

    with patch("collector.api_client.requests.request", side_effect=fake_request):
        yield client


def test_full_pipeline_writes_events_to_file(tmp_path, mock_api):
    state_path = str(tmp_path / "state.json")
    log_dir = str(tmp_path / "logs")

    state = StateManager(state_path)
    queue: Queue = Queue(maxsize=1000)
    metrics = MetricsCollector()

    handler = JsonFileOutput({
        "directory": log_dir,
        "rotation": "hourly",
        "filename_prefix": "falcon",
        "max_size_mb": 256,
        "min_free_disk_mb": 0,
    })
    dispatcher = OutputDispatcher(queue, [handler], metrics)
    dispatcher.start()

    collector = AlertsCollector(
        api_client=mock_api,
        state_manager=state,
        output_queue=queue,
        config={"poll_interval_seconds": 999, "batch_size": 100},
        global_config={"tag": "integration-test", "checkpoint_per_page": False},
    )
    # Run one poll cycle manually (don't start the thread loop)
    with patch("collector.api_client.requests.request") as mock_req:
        mock_req.side_effect = [
            _make_resp({"resources": ["composite-id-001"], "meta": {"pagination": {}}}),
            _make_resp({"resources": [{"composite_id": "composite-id-001",
                                        "created_timestamp": "2026-03-30T12:00:00Z",
                                        "severity": 3}]}),
        ]
        collector._poll()

    time.sleep(0.2)
    dispatcher.stop()
    handler.close()

    log_files = list(Path(log_dir).glob("*.json"))
    assert len(log_files) == 1
    lines = log_files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["_source"] == "alerts"
    assert event["_tag"] == "integration-test"
    assert event["_event_id"] == "composite-id-001"
    assert event["composite_id"] == "composite-id-001"


def _make_resp(body: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.raise_for_status = MagicMock()
    r.json.return_value = body
    return r
