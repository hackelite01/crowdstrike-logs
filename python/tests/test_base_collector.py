import threading
import time
from queue import Queue
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from collector.base import BaseCollector, enrich_event, should_skip_event


def test_enrich_event_adds_required_fields():
    event = {"id": "evt-1", "data": "value"}
    enriched = enrich_event(event, source="alerts", tag="my-tenant", event_id_field="id")
    assert enriched["_source"] == "alerts"
    assert enriched["_tag"] == "my-tenant"
    assert enriched["_event_id"] == "evt-1"
    assert enriched["_collector_version"] == "1.0.0"
    assert "_collected_at" in enriched
    # original fields preserved
    assert enriched["data"] == "value"


def test_enrich_event_collected_at_is_utc_iso():
    event = {}
    enriched = enrich_event(event, source="alerts", tag="t", event_id_field="id")
    ts = enriched["_collected_at"]
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def test_should_skip_event_same_ts_and_lower_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="aaa",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is True


def test_should_skip_event_same_ts_same_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="bbb",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is True


def test_should_not_skip_event_newer_ts():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:01Z",
        event_id="aaa",
        last_ts="2026-01-01T00:00:00Z",
        last_id="zzz",
    ) is False


def test_should_not_skip_event_same_ts_higher_id():
    from collector.base import should_skip_event
    assert should_skip_event(
        event_ts="2026-01-01T00:00:00Z",
        event_id="ccc",
        last_ts="2026-01-01T00:00:00Z",
        last_id="bbb",
    ) is False
