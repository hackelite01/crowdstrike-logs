import json
import os
from pathlib import Path
import pytest
from state.manager import StateManager


def test_load_returns_empty_when_file_missing(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    assert sm.load() == {}


def test_save_and_load_roundtrip(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.save({"alerts": {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": "abc"}})
    data = sm.load()
    assert data["alerts"]["last_id"] == "abc"


def test_update_source_creates_entry(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.update_source("alerts", "2026-01-01T00:00:00Z", "id-001")
    data = sm.load()
    assert data["alerts"] == {"last_timestamp": "2026-01-01T00:00:00Z", "last_id": "id-001"}


def test_update_source_preserves_other_sources(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.update_source("alerts", "2026-01-01T00:00:00Z", "a1")
    sm.update_source("hosts", "2026-01-02T00:00:00Z", "h1")
    data = sm.load()
    assert "alerts" in data
    assert "hosts" in data


def test_atomic_write_uses_same_dir(tmp_path):
    sm = StateManager(str(tmp_path / "state.json"))
    sm.save({"test": "value"})
    # tmp file should be gone after save
    assert not (tmp_path / "state.json.tmp").exists()
    assert (tmp_path / "state.json").exists()


def test_get_source_state_defaults(tmp_path):
    from datetime import datetime, timezone, timedelta
    sm = StateManager(str(tmp_path / "state.json"))
    state = sm.get_source_state("alerts")
    # default last_timestamp is ~1 hour ago
    ts = datetime.fromisoformat(state["last_timestamp"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    assert abs((now - ts).total_seconds() - 3600) < 5
    assert state["last_id"] == ""
