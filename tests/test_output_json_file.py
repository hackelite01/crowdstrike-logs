import json
import shutil
import time
from pathlib import Path
import pytest
from output.json_file import JsonFileOutput


def test_writes_ndjson_line(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"_source": "alerts", "id": "1"})
    out.close()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["id"] == "1"


def test_multiple_writes_each_on_own_line(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"id": "1"})
    out.write({"id": "2"})
    out.close()
    files = list(tmp_path.glob("*.json"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 2


def test_filename_contains_prefix_and_source(tmp_path):
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 0})
    out.write({"_source": "alerts", "id": "1"})
    out.close()
    files = list(tmp_path.glob("falcon_alerts_*.json"))
    assert len(files) == 1


def test_disables_when_disk_full(tmp_path, monkeypatch):
    # Simulate disk full by patching disk_usage to return tiny free space
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "disk_usage", lambda p: type("u", (), {"free": 1024 * 1024})())
    out = JsonFileOutput({"directory": str(tmp_path), "rotation": "hourly",
                          "filename_prefix": "falcon", "max_size_mb": 256,
                          "min_free_disk_mb": 500})
    out.write({"id": "1"})  # should not raise, just skip
    out.close()
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 0
