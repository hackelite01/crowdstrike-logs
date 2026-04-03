import json
import shutil
from pathlib import Path
from unittest.mock import patch
from datetime import timezone, datetime
import pytest
from output.json_file import JsonFileOutput


def _make_out(tmp_path, client_name="FCT", min_free_disk_mb=0):
    return JsonFileOutput({
        "directory": str(tmp_path),
        "client_name": client_name,
        "min_free_disk_mb": min_free_disk_mb,
    })


def test_writes_ndjson_line(tmp_path):
    out = _make_out(tmp_path)
    out.write({"id": "1"})
    out.close()
    active = tmp_path / "falcon_alerts_FCT.json"
    assert active.exists()
    data = json.loads(active.read_text().strip())
    assert data["id"] == "1"


def test_multiple_writes_same_file(tmp_path):
    out = _make_out(tmp_path)
    out.write({"id": "1"})
    out.write({"id": "2"})
    out.close()
    lines = (tmp_path / "falcon_alerts_FCT.json").read_text().strip().splitlines()
    assert len(lines) == 2


def test_active_filename_uses_client_name(tmp_path):
    out = _make_out(tmp_path, client_name="Acme")
    out.write({"id": "1"})
    out.close()
    assert (tmp_path / "falcon_alerts_Acme.json").exists()


def test_date_rotation(tmp_path):
    out = _make_out(tmp_path)

    # Write on day 1
    with patch("output.json_file.JsonFileOutput._today_utc", return_value="2026-03-31"):
        out.write({"id": "1"})

    # Write on day 2 — triggers rotation
    with patch("output.json_file.JsonFileOutput._today_utc", return_value="2026-04-01"):
        out.write({"id": "2"})

    out.close()

    # Day 1 data should be in the dated archive
    dated = tmp_path / "falcon_alerts_FCT_2026-03-31.json"
    assert dated.exists()
    assert json.loads(dated.read_text().strip())["id"] == "1"

    # Day 2 data in the active file
    active = tmp_path / "falcon_alerts_FCT.json"
    assert active.exists()
    assert json.loads(active.read_text().strip())["id"] == "2"


def test_disables_when_disk_full(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "disk_usage", lambda p: type("u", (), {"free": 1024 * 1024})())
    out = _make_out(tmp_path, min_free_disk_mb=500)
    out.write({"id": "1"})
    out.close()
    assert not (tmp_path / "falcon_alerts_FCT.json").exists()
