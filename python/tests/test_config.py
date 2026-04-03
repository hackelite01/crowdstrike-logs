import os
import pytest
import yaml
from pathlib import Path
from utils.config import load_config, ConfigError


def write_yaml(tmp_path, content: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(content))
    return str(p)


def test_loads_plain_values(tmp_path):
    path = write_yaml(tmp_path, {"falcon": {"base_url": "https://example.com"}})
    cfg = load_config(path)
    assert cfg["falcon"]["base_url"] == "https://example.com"


def test_substitutes_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET", "hunter2")
    path = write_yaml(tmp_path, {"falcon": {"client_secret": "${MY_SECRET}"}})
    cfg = load_config(path)
    assert cfg["falcon"]["client_secret"] == "hunter2"


def test_raises_on_missing_env_var(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    path = write_yaml(tmp_path, {"key": "${MISSING_VAR}"})
    with pytest.raises(ConfigError, match="MISSING_VAR"):
        load_config(path)


def test_substitutes_nested_env_vars(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST", "10.0.0.1")
    path = write_yaml(tmp_path, {"outputs": {"syslog_tcp": {"host": "${HOST}"}}})
    cfg = load_config(path)
    assert cfg["outputs"]["syslog_tcp"]["host"] == "10.0.0.1"


def test_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")
