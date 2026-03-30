import os
import re
import yaml
from typing import Any


class ConfigError(Exception):
    pass


def _substitute_env_vars(value: str) -> str:
    pattern = r'\$\{([^}]+)\}'

    def replacer(match: re.Match) -> str:
        var_name = match.group(1)
        val = os.environ.get(var_name)
        if val is None:
            raise ConfigError(f"Environment variable '{var_name}' is not set")
        return val

    return re.sub(pattern, replacer, value)


def _resolve(obj: Any) -> Any:
    if isinstance(obj, str):
        return _substitute_env_vars(obj)
    if isinstance(obj, dict):
        return {k: _resolve(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(item) for item in obj]
    return obj


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return _resolve(raw or {})
