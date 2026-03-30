import logging
import random
import threading
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("collector.api_client")

_MAX_RETRIES = 5
_BASE_BACKOFF = 2


class RateLimitController:
    """Single shared gate for all collector threads — Falcon rate limits per API key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._retry_after: float = 0.0

    def set_retry_after(self, epoch: float) -> None:
        with self._lock:
            if epoch > self._retry_after:
                self._retry_after = epoch

    def wait_if_limited(self) -> None:
        deadline = self._retry_after
        now = time.time()
        if now < deadline:
            wait = deadline - now + 0.5
            logger.warning("Rate limited (global) — sleeping %.1fs", wait)
            time.sleep(wait)


class ApiClient:
    def __init__(
        self,
        auth_manager: Any,
        rate_limit_controller: RateLimitController,
        base_url: str,
    ) -> None:
        self._auth = auth_manager
        self._rl = rate_limit_controller
        self._base_url = base_url.rstrip("/")

    def get(self, path: str, params: Optional[Dict] = None) -> dict:
        return self._request("GET", path, params=params)

    def post(self, path: str, json: Optional[Dict] = None) -> dict:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        url = f"{self._base_url}{path}"
        for attempt in range(_MAX_RETRIES):
            self._rl.wait_if_limited()
            headers = {"Authorization": f"Bearer {self._auth.get_token()}"}
            try:
                resp = requests.request(
                    method, url, headers=headers, timeout=30, **kwargs
                )
            except requests.exceptions.RequestException as exc:
                if attempt == _MAX_RETRIES - 1:
                    raise
                logger.warning("Network error (attempt %d): %s", attempt + 1, exc)
                self._backoff(attempt)
                continue

            if resp.status_code == 401:
                logger.warning("401 Unauthorized — refreshing token and retrying")
                self._auth.force_refresh()
                headers["Authorization"] = f"Bearer {self._auth.get_token()}"
                resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

            if resp.status_code == 429:
                retry_after = int(
                    resp.headers.get("X-RateLimit-RetryAfter", int(time.time()) + 60)
                )
                self._rl.set_retry_after(float(retry_after))
                self._rl.wait_if_limited()
                continue

            if resp.status_code in (500, 503):
                if attempt == _MAX_RETRIES - 1:
                    resp.raise_for_status()
                logger.warning("HTTP %d (attempt %d) — retrying", resp.status_code, attempt + 1)
                self._backoff(attempt)
                continue

            resp.raise_for_status()
            return resp.json()

        raise RuntimeError(f"Max retries ({_MAX_RETRIES}) exceeded for {method} {path}")

    def _backoff(self, attempt: int) -> None:
        sleep = _BASE_BACKOFF * (2 ** attempt) + random.random()
        logger.debug("Backoff %.1fs (attempt %d)", sleep, attempt + 1)
        time.sleep(sleep)
