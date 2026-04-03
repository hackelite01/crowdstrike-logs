import logging
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger("collector.auth")


class AuthManager:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        refresh_buffer_seconds: int = 300,
    ) -> None:
        self._base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_buffer = refresh_buffer_seconds
        self._token: Optional[str] = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def get_token(self) -> str:
        if self._is_expiring():
            with self._lock:
                if self._is_expiring():
                    self._do_refresh()
        return self._token  # type: ignore[return-value]

    def _is_expiring(self) -> bool:
        return time.time() >= (self._expires_at - self._refresh_buffer)

    def _do_refresh(self) -> None:
        logger.info("Refreshing OAuth2 token")
        resp = requests.post(
            f"{self._base_url}/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._expires_at = time.time() + data["expires_in"]
        logger.info("Token refreshed, expires_in=%ds", data["expires_in"])

    def force_refresh(self) -> None:
        """Called on 401 mid-poll — refreshes under lock."""
        with self._lock:
            self._do_refresh()

    def revoke(self) -> None:
        if not self._token:
            return
        try:
            requests.post(
                f"{self._base_url}/oauth2/revoke",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "token": self._token,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                timeout=10,
            )
            logger.info("OAuth2 token revoked")
        except Exception as exc:
            logger.warning("Token revocation failed (ignored): %s", exc)
