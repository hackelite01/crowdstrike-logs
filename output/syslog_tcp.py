import json
import logging
import socket
import ssl
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from output.base import OutputHandler

logger = logging.getLogger("output.syslog_tcp")


class SyslogTcpOutput(OutputHandler):
    name = "syslog_tcp"

    def __init__(self, config: Dict[str, Any]) -> None:
        self._host = config["host"]
        self._port = config["port"]
        self._facility = config.get("facility", 16)
        self._app_name = config.get("app_name", "falcon-collector")
        self._tls_cfg = config.get("tls", {})
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self.enabled = True

    def _connect(self) -> None:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)
        try:
            if self._tls_cfg.get("enabled"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ca = self._tls_cfg.get("ca_cert")
                if ca:
                    ctx.load_verify_locations(ca)
                ctx.verify_mode = (
                    ssl.CERT_REQUIRED if self._tls_cfg.get("verify", True) else ssl.CERT_NONE
                )
                self._sock = ctx.wrap_socket(raw, server_hostname=self._host)
            else:
                self._sock = raw
            self._sock.connect((self._host, self._port))
        except Exception:
            raw.close()
            raise
        logger.info("Syslog TCP connected to %s:%d", self._host, self._port)

    def _format_rfc5424(self, event: Dict[str, Any]) -> bytes:
        priority = self._facility * 8 + 6  # severity=6 (informational)
        ts = event.get("_collected_at", datetime.now(timezone.utc).isoformat())
        msg = json.dumps(event)
        frame = f"<{priority}>1 {ts} - {self._app_name} - - - {msg}\n"
        return frame.encode("utf-8")

    def write(self, event: Dict[str, Any]) -> None:
        with self._lock:
            data = self._format_rfc5424(event)
            for attempt in range(2):
                try:
                    if self._sock is None:
                        self._connect()
                    self._sock.sendall(data)  # type: ignore[union-attr]
                    return
                except (BrokenPipeError, OSError, ssl.SSLError) as exc:
                    logger.warning("Syslog TCP error (attempt %d): %s — reconnecting", attempt + 1, exc)
                    self._sock = None
            logger.error("Syslog TCP: failed to send after reconnect")

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
