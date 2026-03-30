import json
import socket
from unittest.mock import MagicMock, patch
from output.syslog_tcp import SyslogTcpOutput


def _make_output(tls_enabled=False):
    config = {
        "host": "127.0.0.1", "port": 514, "facility": 16,
        "app_name": "falcon-collector",
        "tls": {"enabled": tls_enabled, "ca_cert": "", "verify": True},
    }
    return SyslogTcpOutput(config)


def test_write_sends_bytes_over_socket():
    out = _make_output()
    mock_sock = MagicMock()
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._connect()
        out.write({"_source": "alerts", "id": "1", "_collected_at": "2026-01-01T00:00:00Z"})
    mock_sock.sendall.assert_called_once()
    sent = mock_sock.sendall.call_args[0][0]
    assert isinstance(sent, bytes)


def test_write_formats_rfc5424():
    out = _make_output()
    mock_sock = MagicMock()
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._connect()
        out.write({"_source": "alerts", "id": "test-evt", "_collected_at": "2026-01-01T00:00:00Z"})
    sent = mock_sock.sendall.call_args[0][0].decode()
    assert "<" in sent  # priority
    assert "falcon-collector" in sent


def test_reconnects_on_broken_pipe():
    out = _make_output()
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = [BrokenPipeError, None]
    with patch("output.syslog_tcp.socket.socket", return_value=mock_sock):
        out._sock = mock_sock
        out.write({"_source": "alerts", "id": "1", "_collected_at": "2026-01-01T00:00:00Z"})
    assert mock_sock.sendall.call_count == 2
