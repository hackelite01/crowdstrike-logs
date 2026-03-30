import time
import pytest
from unittest.mock import MagicMock, patch, call
from collector.api_client import ApiClient, RateLimitController


def _make_response(status: int, body: dict, headers: dict = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.headers = headers or {}
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    else:
        resp.raise_for_status = MagicMock()
    return resp


def _make_client(mock_post=None):
    auth = MagicMock()
    auth.get_token.return_value = "tok"
    rl = RateLimitController()
    client = ApiClient(auth, rl, "https://api.example.com")
    return client, auth, rl


def test_get_returns_response_body():
    client, _, _ = _make_client()
    ok_resp = _make_response(200, {"resources": ["id1"]})
    with patch("collector.api_client.requests.request", return_value=ok_resp):
        result = client.get("/detects/queries/detects/v1", params={"limit": 10})
    assert result == {"resources": ["id1"]}


def test_retries_on_500_then_succeeds():
    client, _, _ = _make_client()
    fail = _make_response(500, {})
    ok = _make_response(200, {"resources": []})
    with patch("collector.api_client.requests.request", side_effect=[fail, ok]):
        with patch("collector.api_client.time.sleep"):
            result = client.get("/some/path")
    assert result == {"resources": []}


def test_raises_after_max_retries():
    client, _, _ = _make_client()
    fail = _make_response(500, {})
    with patch("collector.api_client.requests.request", return_value=fail):
        with patch("collector.api_client.time.sleep"):
            with pytest.raises(Exception):
                client.get("/some/path")


def test_handles_429_with_retry_after_header():
    client, _, rl = _make_client()
    future_epoch = int(time.time()) + 5
    throttled = _make_response(429, {}, {"X-RateLimit-RetryAfter": str(future_epoch)})
    ok = _make_response(200, {"resources": []})
    with patch("collector.api_client.requests.request", side_effect=[throttled, ok]):
        with patch("collector.api_client.time.sleep") as mock_sleep:
            result = client.get("/some/path")
    assert result == {"resources": []}
    mock_sleep.assert_called()


def test_handles_401_refreshes_token_and_retries():
    client, auth, _ = _make_client()
    unauthorized = _make_response(401, {})
    unauthorized.raise_for_status = MagicMock()
    ok = _make_response(200, {"resources": ["x"]})
    with patch("collector.api_client.requests.request", side_effect=[unauthorized, ok]):
        result = client.get("/some/path")
    auth.force_refresh.assert_called_once()
    assert result == {"resources": ["x"]}


def test_rate_limit_controller_wait_if_limited():
    rl = RateLimitController()
    rl.set_retry_after(time.time() + 2)
    with patch("collector.api_client.time.sleep") as mock_sleep:
        rl.wait_if_limited()
    mock_sleep.assert_called_once()
    sleep_arg = mock_sleep.call_args[0][0]
    assert 1.5 < sleep_arg < 3.0
