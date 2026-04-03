import time
import pytest
from unittest.mock import patch, MagicMock
from collector.auth import AuthManager


def _mock_token_response(expires_in: int = 1800) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 201
    resp.json.return_value = {"access_token": "tok-abc", "expires_in": expires_in}
    resp.raise_for_status = MagicMock()
    return resp


def test_get_token_fetches_on_first_call():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()) as mock_post:
        auth = AuthManager("https://api.example.com", "cid", "csec")
        token = auth.get_token()
    assert token == "tok-abc"
    mock_post.assert_called_once()


def test_get_token_reuses_valid_token():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()) as mock_post:
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
        auth.get_token()
    assert mock_post.call_count == 1


def test_get_token_refreshes_when_expiring():
    with patch("collector.auth.requests.post", return_value=_mock_token_response(expires_in=200)) as mock_post:
        # buffer=300 > expires_in=200, so token is immediately expiring
        auth = AuthManager("https://api.example.com", "cid", "csec", refresh_buffer_seconds=300)
        auth.get_token()  # fetch
        auth.get_token()  # should refresh again because expiring
    assert mock_post.call_count == 2


def test_revoke_posts_to_revoke_endpoint():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()):
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
    with patch("collector.auth.requests.post") as mock_revoke:
        auth.revoke()
    mock_revoke.assert_called_once()
    call_kwargs = mock_revoke.call_args
    assert "/oauth2/revoke" in call_kwargs[0][0]


def test_revoke_silently_ignores_failure():
    with patch("collector.auth.requests.post", return_value=_mock_token_response()):
        auth = AuthManager("https://api.example.com", "cid", "csec")
        auth.get_token()
    with patch("collector.auth.requests.post", side_effect=Exception("network error")):
        auth.revoke()  # should not raise
