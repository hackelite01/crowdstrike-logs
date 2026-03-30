from unittest.mock import MagicMock, patch
from output.http_post import HttpPostOutput


def _make_output():
    return HttpPostOutput({
        "url": "https://10.0.0.1:8080/ingest",
        "headers": {"X-Api-Key": "secret"},
        "batch_size": 2,
        "timeout_seconds": 5,
    })


def test_buffers_until_batch_size():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        assert mock_post.call_count == 0
        out.write({"id": "2"})
        assert mock_post.call_count == 1


def test_flush_on_close_sends_partial_batch():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        out.close()
    assert mock_post.call_count == 1


def test_includes_custom_headers():
    out = _make_output()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status = MagicMock()
    with patch("output.http_post.requests.post", return_value=ok) as mock_post:
        out.write({"id": "1"})
        out.write({"id": "2"})
    call_kwargs = mock_post.call_args[1]
    assert call_kwargs["headers"]["X-Api-Key"] == "secret"
