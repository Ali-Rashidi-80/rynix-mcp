"""check_access returns E4 shape."""

from unittest.mock import patch

from rynix_mcp.server import check_access


@patch("rynix_mcp.server.http_probe")
def test_check_access_e4_shape(mock_probe):
    mock_probe.return_value = {
        "status": 200,
        "hash": "abc123",
        "body_preview": '{"id":1}',
        "headers": {},
    }
    result = check_access(
        "http://127.0.0.1:8000",
        "/api/v1/cases/1",
        "GET",
        "token",
        profile="generic-fastapi-react",
    )
    assert result == {"status": 200, "body_hash": "abc123", "snippet": '{"id":1}'}
    mock_probe.assert_called_once()
    assert mock_probe.call_args.kwargs.get("allow_write") is False
