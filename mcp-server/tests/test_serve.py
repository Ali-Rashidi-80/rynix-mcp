"""HTTP serve factory and transport wiring tests."""

from unittest.mock import patch

import pytest
from rynix_mcp.serve import _MIN_TOKEN_LEN, create_mcp, serve


def test_create_mcp_returns_server():
    server = create_mcp()
    tools = {t.name for t in server._tool_manager.list_tools()}
    assert "health_check" in tools
    assert len(tools) >= 30


def test_serve_rejects_short_token():
    with (
        pytest.raises(SystemExit),
        patch("rynix_mcp.serve.os.environ", {"RYNIX_SERVE_TOKEN": "short"}),
    ):
        serve()


def test_serve_rejects_empty_token():
    with pytest.raises(SystemExit), patch("rynix_mcp.serve.os.environ", {}):
        serve()


def test_serve_uses_streamable_http_transport():
    token = "x" * _MIN_TOKEN_LEN
    with (
        patch("rynix_mcp.serve.os.environ", {"RYNIX_SERVE_TOKEN": token}),
        patch("rynix_mcp.serve.mcp.run") as mock_run,
    ):
        serve(host="127.0.0.1", port=18090)
    mock_run.assert_called_once_with(transport="streamable-http", host="127.0.0.1", port=18090)


def test_serve_sets_bearer_token_env():
    token = "a" * _MIN_TOKEN_LEN
    env = {"RYNIX_SERVE_TOKEN": token}
    with (
        patch("rynix_mcp.serve.os.environ", env),
        patch("rynix_mcp.serve.mcp.run") as mock_run,
    ):
        serve()
    assert mock_run.called
    assert env["FASTMCP_SERVER_AUTH_BEARER_TOKEN"] == token
