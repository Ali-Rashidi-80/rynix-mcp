"""Tests for stealth-gate session cookie propagation."""

from unittest.mock import patch

import httpx
from rynix_mcp.http_session import ensure_stealth_gate, session_cookies, store_client_cookies
from rynix_mcp.session import STORE


@patch("rynix_mcp.http_session.unlock_stealth_gate", return_value=True)
@patch("rynix_mcp.http_session.load_gate_secret", return_value="secret")
@patch("rynix_mcp.http_session.httpx.Client")
def test_ensure_stealth_gate_stores_cookies(mock_client_cls, _secret, _unlock):
    mock_client = mock_client_cls.return_value.__enter__.return_value
    mock_client.cookies = httpx.Cookies()
    mock_client.cookies.set("gate", "1", domain="api.example.com")

    ok = ensure_stealth_gate("https://api.example.com", session_id="gate-test")
    assert ok is True
    cookies = session_cookies("https://api.example.com", session_id="gate-test")
    assert cookies.get("gate") == "1"
    assert STORE.get("gate-test").gate_unlocked["api.example.com"] is True


def test_store_client_cookies_from_external_client():
    client = httpx.Client()
    client.cookies.set("adl_gate", "ok", domain="api.example.com")
    store_client_cookies("https://api.example.com", client, session_id="copy-test")
    assert STORE.get("copy-test").gate_unlocked["api.example.com"] is True
    client.close()
