"""Tests for stealth gate unlock helper."""

from typing import Any
from unittest.mock import MagicMock

import httpx
from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate


def test_load_gate_secret_from_env(monkeypatch):
    monkeypatch.setenv("RYNIX_STEALTH_GATE_SECRET", "test-gate-value")
    assert load_gate_secret() == "test-gate-value"


def test_unlock_stealth_gate_defaults_to_header():
    client = httpx.Client()
    captured: dict[str, Any] = {}
    gate = {"query_param": "api_gate", "cookie_name": "api_gate"}

    def fake_get(url: str, **kwargs):
        captured["url"] = url
        captured["headers"] = kwargs.get("headers", {})
        response = MagicMock()
        response.status_code = 302
        response.cookies = httpx.Cookies()
        response.cookies.set("api_gate", "token", domain="api.example.com")
        client.cookies.set("api_gate", "token", domain="api.example.com")
        return response

    client.get = fake_get  # type: ignore[method-assign]
    ok = unlock_stealth_gate(
        "https://api.example.com", "secret-32chars-minimum!!", client, gate=gate
    )
    client.close()
    assert ok is True
    # Secret must NOT leak in URL by default
    assert "secret-32chars-minimum" not in captured["url"]
    assert "api_gate=" not in captured["url"]
    assert captured["headers"].get("X-Gate-Secret") == "secret-32chars-minimum!!"


def test_unlock_stealth_gate_opt_in_query():
    client = httpx.Client()
    captured: dict[str, Any] = {}
    gate = {"query_param": "api_gate", "cookie_name": "api_gate", "transport": "query"}

    def fake_get(url: str, **kwargs):
        captured["url"] = url
        response = MagicMock()
        response.status_code = 302
        response.cookies = httpx.Cookies()
        response.cookies.set("api_gate", "token", domain="api.example.com")
        client.cookies.set("api_gate", "token", domain="api.example.com")
        return response

    client.get = fake_get  # type: ignore[method-assign]
    ok = unlock_stealth_gate(
        "https://api.example.com", "secret-32chars-minimum!!", client, gate=gate
    )
    client.close()
    assert ok is True
    assert "api_gate=" in captured["url"]
    assert "secret-32chars-minimum" in captured["url"]
