"""Structural coverage for URL-bearing MCP tool parameters."""

import inspect

from rynix_mcp.probe_urls import URL_BEARING_KEYS, extract_probe_urls


def test_extract_probe_urls_collects_frontend_url():
    urls = extract_probe_urls(
        "http://127.0.0.1:8000",
        {"frontend_url": "http://127.0.0.1:3000", "action": "run"},
    )
    assert "http://127.0.0.1:8000" in urls
    assert "http://127.0.0.1:3000" in urls


def test_url_bearing_keys_include_frontend_url():
    assert "frontend_url" in URL_BEARING_KEYS


def test_probe_urls_helper_signature():
    sig = inspect.signature(extract_probe_urls)
    assert "target_url" in sig.parameters
    assert "options" in sig.parameters
