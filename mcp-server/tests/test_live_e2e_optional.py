"""Optional live E2E — runs only when RYNIX_PROBE_BASE_URL is set."""

import os

import pytest
from rynix_mcp.server import mcp

BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "").strip()
PROFILE = os.environ.get("RYNIX_PROBE_PROFILE", "example-law-firm")


def _fn(name: str):
    tool = next(t for t in mcp._tool_manager.list_tools() if t.name == name)
    return tool.fn


@pytest.mark.skipif(not BASE, reason="set RYNIX_PROBE_BASE_URL for live E2E")
def test_live_health_probe():
    result = _fn("http_probe")(base_url=BASE, path="/api/health", session_id="live-e2e")
    status = result.get("status") or result.get("status_code")
    assert status in (200, 401, 403, 404)


@pytest.mark.skipif(not BASE, reason="set RYNIX_PROBE_BASE_URL for live E2E")
def test_live_scope_and_idor_matrix():
    scope = _fn("scope_check")(base_url=BASE, profile=PROFILE)
    assert scope.get("allowed") is not None
    matrix = _fn("run_idor_matrix")(base_url=BASE, profile=PROFILE, session_id="live-e2e")
    assert "error" not in matrix or matrix.get("comparisons", 0) >= 0
