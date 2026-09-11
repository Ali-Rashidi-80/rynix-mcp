"""rynix.scope.toml deny-by-default live probes."""

from pathlib import Path

from rynix_mcp.scope import live_probe_allowed

FIXTURE_REPO = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "scope-repo"


def test_live_probe_denied_without_allow_live():
    ok, reason = live_probe_allowed(FIXTURE_REPO, allow_live=False)
    assert ok is False
    assert "live_probe=false" in reason


def test_live_probe_allowed_with_flag():
    ok, _ = live_probe_allowed(FIXTURE_REPO, allow_live=True)
    assert ok is True


def test_no_scope_file_allows_probe():
    ok, _ = live_probe_allowed(None, allow_live=False)
    assert ok is True
