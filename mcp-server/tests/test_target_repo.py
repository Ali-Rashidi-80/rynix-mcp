from pathlib import Path

import pytest
from rynix_mcp.profiles import resolve_profile_name
from rynix_mcp.target_repo import target_repo_env, target_repo_path


def test_target_repo_env(monkeypatch):
    monkeypatch.setenv("RYNIX_TARGET_REPO", "/tmp/app")
    assert target_repo_env() == "/tmp/app"


def test_resolve_profile_from_pentest_override(tmp_path: Path):
    pentest = tmp_path / ".pentest"
    pentest.mkdir()
    (pentest / "profile.toml").write_text('name = "custom-profile"\n', encoding="utf-8")
    assert resolve_profile_name(None, tmp_path) == "custom-profile"


def test_target_repo_required_raises(monkeypatch):
    monkeypatch.delenv("RYNIX_TARGET_REPO", raising=False)
    with pytest.raises(RuntimeError, match="RYNIX_TARGET_REPO"):
        target_repo_path(required=True)
