"""P0 security fixes — profiles, plugins, export paths, check_access."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from rynix_mcp.config import PROFILES_DIR, ROOT
from rynix_mcp.path_safety import resolve_evidence_path
from rynix_mcp.plugins import load_manifest
from rynix_mcp.profiles import load_profile
from rynix_mcp.scanner import scope_allowed
from rynix_mcp.server import check_access, export_report, record_finding
from rynix_mcp.session import STORE

_PENTEST_OUTPUT = ROOT / "pentest_output"


def test_load_profile_rejects_path_traversal():
    with pytest.raises(ValueError, match="invalid profile name"):
        load_profile("../evil", PROFILES_DIR)


def test_load_profile_sets_fallback_metadata():
    prof = load_profile("nonexistent-profile-xyz", PROFILES_DIR)
    assert prof.get("_profile_fallback_from") == "nonexistent-profile-xyz"


def test_load_manifest_rejects_traversal_ids():
    assert load_manifest("../template-scan") is None
    assert load_manifest("foo/bar") is None
    assert load_manifest("..\\evil-plugin") is None


def test_scope_rejects_lone_wildcard():
    profile = {"scope": {"allow_hosts": ["*"]}}
    ok, _ = scope_allowed("http://evil.example.com", profile, "")
    assert ok is False


@patch("rynix_mcp.server.http_probe")
def test_check_access_defaults_allow_write_false(mock_probe):
    mock_probe.return_value = {
        "status": 200,
        "hash": "abc",
        "body_preview": "{}",
        "headers": {},
    }
    check_access("http://127.0.0.1:8000", "/api/v1/cases/1", "GET", "token")
    assert mock_probe.call_args.kwargs.get("allow_write") is False


@patch("rynix_mcp.server.http_probe")
def test_check_access_passes_allow_write_when_set(mock_probe):
    mock_probe.return_value = {
        "status": 200,
        "hash": "abc",
        "body_preview": "{}",
        "headers": {},
    }
    check_access(
        "http://127.0.0.1:8000",
        "/api/v1/cases/1",
        "POST",
        "token",
        allow_write=True,
    )
    assert mock_probe.call_args.kwargs.get("allow_write") is True


def test_record_finding_rejects_invalid_severity():
    result = record_finding("urgent", "x", "/a", "e", session_id="sev-test")
    assert result["error"]["code"] == "INVALID_SEVERITY"


def test_export_evidence_blocks_traversal_names():
    _PENTEST_OUTPUT.mkdir(parents=True, exist_ok=True)
    session = STORE.get("ev-path-test")
    session.add_evidence("../../evil.txt", "payload")
    with tempfile.TemporaryDirectory(dir=_PENTEST_OUTPUT) as tmp:
        paths = export_report(tmp, session_id="ev-path-test", formats="json")
        evidence_dir = Path(paths["evidence_dir"])
        assert all(p.parent == evidence_dir.resolve() for p in evidence_dir.glob("*.txt"))
        assert not any(".." in p.name for p in evidence_dir.glob("*.txt"))


def test_resolve_evidence_path_sanitizes(tmp_path):
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    p = resolve_evidence_path(ev_dir, "../../etc/passwd")
    assert p.name.endswith(".txt")
    assert ".." not in p.name
    assert p.parent == ev_dir.resolve()


@patch("rynix_mcp.server._execute_plugin", return_value={"ok": True})
def test_rynix_plugin_run_denies_frontend_url_out_of_scope(mock_exec):
    from rynix_mcp.server import rynix_plugin_run

    result = rynix_plugin_run(
        plugin_id="wstg",
        target_url="http://127.0.0.1:8000",
        options={"action": "run", "frontend_url": "http://evil.example.com/"},
        allow_live=True,
        profile="example-law-firm",
    )
    assert result.get("error", {}).get("code") == "SCOPE_DENIED"
    mock_exec.assert_not_called()


def test_role_matrix_fixture_has_samples():
    import importlib.util

    fixture = ROOT / "tests" / "fixtures" / "example-law-firm" / "role_matrix.py"
    assert fixture.is_file()
    spec = importlib.util.spec_from_file_location("role_matrix_fixture", fixture)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    assert mod.ROLE_DENY_SAMPLES
    assert mod.ROLE_ALLOW_SAMPLES
