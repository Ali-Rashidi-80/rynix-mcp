"""Comprehensive regression and negative tests for Delta Audit v3 (P0 and P1 fixes)."""

from unittest.mock import patch

import pytest
from rynix_mcp.engagement_session import register_scope
from rynix_mcp.http_session import _is_local
from rynix_mcp.idor_matrix import run_idor_matrix
from rynix_mcp.path_safety import safe_sarif_input_path
from rynix_mcp.probe_urls import extract_probe_urls
from rynix_mcp.profiles import _filter_repo_profile_overrides
from rynix_mcp.scanner import scope_allowed
from rynix_mcp.server import record_finding, unlock_stealth_gate
from rynix_mcp.session import MAX_FINDINGS_ENTRIES, STORE, Finding
from rynix_mcp.wstg_runner import _result


# 1. R-56: _is_local IPv6 support
def test_is_local_ipv6_and_mapped_addresses():
    assert _is_local("http://[::1]:8000") is True
    assert _is_local("http://[::ffff:127.0.0.1]:8080") is True
    assert _is_local("http://127.0.0.1:3000") is True
    assert _is_local("http://localhost:5000") is True
    assert _is_local("https://api.example.com") is False
    assert _is_local("http://192.168.1.1:8000") is False


# 2. N-P18: deny_loopback blocks localhost and loopback IPs
def test_deny_loopback_blocks_loopback_hosts():
    profile_default = {"scope": {"allow_hosts": ["api.example.com"]}}
    allowed, _ = scope_allowed("http://127.0.0.1:8000", profile_default, "")
    assert allowed is True, "Default profile without deny_loopback allows 127.0.0.1"

    profile_deny = {"scope": {"allow_hosts": ["api.example.com"], "deny_loopback": True}}
    allowed, _ = scope_allowed("http://127.0.0.1:8000", profile_deny, "")
    assert allowed is False, "Profile with deny_loopback: true must block 127.0.0.1"

    allowed_v6, _ = scope_allowed("http://[::1]:8000", profile_deny, "")
    assert allowed_v6 is False, "Profile with deny_loopback: true must block ::1"

    allowed_remote, _ = scope_allowed("https://api.example.com", profile_deny, "")
    assert allowed_remote is True, "Explicit allowed remote hosts should still be permitted"


# 3. N3-P02: repo profile cannot override security thresholds in [risk]
def test_repo_profile_risk_override_is_restricted():
    malicious_repo_profile = {
        "auth": {"login_url": "/api/custom-login"},
        "risk": {
            "idor_max_unauth_score": 9999,
            "role_trust": {"attacker": 99},
            "office_roles": ["guest"],
            "extra_endpoints": ["/api/custom-extra"],
            "notes": "safe note",
        },
        "stealth": {"gate": {"secret_key": "EVIL"}},
    }
    safe = _filter_repo_profile_overrides(malicious_repo_profile)
    assert "stealth" not in safe, "stealth block must never be merged from repo"
    assert "risk" in safe
    risk_merged = safe["risk"]
    assert "idor_max_unauth_score" not in risk_merged, "Thresholds must not be merged from repo"
    assert "role_trust" not in risk_merged, "Role trust rankings must not be merged from repo"
    assert "office_roles" not in risk_merged, "Office roles must not be merged from repo"
    assert risk_merged.get("extra_endpoints") == ["/api/custom-extra"]
    assert risk_merged.get("notes") == "safe note"


# 4. N3-P01: WSTG runner inconclusive result does not pass
def test_wstg_result_inconclusive_mapping():
    # When pass_ is None, status becomes inconclusive
    r = _result("WSTG-INPV-01", status="executed", pass_=None, probe="sqli_probe")
    assert r["status"] == "inconclusive"
    assert r["pass"] is None


# 5. N3-P07: IDOR matrix coverage warning on empty active pairs
@patch("rynix_mcp.http_session.ensure_stealth_gate", return_value=True)
@patch("rynix_mcp.server.scope_check", return_value={"allowed": True})
def test_idor_matrix_warns_on_no_active_role_pairs(mock_scope, mock_gate):
    from rynix_mcp.path_safety import resolve_export_output_dir

    with (
        patch.dict(
            "os.environ",
            {"RYNIX_PROBE_PASSWORD": "secret_password", "RYNIX_PROBE_USER_CLIENT": "client-user"},
        ),
        patch("rynix_mcp.server.export_report", return_value={}),
    ):
        res = run_idor_matrix(
            "http://127.0.0.1:8001",
            roles=["client"],
            session_id="matrix-warn-session",
            export_dir="pytest-matrix-out",
        )
    assert res["comparisons"] == 0
    assert any("NO_ACTIVE_ROLE_PAIRS" in w for w in res["warnings"])
    matrix_file = resolve_export_output_dir("pytest-matrix-out") / "matrix.json"
    assert matrix_file.is_file()
    import json

    data = json.loads(matrix_file.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("coverage_warning") == "NO_ACTIVE_ROLE_PAIRS"
    assert data.get("executed") is False


# 6. N3-P06: register_scope validates and normalizes hosts
def test_register_scope_host_validation():
    # Valid hostname
    res1 = register_scope("api.example.com", session_id="scope-val-1")
    assert res1["ok"] is True
    assert res1["scopes"][-1]["host"] == "api.example.com"

    # URL with scheme should be normalized to hostname
    res2 = register_scope("http://169.254.169.254:8080/path", session_id="scope-val-2")
    assert res2["ok"] is True
    assert res2["scopes"][-1]["host"] == "169.254.169.254"

    # Valid CIDR
    res3 = register_scope("10.0.0.0/24", session_id="scope-val-3")
    assert res3["ok"] is True
    assert res3["scopes"][-1]["host"] == "10.0.0.0/24"

    # Invalid host string
    res4 = register_scope("not a valid host @@@!!!", session_id="scope-val-4")
    assert res4["ok"] is False
    assert res4["error"] == "INVALID_HOST"


# 7. N3-P05: extract_probe_urls parses nested options
def test_extract_probe_urls_nested_traversal():
    opts = {
        "level1": {
            "probe_target": "https://sub.example.com/api",
            "url": "https://nested.example.com",
            "level2": {
                "frontend_url": "https://deep.example.com",
            },
        },
        "target": "https://top.example.com",
    }
    urls = extract_probe_urls(options=opts)
    assert "https://top.example.com" in urls
    assert "https://nested.example.com" in urls
    assert "https://deep.example.com" in urls


# 8. N-P10: findings cap enforcement
def test_findings_cap_enforcement():
    sid = "findings-cap-session"
    session = STORE.get(sid)
    session.findings.clear()

    # Add up to cap
    for i in range(MAX_FINDINGS_ENTRIES):
        session.findings.append(
            Finding(
                id=f"f-{i}",
                severity="low",
                title=f"Finding {i}",
                endpoint="/api",
                evidence="proof",
            )
        )

    res = record_finding(
        severity="low",
        title="Overflow",
        endpoint="/api",
        evidence="proof",
        session_id=sid,
    )
    assert "error" in res
    assert res["error"]["code"] == "FINDINGS_CAP_REACHED"


# 9. N-P05: safe_sarif_input_path validates sandbox boundaries
def test_safe_sarif_input_path_traversal_rejection():
    with pytest.raises(ValueError):
        safe_sarif_input_path("/etc/passwd")

    with pytest.raises(ValueError):
        safe_sarif_input_path("../../secret.sarif")

    with pytest.raises(ValueError):
        safe_sarif_input_path("evil\x00.sarif")


# 10. N-P08 / N3-P08: unlock_stealth_gate passes profile & logs audit
@patch("rynix_mcp.server._require_scope", return_value=(True, ""))
@patch("rynix_mcp.http_session.unlock_stealth_gate", return_value=True)
def test_unlock_stealth_gate_passes_profile_and_logs_audit(mock_unlock, mock_scope, monkeypatch):
    monkeypatch.setenv("RYNIX_STEALTH_GATE_SECRET", "super-secret-gate-token-value")
    sid = "unlock-gate-test"
    res = unlock_stealth_gate(
        base_url="https://api.example.com",
        session_id=sid,
        allow_live=True,
    )
    assert res.get("unlocked") is True
    session = STORE.get(sid)
    audit_events = [e for e in session.audit if e.get("event") == "stealth_gate_unlocked"]
    assert len(audit_events) >= 1
    # Secret must be redacted in audit log
    assert "super-secret-gate-token-value" not in str(audit_events[0])
    assert "[REDACTED]" in audit_events[0].get("gate_secret", "")
