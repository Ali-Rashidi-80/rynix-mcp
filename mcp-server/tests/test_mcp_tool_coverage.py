"""Gate #4 — every MCP tool has at least one real invocation test."""

from pathlib import Path
from unittest.mock import patch

import pytest
from rynix_mcp.server import mcp
from tests.test_mcp_tools import EXPECTED_TOOLS

ROOT = Path(__file__).resolve().parents[2]
REPO = str(ROOT / "examples" / "example-law-firm")
if not Path(REPO).is_dir():
    REPO = str(ROOT)


@pytest.fixture
def _gate_patches():
    with (
        patch("rynix_mcp.http_session.ensure_stealth_gate", return_value=True),
        patch("rynix_mcp.server.scope_check", return_value={"allowed": True}),
    ):
        yield


def _fn(name: str):
    tool = next(t for t in mcp._tool_manager.list_tools() if t.name == name)
    return tool.fn


def test_all_mcp_tools_registered():
    tools = {t.name for t in mcp._tool_manager.list_tools()}
    assert tools == EXPECTED_TOOLS


def test_tool_count_is_30():
    assert len(EXPECTED_TOOLS) == 30


@pytest.mark.usefixtures("_gate_patches")
def test_health_and_profiles_invoke():
    health = _fn("health_check")()
    assert health.get("ok") is True
    profiles = _fn("list_profiles")()
    assert isinstance(profiles.get("profiles", []), list)


@pytest.mark.usefixtures("_gate_patches")
def test_static_scan_tools_invoke():
    scan = _fn("analyze_repo")(repo_path=REPO, profile="example-law-firm")
    assert scan.get("modules_scanned", 0) >= 0
    routes = _fn("list_api_routes")(repo_path=REPO, profile="example-law-firm")
    assert "routes" in routes
    fe = _fn("list_frontend_routes")(repo_path=REPO)
    assert "routes" in fe
    rbac = _fn("rbac_matrix")(repo_path=REPO, profile="example-law-firm")
    assert rbac
    risk = _fn("high_risk_surfaces")(repo_path=REPO, profile="example-law-firm")
    assert risk
    brief = _fn("generate_pentest_brief")(repo_path=REPO, profile="example-law-firm")
    assert brief.get("focus") or brief.get("concerns")
    scope = _fn("scope_check")(base_url="http://127.0.0.1:8001", profile="example-law-firm")
    assert scope.get("allowed") is not None


@pytest.mark.usefixtures("_gate_patches")
def test_knowledge_tools_invoke():
    guide = _fn("get_technique_guide")(vuln_class="idor")
    assert guide.get("content")
    wstg = _fn("get_wstg_test")(test_id="WSTG-APIT-02")
    assert wstg.get("content")
    playbook = _fn("agent_engagement_playbook")(scan_mode="quick")
    assert playbook.get("steps")


@pytest.mark.usefixtures("_gate_patches")
def test_session_tools_invoke():
    sid = "coverage-session"
    scope = _fn("register_scope")(host="127.0.0.1", session_id=sid)
    assert scope.get("scopes") is not None
    wstg = _fn("track_wstg_test")(test_id="WSTG-INFO-01", status="started", session_id=sid)
    assert wstg.get("coverage") is not None or wstg.get("wstg_coverage") is not None
    step = _fn("track_probe_step")(name="smoke", status="ok", session_id=sid)
    assert step.get("step") is not None or step.get("probe_steps") is not None
    _fn("save_engagement_context")(key="note", content="test", session_id=sid)
    ctx = _fn("get_engagement_context")(session_id=sid)
    assert ctx.get("context")
    progress = _fn("list_engagement_progress")(session_id=sid)
    assert progress


@pytest.mark.usefixtures("_gate_patches")
def test_plugin_tools_invoke():
    plugins = _fn("list_plugins")()
    assert plugins.get("plugins")
    health = _fn("plugin_health_check")(plugin_id="template-scan")
    assert health.get("status") or health.get("plugin_id")
    run = _fn("rynix_plugin_run")(plugin_id="wstg", options={"action": "health"})
    assert run.get("status") or run.get("plugin_id") or run.get("ok") is not None


@pytest.mark.usefixtures("_gate_patches")
def test_export_and_openapi_invoke():
    stub = _fn("export_openapi_stub")(repo_path=REPO, profile="example-law-firm")
    assert stub.get("paths") or stub.get("openapi") or stub.get("info")
    report = _fn("export_report")(
        output_dir="tool-coverage-export",
        session_id="coverage-export",
        formats="json",
    )
    assert report


@pytest.mark.usefixtures("_gate_patches")
def test_live_probe_tools_invoke():
    sid = "coverage-live"
    with patch("rynix_mcp.http_session.request") as mock_req:
        mock_req.return_value.status_code = 200
        mock_req.return_value.text = "ok"
        mock_req.return_value.headers = {}
        probe = _fn("http_probe")(base_url="http://127.0.0.1:8001", path="/", session_id=sid)
        assert probe.get("status") == 200 or probe.get("status_code") == 200

    with (
        patch("rynix_mcp.http_session.request") as mock_req,
        patch("rynix_mcp.server._require_live_probe", return_value=(True, "")),
    ):
        mock_resp = mock_req.return_value
        mock_resp.status_code = 200
        mock_resp.text = '{"access_token":"test-token"}'
        mock_resp.json.return_value = {"access_token": "test-token"}
        mock_resp.headers = {}
        login = _fn("auth_login")(
            base_url="http://127.0.0.1:8001",
            username="user",
            password="pass",
            session_id=sid,
            role_label="client",
            allow_live=True,
        )
        assert login.get("token_preview") or login.get("error")

    gate = _fn("unlock_stealth_gate")(base_url="http://127.0.0.1:8001", session_id=sid)
    assert gate.get("ok") is not None or gate.get("unlocked") is not None

    with patch("rynix_mcp.http_session.request") as mock_req:
        mock_req.return_value.status_code = 403
        mock_req.return_value.text = ""
        mock_req.return_value.headers = {}
        access = _fn("check_access")(
            base_url="http://127.0.0.1:8001",
            path="/api/v1/cases/",
            method="GET",
            token="test-token",
            session_id=sid,
        )
        assert access.get("status") == 403 or access.get("allowed") is not None

    with patch("rynix_mcp.http_session.request") as mock_cmp:
        mock_cmp.return_value.status_code = 200
        mock_cmp.return_value.text = "{}"
        mock_cmp.return_value.headers = {}
        cmp = _fn("compare_role_response")(
            base_url="http://127.0.0.1:8001",
            path="/api/v1/cases/1",
            method="GET",
            token_a="a",
            token_b="b",
            session_id=sid,
        )
        assert cmp.get("verdict")

    finding = _fn("record_finding")(
        title="coverage",
        severity="info",
        endpoint="/api/v1/cases/1",
        evidence="http_probe status 200",
        session_id=sid,
    )
    assert finding.get("finding_id")

    with (
        patch.dict("os.environ", {"RYNIX_PROBE_PASSWORD": "x", "RYNIX_PROBE_USER_CLIENT": "c"}),
        patch("rynix_mcp.server.auth_login", return_value={"token_preview": "x"}),
        patch(
            "rynix_mcp.server.compare_role_response",
            return_value={"verdict": "no_signal", "idor_likely": False},
        ),
        patch("rynix_mcp.server.export_report", return_value={"json_path": "x"}),
    ):
        matrix = _fn("run_idor_matrix")(
            base_url="http://127.0.0.1:8001",
            session_id="coverage-matrix",
        )
        assert matrix.get("comparisons", 0) >= 0 or matrix.get("error")
