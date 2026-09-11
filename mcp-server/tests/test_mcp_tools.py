"""Count and name MCP tools — gate G3 substitute when Inspector unavailable."""

from rynix_mcp.server import mcp

EXPECTED_TOOLS = {
    "health_check",
    "list_profiles",
    "analyze_repo",
    "list_api_routes",
    "list_frontend_routes",
    "rbac_matrix",
    "high_risk_surfaces",
    "generate_pentest_brief",
    "scope_check",
    "http_probe",
    "auth_login",
    "unlock_stealth_gate",
    "check_access",
    "compare_role_response",
    "record_finding",
    "export_report",
    "export_openapi_stub",
    "get_technique_guide",
    "get_wstg_test",
    "agent_engagement_playbook",
    "list_plugins",
    "plugin_health_check",
    "rynix_plugin_run",
    "run_idor_matrix",
    "register_scope",
    "track_wstg_test",
    "track_probe_step",
    "save_engagement_context",
    "get_engagement_context",
    "list_engagement_progress",
}


def test_tool_count_and_names():
    tools = {t.name for t in mcp._tool_manager.list_tools()}
    missing = EXPECTED_TOOLS - tools
    assert not missing, f"missing tools: {missing}"
    assert len(tools) == len(EXPECTED_TOOLS), (
        f"expected {len(EXPECTED_TOOLS)}, got {len(tools)}: {tools}"
    )


def test_core_tools_at_least_16():
    core = EXPECTED_TOOLS - {"list_plugins", "plugin_health_check", "rynix_plugin_run"}
    tools = {t.name for t in mcp._tool_manager.list_tools()}
    assert len(core & tools) >= 16
