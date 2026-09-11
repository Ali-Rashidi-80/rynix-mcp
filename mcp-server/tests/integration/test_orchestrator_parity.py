from rynix_mcp.plugins import rynix_plugin_run


def test_orchestrator_health():
    result = rynix_plugin_run("agent-orchestrator")
    assert result.get("plugin_id") == "agent-orchestrator"
    assert result.get("architecture") == "host_agent"


def test_orchestrator_probe_disabled():
    result = rynix_plugin_run("agent-orchestrator", options='{"action":"probe"}')
    assert result.get("error", {}).get("code") == "PLUGIN_DISABLED"
