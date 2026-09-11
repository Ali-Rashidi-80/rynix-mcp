from rynix_mcp.guides_delegate import guides_health
from rynix_mcp.plugins import rynix_plugin_run


def test_agent_guides_host_agent_architecture():
    health = guides_health()
    assert health["architecture"] == "host_agent"
    assert health["no_external_llm_required"] is True


def test_agent_guides_playbook():
    result = rynix_plugin_run(
        "agent-guides",
        target_url="http://127.0.0.1:8001",
        options='{"action":"playbook","scan_mode":"quick"}',
    )
    assert result.get("architecture") == "host_agent"
    assert len(result.get("steps", [])) >= 2
