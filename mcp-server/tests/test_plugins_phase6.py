"""Phase 6b–6e plugin manifests and runners."""

from rynix_mcp.config import ROOT
from rynix_mcp.engagement import validate_engagement_yaml
from rynix_mcp.guides_delegate import guides_health
from rynix_mcp.plugins import list_plugin_manifests, plugin_health_check, rynix_plugin_run
from rynix_mcp.sarif_import import merge_sarif_file


def test_all_phase_manifests_present():
    plugins = list_plugin_manifests()
    ids = {p["id"] for p in plugins}
    for pid in (
        "template-scan",
        "wstg",
        "engagement",
        "sarif-import",
        "agent-guides",
        "agent-orchestrator",
        "browser-debug",
        "pipeline-runner",
        "cyber-range",
        "whitebox-scan",
    ):
        assert pid in ids


def test_engagement_validate_example_engagement():
    example = ROOT / "schemas" / "engagements" / "example.yaml"
    result = validate_engagement_yaml(str(example))
    assert result["valid"] is True
    assert "127.0.0.1" in result["allowed_hosts"]


def test_engagement_plugin_run_defaults_to_validate():
    result = rynix_plugin_run("engagement")
    assert result.get("valid") is True or result.get("action") == "validate"


def test_engagement_plugin_scopes_action():
    result = rynix_plugin_run("engagement", options='{"action":"scopes"}')
    assert result.get("action") == "scopes"
    assert isinstance(result.get("scopes"), list)


def test_sarif_import_merge_imports_findings():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "TEST-001",
                        "level": "error",
                        "message": {"text": "Imported from SARIF fixture"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "/api/v1/test"}}}
                        ],
                    }
                ]
            }
        ],
    }
    import json
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False, encoding="utf-8") as f:
        json.dump(sarif, f)
        path = f.name
    result = merge_sarif_file(path, session_id="sarif-test")
    assert result["imported_count"] == 1
    assert result["recorded_finding_ids"]


def test_agent_guides_enabled_host_agent():
    health = plugin_health_check("agent-guides")
    assert health.get("enabled") is True
    run = rynix_plugin_run("agent-guides")
    assert run.get("architecture") == "host_agent"
    assert run.get("no_external_llm_required") is True
    playbook = rynix_plugin_run(
        "agent-guides",
        target_url="http://127.0.0.1:8001",
        options='{"action":"playbook","scan_mode":"quick"}',
    )
    assert playbook.get("scan_mode") == "quick"
    assert len(playbook.get("steps", [])) >= 2


def test_agent_guides_health_reports_prerequisites():
    result = guides_health()
    assert result["architecture"] == "host_agent"
    assert "skills_in_mcp" in result
    assert "llm_configured" not in result


def test_agent_orchestrator_health_when_disabled():
    run = rynix_plugin_run("agent-orchestrator")
    assert run.get("plugin_id") == "agent-orchestrator"
    assert run.get("action") == "health"


def test_browser_debug_disabled_by_default():
    run = rynix_plugin_run("browser-debug")
    assert run.get("error", {}).get("code") == "PLUGIN_DISABLED"
