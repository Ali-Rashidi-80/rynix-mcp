"""Tests for options coercion, WSTG runner, enabled plugins."""

from rynix_mcp.options_util import parse_options
from rynix_mcp.plugins import load_manifest, rynix_plugin_run
from rynix_mcp.wstg_runner import list_wstg_test_ids, run_wstg_suite


def test_parse_options_accepts_dict():
    assert parse_options({"action": "playbook", "scan_mode": "quick"}) == {
        "action": "playbook",
        "scan_mode": "quick",
    }


def test_parse_options_accepts_json_string():
    assert parse_options('{"action":"run"}')["action"] == "run"


def test_agent_guides_playbook_accepts_dict_options():
    result = rynix_plugin_run(
        "agent-guides",
        target_url="http://127.0.0.1:8001",
        options={"action": "playbook", "scan_mode": "quick"},
    )
    assert result.get("scan_mode") == "quick"
    assert len(result.get("steps", [])) >= 2


def test_wstg_list_has_109_tests():
    ids = list_wstg_test_ids()
    assert len(ids) == 109


def test_wstg_run_action_structure():
    result = run_wstg_suite("http://127.0.0.1:1", repo_path=None)
    assert result.get("total_tests") == 109
    assert result.get("executed_count") + result.get("inconclusive_count", 0) == 109
    assert len(result.get("results", [])) == 109


def test_agent_orchestrator_disabled_by_default_in_manifest():
    manifest = load_manifest("agent-orchestrator")
    assert manifest is not None
    assert manifest.get("enabled") is False
    run = rynix_plugin_run("agent-orchestrator", options='{"action":"probe"}')
    assert run.get("error", {}).get("code") == "PLUGIN_DISABLED"


def test_browser_debug_disabled_by_default_in_manifest():
    manifest = load_manifest("browser-debug")
    assert manifest.get("enabled") is False
    run = rynix_plugin_run("browser-debug")
    assert run.get("error", {}).get("code") == "PLUGIN_DISABLED"
