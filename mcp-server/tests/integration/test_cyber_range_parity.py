from rynix_mcp.plugins import rynix_plugin_run


def test_cyber_range_list_scenarios():
    result = rynix_plugin_run("cyber-range", options='{"action":"list_scenarios"}')
    assert result.get("plugin_id") == "cyber-range"
    assert len(result.get("scenarios", [])) >= 1


def test_cyber_range_start_scenario():
    result = rynix_plugin_run(
        "cyber-range",
        options='{"action":"start_scenario","scenario_id":"idor-matrix-lab"}',
    )
    assert result.get("action") == "start_scenario"
