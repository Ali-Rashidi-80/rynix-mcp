from rynix_mcp.plugins import rynix_plugin_run


def test_pipeline_status():
    result = rynix_plugin_run("pipeline-runner", options='{"action":"status"}')
    assert result.get("plugin_id") == "pipeline-runner"
    assert "pipeline" in result


def test_pipeline_advance_stage():
    result = rynix_plugin_run("pipeline-runner", options='{"action":"advance_stage"}')
    assert result.get("action") == "advance_stage"
