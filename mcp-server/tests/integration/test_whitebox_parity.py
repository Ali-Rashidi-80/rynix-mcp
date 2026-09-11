from rynix_mcp.plugins import rynix_plugin_run


def test_whitebox_queue_requires_repo():
    result = rynix_plugin_run("whitebox-scan", options='{"action":"queue_from_repo"}')
    assert result.get("error", {}).get("code") == "MISSING_ARG"


def test_whitebox_status_action():
    result = rynix_plugin_run("whitebox-scan", options='{"action":"next_target"}')
    assert result.get("plugin_id") == "whitebox-scan"
    assert result.get("action") == "next_target"
