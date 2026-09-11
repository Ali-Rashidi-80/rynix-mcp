from rynix_mcp.plugins import plugin_health_check, rynix_plugin_run


def test_template_scan_manifest_and_health():
    health = plugin_health_check("template-scan")
    assert health.get("plugin_id") == "template-scan"
    assert "enabled" in health


def test_template_scan_requires_target():
    result = rynix_plugin_run("template-scan")
    assert result.get("error", {}).get("code") == "MISSING_ARG"
