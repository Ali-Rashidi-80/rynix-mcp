from rynix_mcp.plugins import rynix_plugin_run


def test_browser_debug_disabled_by_default():
    result = rynix_plugin_run("browser-debug")
    assert result.get("error", {}).get("code") == "PLUGIN_DISABLED"


def test_browser_debug_health_when_enabled_manifest_exists():
    from rynix_mcp.plugins import load_manifest

    manifest = load_manifest("browser-debug")
    assert manifest is not None
    assert manifest.get("enabled") is False
