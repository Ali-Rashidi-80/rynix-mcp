from rynix_mcp.plugins import rynix_plugin_run


def test_engagement_validate_default():
    result = rynix_plugin_run("engagement")
    assert result.get("valid") is True or result.get("action") == "validate"


def test_engagement_scopes():
    result = rynix_plugin_run("engagement", options='{"action":"scopes"}')
    assert result.get("action") == "scopes"
    assert isinstance(result.get("scopes"), list)
