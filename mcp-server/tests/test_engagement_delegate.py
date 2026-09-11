from rynix_mcp.engagement_delegate import engagement_check_scope, engagement_delegate


def test_engagement_scopes_action():
    result = engagement_delegate("scopes")
    assert result.get("action") == "scopes"
    assert result.get("count", 0) >= 0


def test_engagement_check_allowed_localhost():
    result = engagement_check_scope("", "http://127.0.0.1:8001/api/v1/health")
    assert result.get("action") == "check"
    assert result.get("allowed") is True


def test_engagement_run_host_agent():
    result = engagement_delegate("run")
    assert result.get("action") == "run"
    assert result.get("architecture") == "host_agent"
    assert "playbook" in result
