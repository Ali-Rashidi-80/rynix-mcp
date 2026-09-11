from rynix_mcp.guides_delegate import guides_delegate, guides_health


def test_guides_health_host_agent():
    result = guides_health()
    assert result["architecture"] == "host_agent"
    assert result["no_external_llm_required"] is True


def test_guides_playbook_quick():
    result = guides_delegate(action="scan", target_url="http://127.0.0.1:8001", scan_mode="quick")
    assert result.get("scan_mode") == "quick"
    assert len(result.get("steps", [])) >= 2


def test_guides_guide_idor():
    result = guides_delegate(action="guide", vuln_class="idor")
    assert result.get("action") == "guide"
    assert result.get("result")
