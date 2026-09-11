from rynix_mcp.knowledge import (
    get_technique_guide,
    get_wstg_test,
    list_vuln_classes,
    wstg_test_count,
)


def test_get_technique_guide_idor():
    result = get_technique_guide("idor")
    assert "content" in result
    assert "IDOR" in result["content"] or "BOLA" in result["content"]


def test_get_technique_guide_sql_injection():
    result = get_technique_guide("sql-injection")
    assert "content" in result
    assert result["source"].startswith("knowledge/techniques/")
    assert "total_bytes" in result


def test_vuln_class_catalog():
    classes = list_vuln_classes()
    assert len(classes) >= 10


def test_get_wstg_apit():
    result = get_wstg_test("WSTG-APIT-01")
    assert "content" in result
    assert "WSTG" in result["content"] or "API" in result["content"]


def test_wstg_ported_count():
    assert wstg_test_count() >= 100
