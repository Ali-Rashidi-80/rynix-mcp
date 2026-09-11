"""Plugin system — manifests, health, wstg checklist (Phase 6a)."""

from rynix_mcp.plugins import (
    list_plugin_manifests,
    plugin_health_check,
    run_wstg_checklist,
    rynix_plugin_run,
)


def test_list_plugins_includes_wstg_and_template_scan():
    plugins = list_plugin_manifests()
    ids = {p["id"] for p in plugins}
    assert "wstg" in ids
    assert "template-scan" in ids


def test_wstg_checklist_has_many_tests():
    result = run_wstg_checklist()
    assert result["count"] >= 100
    assert any(t["test_id"] == "WSTG-APIT-01" for t in result["tests"])


def test_wstg_plugin_run():
    result = rynix_plugin_run("wstg")
    assert result["count"] >= 100


def test_template_scan_health_reports_binary():
    result = plugin_health_check("template-scan")
    assert "binary" in result or "error" in result
    assert "plugin_id" in result or result.get("error")
