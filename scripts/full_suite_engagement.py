"""Run full pentest suite: WSTG 109, SQLi, browser, plugins, IDOR summary."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
sys.path.insert(0, str(MCP_SERVER))

from rynix_mcp.browser_debug_delegate import browser_debug_delegate
from rynix_mcp.browser_probe import run_browser_suite
from rynix_mcp.cloud_probe import run_cloud_probe
from rynix_mcp.design_review import PHYSICAL_SOCIAL_TESTS, run_design_review
from rynix_mcp.guides_delegate import guides_delegate
from rynix_mcp.orchestrator_delegate import orchestrator_delegate
from rynix_mcp.plugins import plugin_health_check, rynix_plugin_run
from rynix_mcp.scanner import run_scan, validate_repo_path
from rynix_mcp.sqli_probe import run_sqli_suite
from rynix_mcp.wstg_runner import run_wstg_suite

REPO = Path(os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", "")))
OUT = ROOT / "pentest_output" / "full-suite"
BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
FRONTEND = os.environ.get("RYNIX_FRONTEND_URL", "http://127.0.0.1:5173")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    idor_path = ROOT / "pentest_output" / "completeness-audit" / "COMPLETENESS_AUDIT.json"
    idor_summary: dict = {}
    if idor_path.is_file():
        data = json.loads(idor_path.read_text(encoding="utf-8"))
        idor_summary = data.get("mirror_idor", data.get("production_idor", {}))

    report: dict = {
        "timestamp": datetime.now(UTC).isoformat(),
        "base_url": BASE,
        "repo": str(REPO),
    }

    static_scan = run_scan(validate_repo_path(str(REPO)))
    get_paths = [
        r.get("path") or r.get("route")
        for r in static_scan.get("routes", [])
        if str(r.get("method", "GET")).upper() == "GET"
        and str(r.get("path") or r.get("route") or "").startswith("/")
        and "{" not in str(r.get("path") or r.get("route") or "")
    ]
    if not get_paths:
        get_paths = ["/api/v1/cases", "/api/v1/clients", "/api/v1/users"]

    wstg = run_wstg_suite(
        BASE, repo_path=str(REPO), frontend_url=FRONTEND, idor_summary=idor_summary
    )
    report["wstg"] = {
        "total": wstg.get("total_tests"),
        "executed": wstg.get("executed_count"),
        "failed": wstg.get("failed_count"),
        "pass": wstg.get("pass"),
        "coverage_pct": wstg.get("coverage_pct"),
    }

    report["sqli"] = run_sqli_suite(BASE, get_paths)
    report["browser"] = run_browser_suite(BASE, FRONTEND)
    report["cloud"] = run_cloud_probe(str(REPO))
    report["design_review"] = {
        tid: run_design_review(tid, str(REPO), static_scan) for tid in sorted(PHYSICAL_SOCIAL_TESTS)
    }
    report["agent_guides"] = guides_delegate(action="health")
    report["agent_guides_playbook"] = rynix_plugin_run(
        "agent-guides",
        target_url=BASE,
        options={"action": "playbook", "scan_mode": "quick", "repo_path": str(REPO)},
    )
    report["agent_orchestrator"] = orchestrator_delegate(action="health")
    report["browser_debug"] = browser_debug_delegate(action="health")
    report["plugin_health"] = {
        pid: plugin_health_check(pid)
        for pid in (
            "template-scan",
            "wstg",
            "engagement",
            "agent-guides",
            "agent-orchestrator",
            "browser-debug",
        )
    }

    optional_ready = report["agent_orchestrator"].get("reachable") or report["browser_debug"].get(
        "reachable"
    )
    overall = (
        wstg.get("pass") is True
        and report["sqli"].get("pass") is True
        and report["browser"].get("pass") is True
    )
    report["overall_pass"] = overall
    report["optional_stack"] = {
        "agent_orchestrator_reachable": report["agent_orchestrator"].get("reachable"),
        "browser_debug_reachable": report["browser_debug"].get("reachable"),
        "playwright_available": report["browser"].get("playwright_available"),
        "any_optional_live": optional_ready,
    }

    out_json = OUT / "FULL_SUITE_REPORT.json"
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    wstg_detail = OUT / "WSTG_SUITE_RESULTS.json"
    wstg_detail.write_text(json.dumps(wstg, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        json.dumps(
            {"overall_pass": overall, "optional": report["optional_stack"], "out": str(out_json)},
            indent=2,
        )
    )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
