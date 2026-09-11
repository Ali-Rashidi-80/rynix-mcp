#!/usr/bin/env python3
"""Gate #8 — golden engagement jury smoke (quick + standard playbook)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"


def main() -> int:
    sys.path.insert(0, str(MCP_SERVER))
    from rynix_mcp.agent_playbook import build_agent_playbook
    from rynix_mcp.plugins import rynix_plugin_run

    failed = 0
    for mode in ("quick", "standard"):
        pb = build_agent_playbook(scan_mode=mode, target_url="http://127.0.0.1:8001")
        if pb.get("architecture") != "host_agent":
            print(f"FAIL playbook {mode}: wrong architecture", file=sys.stderr)
            failed += 1
        if len(pb.get("steps", [])) < 2:
            print(f"FAIL playbook {mode}: too few steps", file=sys.stderr)
            failed += 1
        print(f"PASS playbook {mode} ({len(pb['steps'])} steps)")

    plugins = [
        "template-scan",
        "wstg",
        "engagement",
        "agent-guides",
        "pipeline-runner",
        "cyber-range",
        "whitebox-scan",
        "agent-orchestrator",
        "browser-debug",
    ]
    for pid in plugins:
        if pid == "template-scan":
            result = rynix_plugin_run(pid)
            ok = result.get("error", {}).get("code") == "MISSING_ARG"
        elif pid == "browser-debug":
            result = rynix_plugin_run(pid)
            ok = result.get("error", {}).get("code") == "PLUGIN_DISABLED"
        elif pid == "agent-orchestrator":
            result = rynix_plugin_run(pid)
            ok = result.get("plugin_id") == pid
        elif pid == "wstg":
            result = rynix_plugin_run(pid, options='{"action":"list"}')
            ok = result.get("count", 0) >= 100
        elif pid == "pipeline-runner":
            result = rynix_plugin_run(pid, options='{"action":"status"}')
            ok = "pipeline" in result
        elif pid == "cyber-range":
            result = rynix_plugin_run(pid, options='{"action":"list_scenarios"}')
            ok = len(result.get("scenarios", [])) >= 1
        elif pid == "engagement":
            result = rynix_plugin_run(pid)
            ok = result.get("valid") is True or result.get("action") == "validate"
        elif pid == "agent-guides":
            result = rynix_plugin_run(pid)
            ok = result.get("architecture") == "host_agent" or result.get("plugin_id") == pid
        elif pid == "whitebox-scan":
            result = rynix_plugin_run(pid, options='{"action":"next_target"}')
            ok = result.get("plugin_id") == pid and result.get("action") == "next_target"
        else:
            result = rynix_plugin_run(pid)
            ok = result.get("plugin_id") == pid
        status = "PASS" if ok else "FAIL"
        print(f"{status} plugin {pid}")
        if not ok:
            failed += 1
            print(json.dumps(result, indent=2)[:300], file=sys.stderr)

    if failed:
        return 1
    print("golden engagement jury — OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
