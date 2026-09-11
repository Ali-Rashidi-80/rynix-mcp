#!/usr/bin/env python3
"""Verify knowledge docs reference valid MCP tool names."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"

VALID = {
    "analyze_repo",
    "http_probe",
    "record_finding",
    "export_report",
    "scope_check",
    "compare_role_response",
    "run_idor_matrix",
    "register_scope",
    "track_wstg_test",
    "track_probe_step",
    "rynix_plugin_run",
    "get_technique_guide",
    "get_wstg_test",
    "agent_engagement_playbook",
    "template-scan",
    "list_plugins",
    "plugin_health_check",
}

TOOL_REF = re.compile(r"`([a-z_]+)`")


def main() -> int:
    unknown: list[str] = []
    for path in KNOWLEDGE.rglob("*.md"):
        if "wstg" not in path.parts or path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "## Rynix workflow" not in text:
            unknown.append(f"{path.name}: missing Rynix workflow")
    if unknown:
        print(f"FAIL {len(unknown)} WSTG files missing workflow", file=sys.stderr)
        return 1
    print("PASS knowledge tool xref (WSTG workflows present)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
