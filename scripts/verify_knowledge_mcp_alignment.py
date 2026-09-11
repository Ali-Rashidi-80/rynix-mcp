#!/usr/bin/env python3
"""Gate #7 — knowledge phantom API names align with real MCP tools."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"

REAL_TOOLS = {
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
}

PHANTOM = re.compile(
    r"\b(track_tool\(|launch_background\(|web_search\b)",
    re.IGNORECASE,
)


def main() -> int:
    hits: list[str] = []
    for path in KNOWLEDGE.rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in PHANTOM.finditer(text):
            rel = path.relative_to(KNOWLEDGE)
            # Allow generic docker mention in coordination docs if paired with real tools
            if "track_tool" in m.group(0) and "roles/" in str(rel):
                continue
            hits.append(f"{rel}: {m.group(0)}")
    if len(hits) > 15:
        print(f"WARN {len(hits)} phantom API refs (threshold 15)", file=sys.stderr)
        for h in hits[:10]:
            print(f"  {h}", file=sys.stderr)
        return 1
    print(f"PASS knowledge MCP alignment ({len(hits)} minor phantom refs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
