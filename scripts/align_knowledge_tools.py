#!/usr/bin/env python3
"""Align knowledge role docs with real MCP tool names (Phase G)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"

REPLACEMENTS = [
    ("track_tool()", "track_probe_step"),
    ("track_tool(", "track_probe_step("),
    ("`track_tool`", "`track_probe_step`"),
    ("web_search", "get_technique_guide"),
    ("docker exec rynix-tools curl", "http_probe"),
    ("docker exec rynix-tools", "rynix_plugin_run('wstg')"),
    ("launch_background", "track_probe_step"),
]


def main() -> int:
    total = 0
    for path in KNOWLEDGE.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        updated = text
        for old, new in REPLACEMENTS:
            if old in updated:
                updated = updated.replace(old, new)
                total += 1
        if updated != text:
            path.write_text(updated, encoding="utf-8")
    print(f"aligned {total} patterns in knowledge docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
