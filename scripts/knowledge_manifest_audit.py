#!/usr/bin/env python3
"""Gate #5 — knowledge MANIFEST.toml signed with zero pending entries."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
KNOWLEDGE = MCP_SERVER / "rynix_mcp" / "knowledge"
MANIFEST = KNOWLEDGE / "MANIFEST.toml"


def main() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL missing {MANIFEST}", file=sys.stderr)
        return 1

    sys.path.insert(0, str(MCP_SERVER))
    import tomllib

    from rynix_mcp.knowledge import (
        list_vuln_classes,
        techniques_topic_count,
        wstg_test_count,
    )

    data = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = data.get("entry", [])
    pending = [e for e in entries if e.get("status") == "pending"]
    wstg_count = wstg_test_count()
    technique_count = techniques_topic_count()
    vuln_count = len(list_vuln_classes())

    errors: list[str] = []
    if pending:
        errors.append(f"{len(pending)} pending manifest entries")
    if wstg_count < 109:
        errors.append(f"WSTG count {wstg_count} < 109")
    if technique_count < 25:
        errors.append(f"techniques count {technique_count} < 25")
    if vuln_count < 50:
        errors.append(f"vuln-class catalog count {vuln_count} < 50")
    if not data.get("signed"):
        errors.append("manifest not signed")

    listed_paths = {e.get("path", "") for e in entries}
    for rel in listed_paths:
        if rel and not (KNOWLEDGE / rel).is_file():
            errors.append(f"manifest lists missing file: {rel}")

    on_disk = {
        p.relative_to(KNOWLEDGE).as_posix()
        for p in KNOWLEDGE.rglob("*.md")
        if p.name.lower() != "readme.md"
    }
    unlisted = sorted(on_disk - listed_paths)
    if unlisted:
        errors.append(
            f"{len(unlisted)} markdown files not in manifest (run sync_knowledge_manifest.py)"
        )
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        return 1

    print(f"PASS knowledge manifest ({len(entries)} entries, WSTG={wstg_count})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
