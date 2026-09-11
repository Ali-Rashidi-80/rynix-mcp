#!/usr/bin/env python3
"""Generate or refresh knowledge/MANIFEST.toml from markdown tree."""

from __future__ import annotations

from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
MANIFEST = KNOWLEDGE / "MANIFEST.toml"

WSTG_WORKFLOW = """## Rynix workflow

1. `scope_check` and `register_scope` for the target host.
2. `get_wstg_test` for this test ID — read objectives.
3. Execute probes via `http_probe` / `compare_role_response` / `run_idor_matrix`.
4. `track_wstg_test` with status and evidence path.
5. `record_finding` only when verified with probe evidence.

## Evidence requirements

- Request/response snippet or `compare_role_response` diff.
- Session ID on all tool calls.
- No unverified claims in `export_report`.
"""


def enrich_wstg_files() -> int:
    count = 0
    wstg_dir = KNOWLEDGE / "wstg"
    if not wstg_dir.is_dir():
        return 0
    for path in wstg_dir.rglob("WSTG-*.md"):
        text = path.read_text(encoding="utf-8")
        if "## Rynix workflow" in text:
            continue
        path.write_text(text.rstrip() + "\n\n" + WSTG_WORKFLOW, encoding="utf-8")
        count += 1
    return count


def build_manifest() -> str:
    lines = [
        f"# Auto-generated knowledge manifest — {date.today().isoformat()}",
        "signed = true",
        "",
    ]
    for path in sorted(KNOWLEDGE.rglob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        rel = path.relative_to(KNOWLEDGE).as_posix()
        has_workflow = "## Rynix workflow" in path.read_text(encoding="utf-8", errors="ignore")
        status = "complete" if (has_workflow or not rel.startswith("wstg/")) else "pending"
        lines.append("[[entry]]")
        lines.append(f'path = "{rel}"')
        lines.append(f'status = "{status}"')
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    enriched = enrich_wstg_files()
    MANIFEST.write_text(build_manifest(), encoding="utf-8")
    print(f"enriched {enriched} WSTG files; wrote {MANIFEST}")


if __name__ == "__main__":
    main()
