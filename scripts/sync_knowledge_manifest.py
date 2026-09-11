#!/usr/bin/env python3
"""Sync knowledge/MANIFEST.toml with on-disk markdown files."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
MANIFEST = KNOWLEDGE / "MANIFEST.toml"


def _parse_entries(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[entry]]":
            if current:
                entries.append(current)
            current = {}
        elif stripped.startswith("path = "):
            current["path"] = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("status = "):
            current["status"] = stripped.split("=", 1)[1].strip().strip('"')
    if current:
        entries.append(current)
    return entries


def _render(entries: list[dict[str, str]], signed: bool) -> str:
    lines = [
        "# Auto-generated knowledge manifest — synced from disk",
        f"signed = {'true' if signed else 'false'}",
        "",
    ]
    for entry in entries:
        lines.append("[[entry]]")
        lines.append(f'path = "{entry["path"]}"')
        lines.append(f'status = "{entry.get("status", "complete")}"')
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL missing {MANIFEST}", file=__import__("sys").stderr)
        return 1

    text = MANIFEST.read_text(encoding="utf-8")
    signed = "signed = true" in text
    entries = _parse_entries(text)
    by_path = {e["path"]: e for e in entries}

    # Phase C: ATTRIBUTION.md -> THIRD_PARTY.md
    if "ATTRIBUTION.md" in by_path:
        by_path.pop("ATTRIBUTION.md")
    if (KNOWLEDGE / "THIRD_PARTY.md").is_file():
        by_path.setdefault("THIRD_PARTY.md", {"path": "THIRD_PARTY.md", "status": "complete"})

    # Add every knowledge markdown except README stubs
    for path in sorted(KNOWLEDGE.rglob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        rel = path.relative_to(KNOWLEDGE).as_posix()
        if rel not in by_path:
            by_path[rel] = {"path": rel, "status": "complete"}

    ordered = sorted(by_path.values(), key=lambda e: e["path"])
    MANIFEST.write_text(_render(ordered, signed), encoding="utf-8")
    print(f"synced {len(ordered)} manifest entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
