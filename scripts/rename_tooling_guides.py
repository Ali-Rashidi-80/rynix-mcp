#!/usr/bin/env python3
"""Phase C — rename tooling guides to Rynix-neutral names."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
MANIFEST = KNOWLEDGE / "MANIFEST.toml"

RENAMES = {
    "tooling--sqlmap.md": "tooling--sql-injection-cli.md",
    "tooling--katana.md": "tooling--web-crawler.md",
    "tooling--ffuf.md": "tooling--fuzz-cli.md",
}

CONTENT_REPLACEMENTS = [
    (r"\bsqlmap\b", "sql-injection-cli"),
    (r"\bkatana\b", "web-crawler"),
    (r"\bffuf\b", "fuzz-cli"),
    (r"\bwhatweb\b", "tech-fingerprint-cli"),
]


def main() -> int:
    vuln = KNOWLEDGE / "vuln-classes"
    for old, new in RENAMES.items():
        src = vuln / old
        dst = vuln / new
        if src.is_file() and not dst.is_file():
            text = src.read_text(encoding="utf-8")
            for pattern, repl in CONTENT_REPLACEMENTS:
                text = re.sub(pattern, repl, text, flags=re.IGNORECASE)
            dst.write_text(text, encoding="utf-8")
            src.unlink()
            print(f"renamed {old} -> {new}")

    if MANIFEST.is_file():
        text = MANIFEST.read_text(encoding="utf-8")
        for old, new in RENAMES.items():
            text = text.replace(old, new)
        for pattern, repl in CONTENT_REPLACEMENTS:
            text = re.sub(pattern, repl, text, flags=re.IGNORECASE)
        MANIFEST.write_text(text, encoding="utf-8")

    for md in KNOWLEDGE.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        updated = text
        for pattern, repl in CONTENT_REPLACEMENTS:
            updated = re.sub(pattern, repl, updated, flags=re.IGNORECASE)
        if updated != text:
            md.write_text(updated, encoding="utf-8")

    print("tooling rename scrub complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
