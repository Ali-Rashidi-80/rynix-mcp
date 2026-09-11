#!/usr/bin/env python3
"""Phase I — add ASVS/CWE enrichment blocks to WSTG files missing them."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WSTG = ROOT / "mcp-server" / "rynix_mcp" / "knowledge" / "wstg"

BLOCK = """
## ASVS mapping

- V4 Access Control — verify role-appropriate responses for this test class.
- V13 API and Web Service — confirm authn/authz on affected endpoints.

## CWE references

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
"""


def main() -> int:
    updated = 0
    for path in WSTG.rglob("WSTG-*.md"):
        text = path.read_text(encoding="utf-8")
        if "## ASVS mapping" in text:
            continue
        if "## Rynix workflow" not in text:
            continue
        text = text.rstrip() + BLOCK + "\n"
        path.write_text(text, encoding="utf-8")
        updated += 1
    print(f"enriched {updated} WSTG files with ASVS/CWE blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
