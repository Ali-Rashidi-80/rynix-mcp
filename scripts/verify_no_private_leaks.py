#!/usr/bin/env python3

"""Gate #2 — no private paths or org names in tracked files."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


PATTERNS = [
    r"adlomid",
    r"Liquidglass",
    r"nellie",
    r"D:\\0\\",
    r"D:/0/",
    r"Users\\ICT",
    r"Liquidglasslegalerp",
    r"900100100[0-9]",
    r"chabokan",
    r"RYNIX_LEGAL_ERP",
    r"legal-erp",
    r"ADL_API",
    r"adl_api",
]


COMBINED = re.compile("|".join(f"({p})" for p in PATTERNS), re.IGNORECASE)

SKIP = {".git", ".venv", "target", "pentest_output", "__pycache__"}

ALLOWLIST_FILES = {
    "verify_no_private_leaks.py",
    "verify_github_publish_ready.py",
    "scrub_publish_leaks.py",
    "verify_zero_brands.py",
    "scrub_competitor_brands.py",
}


def main() -> int:
    hits: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue

        if any(s in SKIP for s in path.parts):
            continue

        if path.name in ALLOWLIST_FILES:
            continue

        if path.suffix.lower() not in {".md", ".py", ".rs", ".toml", ".json", ".yml", ".ps1"}:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")

        except OSError:
            continue

        for m in COMBINED.finditer(text):
            rel = path.relative_to(ROOT)

            hits.append(f"{rel}: {m.group(0)}")

    if hits:
        print(f"FAIL {len(hits)} private leak hits:", file=sys.stderr)

        for h in hits[:30]:
            print(f"  {h}", file=sys.stderr)

        return 1

    print("PASS no private leaks")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
