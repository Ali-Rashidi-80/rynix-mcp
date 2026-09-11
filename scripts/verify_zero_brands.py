#!/usr/bin/env python3
"""Gate #1 — zero competitor brand strings in tracked source."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCAN_DIRS = (
    "mcp-server",
    "rynix-core/src",
    "plugins",
    "profiles",
    "scripts",
    "docs",
    "stacks",
    ".cursor",
    ".github",
    "templates",
    "examples",
    "tests",
)
SKIP_PARTS = {".git", ".venv", "target", "node_modules", "pentest_output", "__pycache__"}
SKIP_FILES = {
    "verify_zero_brands.py",
    "scrub_competitor_brands.py",
    "scrub_knowledge_brands.py",
    "parity_matrix.toml",
    "v1-ship.contract.toml",
    "scrub_publish_leaks.py",
    "verify_github_publish_ready.py",
    "verify_no_private_leaks.py",
    "final_verify.py",
    "scrub_autopentest.py",
}

# Competitor product names and domains (case-insensitive).
PATTERNS = [
    r"\bnuclei\b",
    r"\bstrix\b",
    r"\bpentestkit\b",
    r"\bshannon\b",
    r"\bpentagi\b",
    r"\bdark-?moon\b",
    r"\bdarkmoon\b",
    r"portswigger\.net",
    r"projectdiscovery\.io",
    r"sqlmap\.org",
    r"burpsuite",
    r"\bBurp\b",
    r"\bcorscanner\b",
    r"\bCORScanner\b",
    r"\bautopentest\b",
    r"AutoPentest",
    r"\bNoir\b",
    r"\bsubfinder\b",
    r"\bnaabu\b",
    r"RYNIX_LEGAL_ERP",
    r"RYNIX_PENTAGI",
    r"ADL_API",
    r"adl_api",
    r"projectdiscovery",
]

COMBINED = re.compile("|".join(f"({p})" for p in PATTERNS), re.IGNORECASE)


def iter_files() -> list[Path]:
    out: list[Path] = []
    for rel in SCAN_DIRS:
        base = ROOT / rel
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if "contracts" in path.parts:
                continue
            if path.name in SKIP_FILES:
                continue
            if path.suffix.lower() in {
                ".md",
                ".py",
                ".rs",
                ".toml",
                ".json",
                ".yml",
                ".yaml",
                ".ps1",
                ".sh",
            }:
                out.append(path)
    return out


def main() -> int:
    hits: list[str] = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in COMBINED.finditer(text):
            rel = path.relative_to(ROOT)
            hits.append(f"{rel}: {match.group(0)}")
    if hits:
        print(f"FAIL {len(hits)} competitor brand hits:", file=sys.stderr)
        for line in hits[:50]:
            print(f"  {line}", file=sys.stderr)
        if len(hits) > 50:
            print(f"  ... and {len(hits) - 50} more", file=sys.stderr)
        return 1
    print("PASS zero competitor brands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
