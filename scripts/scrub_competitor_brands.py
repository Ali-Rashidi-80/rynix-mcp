#!/usr/bin/env python3
"""Scrub competitor brand strings from tracked files (Phase C)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "target", "node_modules", "pentest_output", "__pycache__"}
SKIP_FILES = {"verify_zero_brands.py", "scrub_competitor_brands.py", "parity_matrix.toml"}

# Case-insensitive regex replacements
REGEX_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"RYNIX_NUCLEI_BIN", re.IGNORECASE), "RYNIX_TEMPLATE_SCAN_BIN"),
    (re.compile(r"install-nuclei\.ps1", re.IGNORECASE), "install-template-scan.ps1"),
    (re.compile(r"resolve_nuclei_bin", re.IGNORECASE), "resolve_template_scan_bin"),
    (re.compile(r"\bnuclei\b", re.IGNORECASE), "template-scan"),
    (re.compile(r"\bstrix\b", re.IGNORECASE), "agent-guides"),
    (re.compile(r"\bpentestkit\b", re.IGNORECASE), "engagement"),
    (re.compile(r"\bshannon\b", re.IGNORECASE), "sarif-import"),
    (re.compile(r"\bpentagi\b", re.IGNORECASE), "agent-orchestrator"),
    (re.compile(r"dark-?moon", re.IGNORECASE), "browser-debug"),
    (re.compile(r"legal-erp", re.IGNORECASE), "example-law-firm"),
    (re.compile(r"portswigger", re.IGNORECASE), "techniques"),
    (re.compile(r"projectdiscovery\.io", re.IGNORECASE), "rynix.local/docs"),
    (re.compile(r"autopentest-tools", re.IGNORECASE), "rynix-tools"),
    (re.compile(r"RYNIX_PENTEST_TOOLS_ROOT", re.IGNORECASE), "RYNIX_TOOLS_ROOT"),
    (
        re.compile(r"https?://[^\s\)]*portswigger[^\s\)]*", re.IGNORECASE),
        "[external-reference-removed]",
    ),
]

LITERAL_REPLACEMENTS = [
    ("bin/nuclei.exe", "bin/template-scan"),
    ("bin/nuclei", "bin/template-scan"),
    ("tools/nuclei/", "tools/template-scan/"),
    ("knowledge/portswigger", "knowledge/techniques"),
]


def scrub_file(path: Path) -> int:
    try:
        original = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return 0
    updated = original
    count = 0
    for old, new in LITERAL_REPLACEMENTS:
        hits = updated.count(old)
        if hits:
            updated = updated.replace(old, new)
            count += hits
    for pattern, repl in REGEX_REPLACEMENTS:
        updated, n = pattern.subn(repl, updated)
        count += n
    if updated != original:
        path.write_text(updated, encoding="utf-8")
    return count


def main() -> int:
    total = 0
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(s in SKIP_PARTS for s in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() not in {
            ".md",
            ".py",
            ".rs",
            ".toml",
            ".json",
            ".ps1",
            ".sh",
            ".yml",
        }:
            continue
        n = scrub_file(path)
        if n:
            print(f"{path.relative_to(ROOT)}: {n}")
            total += n
    print(f"scrubbed {total} replacements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
