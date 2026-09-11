#!/usr/bin/env python3
"""Gate — public GitHub publish readiness (brands, private leaks, competitor URLs)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "target", "node_modules", "pentest_output", "__pycache__"}
SKIP_FILES = {
    "verify_github_publish_ready.py",
    "verify_zero_brands.py",
    "verify_no_private_leaks.py",
    "scrub_competitor_brands.py",
    "scrub_knowledge_brands.py",
    "scrub_publish_leaks.py",
    "scrub_autopentest.py",
    "parity_matrix.toml",
    "v1-ship.contract.toml",
    "final_verify.py",
    "verify_gate10_example_law_firm.py",
    "install-template-scan.ps1",
}
TEXT_SUFFIXES = {".md", ".py", ".rs", ".toml", ".json", ".yml", ".yaml", ".ps1", ".sh"}

BRAND_PATTERNS = [
    r"\bnuclei\b",
    r"\bstrix\b",
    r"\bpentestkit\b",
    r"\bshannon\b",
    r"\bpentagi\b",
    r"\bdark-?moon\b",
    r"\bdarkmoon\b",
    r"portswigger",
    r"projectdiscovery",
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
    r"legal-erp",
    r"legal_erp",
    r"RYNIX_LEGAL_ERP",
    r"RYNIX_PENTAGI",
    r"ADL_API",
    r"adl_api",
    r"Liquidglass",
    r"adlomid",
    r"nellie",
    r"NoSQLMap",
]

PRIVATE_PATTERNS = [
    r"D:\\0\\",
    r"D:/0/",
    r"Users\\ICT",
    r"Liquidglasslegalerp",
    r"900100100[0-9]",
    r"chabokan",
]

# httpx CLI brand in docs only — Python `import httpx` is allowed in .py
CLI_TOOL_IN_DOCS = re.compile(r"`httpx`|(?<![./])\bhttpx\b(?!\.)", re.IGNORECASE)

URL_PATTERNS = [
    r"https?://[^\s\)]*portswigger[^\s\)]*",
    r"https?://[^\s\)]*projectdiscovery[^\s\)]*",
    r"https?://github\.com/projectdiscovery[^\s\)]*",
    r"https?://github\.com/sqlmapproject[^\s\)]*",
]


def iter_files() -> list[Path]:
    out: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if "contracts" in path.parts and path.name == "v1-ship.contract.toml":
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            out.append(path)
    return out


def main() -> int:
    brand_re = re.compile("|".join(f"({p})" for p in BRAND_PATTERNS), re.IGNORECASE)
    private_re = re.compile("|".join(f"({p})" for p in PRIVATE_PATTERNS), re.IGNORECASE)
    url_res = [re.compile(p, re.IGNORECASE) for p in URL_PATTERNS]

    hits: list[str] = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(ROOT)

        for m in brand_re.finditer(text):
            hits.append(f"brand {rel}: {m.group(0)}")

        for m in private_re.finditer(text):
            hits.append(f"private {rel}: {m.group(0)}")

        for url_re in url_res:
            for m in url_re.finditer(text):
                hits.append(f"url {rel}: {m.group(0)[:80]}")

        if path.suffix.lower() == ".md" and path.name != "pyproject.toml":
            for m in CLI_TOOL_IN_DOCS.finditer(text):
                hits.append(f"cli-brand {rel}: {m.group(0)}")

    if hits:
        print(f"FAIL {len(hits)} publish-readiness hits:", file=sys.stderr)
        for line in hits[:60]:
            print(f"  {line}", file=sys.stderr)
        if len(hits) > 60:
            print(f"  ... and {len(hits) - 60} more", file=sys.stderr)
        return 1

    print(f"PASS github publish ready ({len(iter_files())} files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
