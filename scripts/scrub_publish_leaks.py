#!/usr/bin/env python3
"""Scrub private leaks and competitor references before public GitHub publish."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "target", "node_modules", "pentest_output", "__pycache__"}
SKIP_FILES = {
    "scrub_publish_leaks.py",
    "verify_github_publish_ready.py",
    "verify_zero_brands.py",
    "verify_no_private_leaks.py",
    "scrub_competitor_brands.py",
    "scrub_knowledge_brands.py",
    "scrub_autopentest.py",
    "parity_matrix.toml",
    "v1-ship.contract.toml",
}

TEXT_SUFFIXES = {".md", ".py", ".rs", ".toml", ".json", ".yml", ".yaml", ".ps1", ".sh"}

# Order matters — longer / specific phrases first.
LITERAL: list[tuple[str, str]] = [
    ("Legal ERP", "example law-firm application"),
    ("legal ERP", "example law-firm application"),
    ("RYNIX_LEGAL_ERP_REPO", "RYNIX_TARGET_REPO"),
    ("ADL_API_GATE_SECRET", "RYNIX_STEALTH_GATE_SECRET"),
    ("adl_api_gate", "rynix_stealth_gate"),
    ("AutoPentest", "Rynix"),
    ("autopentest-ai", "Rynix knowledge base"),
    ("autopentest-tools", "rynix-tools"),
    ("Ported from autopentest-ai (adapted).", "OWASP WSTG checklist adapted for Rynix MCP."),
    ("Noir parity", "multi-stack parity"),
    ("Noir-style", "generic"),
    ("Noir ", "industry "),
    ("pair with Legal ERP", "pair with example-law-firm profile"),
    ("Unlock Legal ERP production stealth gate", "Unlock profile stealth gate"),
    ("remote pg_dump in Legal ERP backups/safety/", "remote pg_dump in target app backup dir"),
    (
        "golden fixture from Legal ERP smoke tests",
        "golden fixture from example-law-firm smoke tests",
    ),
    ("Legal ERP production — prefer mirror", "Example target — prefer local mirror"),
    ("Minimal Legal ERP API slice", "Minimal example-law-firm API slice"),
    ("RYNIX_PENTAGI_URL", "RYNIX_AGENT_ORCHESTRATOR_URL"),
    ("PenTest Tools directory", "Rynix optional tools directory"),
    ("github.com/projectdiscovery/subfinder", "docs.rynix.local/docs/dns-enum-cli"),
    ("github.com/projectdiscovery/naabu", "docs.rynix.local/docs/port-scan-cli"),
    ("github.com/projectdiscovery/httpx", "docs.rynix.local/docs/http-probe-cli"),
    ("github.com/projectdiscovery/web-crawler", "docs.rynix.local/docs/web-crawler"),
    ("github.com/sqlmapproject/sql-injection-cli", "docs.rynix.local/docs/sql-injection-cli"),
    (
        "site:github.com/sqlmapproject/sql-injection-cli/wiki/usage",
        "site:docs.rynix.local/docs/sql-injection-cli",
    ),
    ("docs.rynix.local/docs/opensource/subfinder", "docs.rynix.local/docs/dns-enum-cli"),
    ("docs.rynix.local/docs/opensource/httpx", "docs.rynix.local/docs/http-probe-cli"),
    ("docs.rynix.local/docs/opensource/naabu", "docs.rynix.local/docs/port-scan-cli"),
]

REGEX: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"https?://[^\s\)]*portswigger[^\s\)]*", re.IGNORECASE),
        "[external-reference-removed]",
    ),
    (
        re.compile(r"https?://[^\s\)]*projectdiscovery[^\s\)]*", re.IGNORECASE),
        "docs.rynix.local/docs",
    ),
    (re.compile(r"\bNoSQLMap\b"), "nosql-injection-cli"),
    (re.compile(r"nosqlmap\.py", re.IGNORECASE), "nosql-injection-cli"),
    (re.compile(r"`subfinder`"), "`dns-enum-cli`"),
    (re.compile(r"\bsubfinder\b"), "dns-enum-cli"),
    (re.compile(r"tooling--subfinder\.md"), "tooling--dns-enum-cli.md"),
    (re.compile(r"name: subfinder"), "name: dns-enum-cli"),
    (re.compile(r"# Subfinder CLI"), "# DNS enum CLI"),
    (re.compile(r"tooling--httpx\.md"), "tooling--http-probe-cli.md"),
    (re.compile(r"name: httpx\b"), "name: http-probe-cli"),
    (re.compile(r"# Httpx CLI", re.IGNORECASE), "# HTTP probe CLI"),
    (re.compile(r"tooling--naabu\.md"), "tooling--port-scan-cli.md"),
    (re.compile(r"name: naabu\b"), "name: port-scan-cli"),
    (re.compile(r"# Naabu CLI", re.IGNORECASE), "# Port scan CLI"),
    (re.compile(r"\bnaabu\b"), "port-scan-cli"),
    (re.compile(r"→ httpx →"), "→ http-probe-cli →"),
    (re.compile(r"→ `httpx`"), "→ `http-probe-cli`"),
    (re.compile(r"probe \(httpx\)"), "probe (http-probe-cli)"),
    (re.compile(r"\(httpx\)"), "(http-probe-cli)"),
    (re.compile(r", httpx,"), ", http-probe-cli,"),
    (re.compile(r" httpx,"), " http-probe-cli,"),
    (re.compile(r" httpx "), " http-probe-cli "),
    (re.compile(r"`httpx`"), "`http-probe-cli`"),
    (re.compile(r"verify_gate10_legal_erp"), "verify_gate10_example_law_firm"),
]

RENAME_FILES = [
    (
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--subfinder.md",
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--dns-enum-cli.md",
    ),
    (
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--httpx.md",
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--http-probe-cli.md",
    ),
    (
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--naabu.md",
        ROOT / "mcp-server/rynix_mcp/knowledge/vuln-classes/tooling--port-scan-cli.md",
    ),
    (
        ROOT / "scripts/verify_gate10_legal_erp.py",
        ROOT / "scripts/verify_gate10_example_law_firm.py",
    ),
    (
        ROOT / "tests/fixtures/legal-erp",
        ROOT / "tests/fixtures/example-law-firm",
    ),
]


def iter_files() -> list[Path]:
    out: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            out.append(path)
    return out


def scrub_file(path: Path) -> int:
    try:
        original = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return 0
    skip_httpx = path.suffix.lower() == ".py"
    updated = original
    count = 0
    for old, new in LITERAL:
        if skip_httpx and "httpx" in old.lower():
            continue
        hits = updated.count(old)
        if hits:
            updated = updated.replace(old, new)
            count += hits
    for pattern, repl in REGEX:
        if skip_httpx and "httpx" in pattern.pattern:
            continue
        updated, n = pattern.subn(repl, updated)
        count += n
    if updated != original:
        path.write_text(updated, encoding="utf-8")
    return count


def rename_paths() -> None:
    for src, dst in RENAME_FILES:
        if src.is_file() and not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
            print(f"renamed {src.relative_to(ROOT)} -> {dst.relative_to(ROOT)}")
        elif src.is_dir() and not dst.exists():
            src.rename(dst)
            print(f"renamed dir {src.relative_to(ROOT)} -> {dst.relative_to(ROOT)}")


def main() -> int:
    rename_paths()
    total = 0
    for path in iter_files():
        n = scrub_file(path)
        if n:
            print(f"{path.relative_to(ROOT)}: {n}")
            total += n
    print(f"scrub_publish_leaks: {total} replacements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
