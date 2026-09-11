#!/usr/bin/env python3
"""Gate #6b — knowledge enrichment coverage for techniques and frameworks."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
TECHNIQUES = KNOWLEDGE / "techniques"
FRAMEWORKS = KNOWLEDGE / "frameworks"
WSTG = KNOWLEDGE / "wstg"

MIN_FRAMEWORK_LINES = 90
GENAI_DOC = KNOWLEDGE / "custom" / "genai_llm_security_2026.md"
REQUIRED_TECHNIQUE_SECTIONS = (
    "## Rynix workflow",
    "## Evidence requirements",
    "## ASVS mapping",
    "## Rynix tooling",
)
REQUIRED_WSTG_SECTIONS = (
    "## Rynix workflow",
    "## Evidence requirements",
    "## ASVS mapping",
    "## Rynix tooling",
    "## Test focus",
)
FRAMEWORK_REQUIRED_SECTION = "## Stack-specific probe matrix"
PRESERVED_DEEP = {"django.md", "fastapi.md", "nestjs.md", "nextjs.md"}


def main() -> int:
    errors: list[str] = []

    if not GENAI_DOC.is_file():
        errors.append("missing custom/genai_llm_security_2026.md")

    llm = KNOWLEDGE / "techniques" / "web-llm-attacks.md"
    if llm.is_file() and "## GenAI / LLM 2026 notes" not in llm.read_text(encoding="utf-8"):
        errors.append("web-llm-attacks missing GenAI 2026 block")

    wstg_files = list((KNOWLEDGE / "wstg").rglob("WSTG-*.md"))
    genai_missing = sum(
        1 for p in wstg_files if "## GenAI / LLM 2026 notes" not in p.read_text(encoding="utf-8")
    )
    if genai_missing:
        errors.append(f"{genai_missing} WSTG files missing GenAI 2026 block")

    for path in TECHNIQUES.glob("*.md"):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        for section in REQUIRED_TECHNIQUE_SECTIONS:
            if section not in text:
                errors.append(f"technique {path.name} missing {section}")

    for path in FRAMEWORKS.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if len(lines) < MIN_FRAMEWORK_LINES:
            errors.append(
                f"framework {path.name} only {len(lines)} lines (min {MIN_FRAMEWORK_LINES})"
            )
        if path.name not in PRESERVED_DEEP and FRAMEWORK_REQUIRED_SECTION not in text:
            errors.append(f"framework {path.name} missing {FRAMEWORK_REQUIRED_SECTION}")

    wstg_files = list(WSTG.rglob("WSTG-*.md"))
    for path in wstg_files:
        text = path.read_text(encoding="utf-8")
        for section in REQUIRED_WSTG_SECTIONS:
            if section not in text:
                errors.append(f"wstg {path.name} missing {section}")

    if errors:
        for e in errors[:40]:
            print(f"FAIL {e}", file=sys.stderr)
        if len(errors) > 40:
            print(f"  ... and {len(errors) - 40} more", file=sys.stderr)
        return 1

    print(
        f"PASS knowledge enrichment "
        f"(techniques={len(list(TECHNIQUES.glob('*.md'))) - 1}, "
        f"frameworks={len(list(FRAMEWORKS.glob('*.md')))}, "
        f"wstg={len(wstg_files)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
