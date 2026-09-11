#!/usr/bin/env python3
"""Phase I — attach GenAI 2026 enrichment blocks to relevant knowledge files."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
GENAI_DOC = "custom/genai_llm_security_2026.md"

BLOCK = """
## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.
"""

TECHNIQUES_DIR = KNOWLEDGE / "techniques"


def main() -> int:
    if not (KNOWLEDGE / GENAI_DOC).is_file():
        print(f"FAIL missing {GENAI_DOC}", file=__import__("sys").stderr)
        return 1

    updated = 0
    tech_dir = KNOWLEDGE / "techniques"
    wstg_dir = KNOWLEDGE / "wstg"
    for path in tech_dir.glob("*.md"):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        if "## GenAI / LLM 2026 notes" in text:
            continue
        path.write_text(text.rstrip() + BLOCK + "\n", encoding="utf-8")
        updated += 1

    for path in wstg_dir.rglob("WSTG-*.md"):
        text = path.read_text(encoding="utf-8")
        if "## GenAI / LLM 2026 notes" in text:
            continue
        path.write_text(text.rstrip() + BLOCK + "\n", encoding="utf-8")
        updated += 1

    print(f"genai enrichment applied to {updated} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
