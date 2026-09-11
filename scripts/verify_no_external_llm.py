#!/usr/bin/env python3
"""Gate #3 — no external LLM API keys or subprocess LLM delegates."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PATTERNS = [
    r"OPENAI_API_KEY",
    r"ANTHROPIC_API_KEY",
    r"LITELLM",
    r"STRIX_LLM",
    r"requires_llm\s*=\s*true",
    r"strix_delegate",
    r"pentestkit_delegate",
    r"pentagi_delegate",
    r"browser-debug_delegate",
    r"run_strix_scan",
]

COMBINED = re.compile("|".join(f"({p})" for p in PATTERNS), re.IGNORECASE)
SKIP = {".git", ".venv", "target", "pentest_output", "__pycache__"}
SKIP_FILES = {"verify_no_external_llm.py", "HOST_AGENT_RUNTIME.md"}


def main() -> int:
    hits: list[str] = []
    for path in (ROOT / "mcp-server").rglob("*"):
        if not path.is_file():
            continue
        if any(s in SKIP for s in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() not in {".py", ".toml"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in COMBINED.finditer(text):
            hits.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    if hits:
        print(f"FAIL {len(hits)} external LLM hits:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        return 1
    print("PASS no external LLM")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
