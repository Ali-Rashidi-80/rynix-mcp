#!/usr/bin/env python3
"""Generate documentation statistics from repository sources."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


KNOWLEDGE_ROOT = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"


def count_vuln_classes() -> int:
    return len(list((KNOWLEDGE_ROOT / "vuln-classes").glob("*.md")))


def count_framework_guides() -> int:
    return len(list((KNOWLEDGE_ROOT / "frameworks").glob("*.md")))


def count_stacks() -> int:
    manifest = ROOT / "stacks" / "manifest.toml"
    text = manifest.read_text(encoding="utf-8")
    return len(re.findall(r"^\[\[stack\]\]", text, flags=re.MULTILINE))


def main() -> None:
    print(f"vuln_classes={count_vuln_classes()}")
    print(f"framework_guides={count_framework_guides()}")
    print(f"stacks={count_stacks()}")


if __name__ == "__main__":
    main()
