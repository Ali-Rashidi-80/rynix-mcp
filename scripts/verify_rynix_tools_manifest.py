#!/usr/bin/env python3
"""Gate — docker/rynix-tools must ship >= 25 generic CLIs."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "docker" / "rynix-tools" / "bin"
MANIFEST = ROOT / "docker" / "rynix-tools" / "tools-manifest.toml"
MIN_TOOLS = 25


def main() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL missing {MANIFEST}", file=sys.stderr)
        return 1
    tools = [p for p in BIN.iterdir() if p.is_file() and not p.name.startswith(".")]
    if len(tools) < MIN_TOOLS:
        print(f"FAIL {len(tools)} tools < {MIN_TOOLS}", file=sys.stderr)
        return 1
    print(f"PASS rynix-tools ({len(tools)} CLIs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
