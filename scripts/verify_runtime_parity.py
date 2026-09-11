#!/usr/bin/env python3
"""Gate #11 — verify 9/9 runtime parity plugins have manifest + integration test."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
MATRIX = ROOT / "parity_matrix.toml"


def _load_matrix() -> list[dict[str, str]]:
    import tomllib

    data = tomllib.loads(MATRIX.read_text(encoding="utf-8"))
    return list(data.get("folder", []))


def main() -> int:
    if not MATRIX.is_file():
        print(f"FAIL missing {MATRIX}", file=sys.stderr)
        return 1

    entries = _load_matrix()
    if len(entries) != 9:
        print(f"FAIL expected 9 parity entries, got {len(entries)}", file=sys.stderr)
        return 1

    failed = 0
    for entry in entries:
        slug = entry["slug"]
        plugin = entry["rynix_plugin"]
        strategy = entry["strategy"]
        test_rel = entry["test"]
        manifest = ROOT / "plugins" / f"{plugin}.toml"
        test_path = MCP_SERVER / test_rel

        ok = manifest.is_file() and test_path.is_file()
        status = "PASS" if ok else "FAIL"
        print(f"{status} {slug} ({plugin}) — {strategy}")
        if not manifest.is_file():
            print(f"  missing manifest: {manifest}", file=sys.stderr)
            failed += 1
        if not test_path.is_file():
            print(f"  missing test: {test_path}", file=sys.stderr)
            failed += 1

    if failed:
        print(f"{failed} parity checks failed", file=sys.stderr)
        return 1

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/integration/"],
        cwd=str(MCP_SERVER),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        return proc.returncode

    print("9/9 runtime parity — OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
