#!/usr/bin/env python3
"""Phase K — optional live IDOR smoke for CI (requires RYNIX_PROBE_BASE_URL)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
VENV_PY_WIN = MCP / ".venv" / "Scripts" / "python.exe"
VENV_PY_POSIX = MCP / ".venv" / "bin" / "python"


def _python() -> str:
    venv_env = os.environ.get("VIRTUAL_ENV")
    if venv_env:
        v_win = Path(venv_env) / "Scripts" / "python.exe"
        v_posix = Path(venv_env) / "bin" / "python"
        if v_win.is_file():
            return str(v_win)
        if v_posix.is_file():
            return str(v_posix)
    if VENV_PY_WIN.is_file():
        return str(VENV_PY_WIN)
    if VENV_PY_POSIX.is_file():
        return str(VENV_PY_POSIX)
    return str(Path(sys.executable))


PY = _python()


def main() -> int:
    base = os.environ.get("RYNIX_PROBE_BASE_URL", "").strip()
    if not base:
        print("SKIP live smoke — RYNIX_PROBE_BASE_URL not set")
        return 0

    env = os.environ.copy()
    env.setdefault("RYNIX_GATE10_LIVE", "1")
    env.setdefault("RYNIX_PROBE_PROFILE", "example-law-firm")
    env.setdefault("RYNIX_TARGET_REPO", env.get("RYNIX_TARGET_REPO", str(ROOT)))

    steps = [
        ([str(PY), str(ROOT / "scripts" / "verify_gate10_example_law_firm.py")], ROOT),
        ([str(PY), str(ROOT / "scripts" / "run_example_law_firm_live_engagement.py")], ROOT),
        (
            [str(PY), "-m", "pytest", "-q", "tests/test_live_e2e_optional.py"],
            ROOT / "mcp-server",
        ),
    ]

    for cmd, cwd in steps:
        proc = subprocess.run(cmd, cwd=str(cwd), env=env)
        if proc.returncode != 0:
            print(f"FAIL live smoke: {cmd} exit={proc.returncode}", file=sys.stderr)
            return proc.returncode

    print("PASS live IDOR smoke (gate10 + engagement + e2e optional)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
