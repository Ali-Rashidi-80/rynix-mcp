#!/usr/bin/env python3
"""QA gateway — ruff, mypy, pylint, compileall, pytest, rust."""

from __future__ import annotations

import compileall
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
RYNIX_CORE = ROOT / "rynix-core"
VENV_PY_WIN = MCP / ".venv" / "Scripts" / "python.exe"
VENV_PY_POSIX = MCP / ".venv" / "bin" / "python"


def _resolve_py() -> str:
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


PY = _resolve_py()
SCRIPTS_RUFF = str(ROOT / "scripts" / "ruff.toml")


def run(name: str, cmd: list[str], cwd: Path | None = None) -> int:
    proc = subprocess.run(cmd, cwd=str(cwd or ROOT))
    status = "PASS" if proc.returncode == 0 else "FAIL"
    print(f"[{status}] {name}")
    return proc.returncode


def main() -> int:
    failed: list[str] = []

    checks: list[tuple[str, list[str], Path | None]] = [
        ("ruff-format-mcp", [PY, "-m", "ruff", "format", "rynix_mcp", "tests"], MCP),
        (
            "ruff-format-scripts",
            [PY, "-m", "ruff", "format", "--config", SCRIPTS_RUFF, "scripts"],
            ROOT,
        ),
        ("ruff-check-mcp", [PY, "-m", "ruff", "check", "rynix_mcp", "tests"], MCP),
        (
            "ruff-check-scripts",
            [PY, "-m", "ruff", "check", "--config", SCRIPTS_RUFF, "scripts"],
            ROOT,
        ),
        ("mypy", [PY, "-m", "mypy"], MCP),
        ("pylint", [PY, "-m", "pylint", "rynix_mcp"], MCP),
        ("cargo-build-release", ["cargo", "build", "--release", "-q"], RYNIX_CORE),
        ("pytest", [PY, "-m", "pytest", "-q"], MCP),
        ("rust-test", ["cargo", "test", "-q"], RYNIX_CORE),
    ]

    for name, cmd, cwd in checks:
        if run(name, cmd, cwd) != 0:
            failed.append(name)

    compile_ok = compileall.compile_dir(
        str(MCP / "rynix_mcp"),
        quiet=1,
        force=True,
    ) and compileall.compile_dir(str(ROOT / "scripts"), quiet=1, force=True)
    print(f"[{'PASS' if compile_ok else 'FAIL'}] compileall")
    if not compile_ok:
        failed.append("compileall")

    if failed:
        print(f"run_qa failed: {', '.join(failed)}", file=sys.stderr)
        return 1

    print("run_qa: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
