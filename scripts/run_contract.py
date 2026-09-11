#!/usr/bin/env python3
"""Run docs/contracts/v1-ship.contract.toml evidence gates (G9)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
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


def run_shell(command: str) -> tuple[bool, str]:
    proc = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=300,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip()[:500]


def run_grep(pattern: str, paths: list[str], expect: str) -> tuple[bool, str]:
    regex = re.compile(pattern)
    hits: list[str] = []
    for rel in paths:
        base = ROOT / rel
        if base.is_file():
            text = base.read_text(encoding="utf-8", errors="ignore")
            if regex.search(text):
                hits.append(str(base))
        elif base.is_dir():
            for path in base.rglob("*"):
                if path.is_file() and path.suffix in {".py", ".rs", ".toml", ".md"}:
                    try:
                        if regex.search(path.read_text(encoding="utf-8", errors="ignore")):
                            hits.append(str(path))
                    except OSError:
                        continue
    if expect == "zero_matches":
        ok = len(hits) == 0
        return ok, f"hits={len(hits)} {hits[:3]}"
    return bool(hits), f"hits={len(hits)}"


def main() -> int:
    contract_path = ROOT / "docs" / "contracts" / "v1-ship.contract.toml"
    data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    evidence = data.get("evidence", [])
    failed: list[str] = []

    for item in evidence:
        eid = item.get("id", "?")
        kind = item.get("kind")
        ok = False
        detail = ""

        if kind == "shell":
            cmd = item["command"].replace(
                "uv run --directory mcp-server pytest", f'"{_python()}" -m pytest'
            )
            cmd = cmd.replace("python ", f'"{_python()}" ')
            ok, detail = run_shell(cmd)
        elif kind == "grep":
            ok, detail = run_grep(item["pattern"], item.get("paths", []), item.get("expect", ""))
        else:
            detail = f"unknown kind {kind}"
            ok = False

        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {eid}: {detail[:120]}")
        if not ok:
            failed.append(eid)

    if failed:
        print(f"Contract failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("Contract G9: all evidence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
