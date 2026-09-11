#!/usr/bin/env python3
"""Gate #10 — example-law-firm fixture scan + IDOR matrix smoke (offline-safe)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
VENV_PY_WIN = MCP / ".venv" / "Scripts" / "python.exe"
VENV_PY_POSIX = MCP / ".venv" / "bin" / "python"
EXAMPLE = ROOT / "examples" / "example-law-firm"
GOLDEN = ROOT / "tests" / "golden" / "example-law-firm-fixture-scan.json"


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


def main() -> int:
    py = _python()
    inner = (
        r'''
import json, sys
from pathlib import Path
from unittest.mock import patch
ROOT = Path(r"""'''
        + str(ROOT).replace("\\", "\\\\")
        + r'''""")
sys.path.insert(0, str(ROOT / "mcp-server"))
from rynix_mcp.config import resolve_scanner_bin
from rynix_mcp.scanner import run_scan
from rynix_mcp.idor_matrix import run_idor_matrix
from rynix_mcp.session import STORE

EXAMPLE = ROOT / "examples" / "example-law-firm"
GOLDEN = ROOT / "tests" / "golden" / "example-law-firm-fixture-scan.json"

def _fake_login(base_url, username, password, profile=None, role_label=None, session_id=None, **kwargs):
    session = STORE.get(session_id)
    session.tokens[role_label or username] = f"token-{role_label}"
    return {"token_preview": "...abcd", "role_label": role_label}

if not EXAMPLE.is_dir():
    print("SKIP example-law-firm fixture missing")
    sys.exit(0)
bin_path = resolve_scanner_bin()
if not bin_path.is_file():
    print(f"FAIL scanner missing: {bin_path}", file=sys.stderr)
    sys.exit(1)
scan = run_scan(EXAMPLE, "example-law-firm")
if not scan.get("routes"):
    print("FAIL fixture scan returned zero routes", file=sys.stderr)
    sys.exit(1)
if GOLDEN.is_file():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8-sig"))
    gk = {(r.get("method"), r.get("path"), r.get("file")) for r in golden.get("routes", [])}
    sk = {(r.get("method"), r.get("path"), r.get("file")) for r in scan.get("routes", [])}
    if gk and gk != sk:
        print(f"FAIL golden route mismatch golden={len(gk)} scan={len(sk)}", file=sys.stderr)
        sys.exit(1)
import rynix_mcp.server
with (
    patch.dict("os.environ", {"RYNIX_PROBE_PASSWORD":"x","RYNIX_PROBE_PASSWORD_CEO":"y","RYNIX_PROBE_USER_CLIENT":"client-user","RYNIX_PROBE_USER_LAWYER":"lawyer-user"}),
    patch("rynix_mcp.http_session.ensure_stealth_gate", return_value=True),
    patch("rynix_mcp.server.export_report", return_value={"json_path":"/tmp/f.json"}),
    patch("rynix_mcp.server.compare_role_response", return_value={"verdict":"no_signal","idor_likely":False}),
    patch("rynix_mcp.server.auth_login", side_effect=_fake_login),
    patch("rynix_mcp.server.scope_check", return_value={"allowed":True}),
):
    result = run_idor_matrix("http://127.0.0.1:8001", profile="example-law-firm", roles=["client","lawyer"], session_id="gate10-smoke")
if result.get("error"):
    print(f"FAIL idor matrix: {result['error']}", file=sys.stderr)
    sys.exit(1)
if result.get("idor_signals", 99) != 0:
    print(f"FAIL idor_signals={result.get('idor_signals')}", file=sys.stderr)
    sys.exit(1)
if result.get("comparisons", 0) <= 0:
    print("FAIL zero comparisons", file=sys.stderr)
    sys.exit(1)
print(f"PASS gate10 routes={len(scan.get('routes',[]))} comparisons={result['comparisons']}")
'''
    )
    proc = subprocess.run([py, "-c", inner], cwd=str(ROOT), text=True)
    if proc.returncode != 0:
        return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
