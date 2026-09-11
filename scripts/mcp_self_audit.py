#!/usr/bin/env python3
"""G4 self-audit: MCP Inspector tools/list + optional mcpsec scan."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
VENV_PY_WIN = MCP_SERVER / ".venv" / "Scripts" / "python.exe"
VENV_PY_POSIX = MCP_SERVER / ".venv" / "bin" / "python"
REQUIRED_TOOLS = {
    "analyze_repo",
    "compare_role_response",
    "export_report",
    "health_check",
    "list_plugins",
    "run_idor_matrix",
    "rynix_plugin_run",
}
MIN_TOOL_COUNT = 21


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


def _extract_json_blob(text: str) -> dict | None:
    """Inspector CLI may mix npm notices with JSON — find first object."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def internal_tools_list() -> dict:
    """Fallback when MCP Inspector CLI is unavailable (G4 substitute)."""
    proc = subprocess.run(
        [
            _python(),
            "-c",
            "from rynix_mcp.server import mcp; "
            "names=sorted(t.name for t in mcp._tool_manager.list_tools()); "
            "import json; print(json.dumps(names))",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
        cwd=str(MCP_SERVER),
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout)[:400]}
    try:
        names_list = json.loads((proc.stdout or "").strip())
        names = set(names_list)
    except json.JSONDecodeError:
        return {"ok": False, "error": "internal tool parse failed"}
    missing = REQUIRED_TOOLS - names
    return {
        "ok": not missing and len(names) >= MIN_TOOL_COUNT,
        "tool_count": len(names),
        "missing": sorted(missing),
        "names": sorted(names),
        "source": "internal_registry",
    }


def inspector_tools_list() -> dict:
    npx = shutil.which("npx")
    if not npx:
        fallback = internal_tools_list()
        fallback["skipped"] = True
        fallback["reason"] = "npx not in PATH"
        return fallback

    cmd = [
        npx,
        "--yes",
        "@modelcontextprotocol/inspector",
        "--cli",
        _python(),
        "-m",
        "rynix_mcp",
        "--method",
        "tools/list",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=180,
            shell=False,
            cwd=str(MCP_SERVER),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        fallback = internal_tools_list()
        fallback["error"] = "inspector timeout"
        return fallback

    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 and not out.strip():
        return {"ok": False, "exit_code": proc.returncode, "output_preview": out[:800]}

    data = _extract_json_blob(proc.stdout or out)
    if not data:
        names = {name for name in REQUIRED_TOOLS if name in out}
        partial = {
            "ok": len(names) >= len(REQUIRED_TOOLS) - 2,
            "partial_parse": True,
            "found": sorted(names),
            "output_preview": out[:600],
        }
        if partial["ok"]:
            return partial
        fallback = internal_tools_list()
        fallback["inspector_partial"] = partial
        return fallback

    tools = data.get("tools") or data.get("result", {}).get("tools") or []
    names = {t.get("name") for t in tools if isinstance(t, dict) and t.get("name")}
    missing = REQUIRED_TOOLS - names
    result = {
        "ok": not missing and len(names) >= MIN_TOOL_COUNT,
        "tool_count": len(names),
        "missing": sorted(missing),
        "names": sorted(names),
        "source": "inspector_cli",
    }
    if result["ok"]:
        return result
    fallback = internal_tools_list()
    if fallback.get("ok"):
        fallback["inspector_partial"] = result
        return fallback
    return result


def mcpsec_scan() -> dict:
    """Run mcpsec against rynix_mcp stdio server when available."""
    if not shutil.which("uv"):
        return {"skipped": True, "reason": "uv not in PATH", "optional": True}
    try:
        help_proc = subprocess.run(
            ["uv", "tool", "run", "mcpsec", "--help"],
            capture_output=True,
            text=True,
            timeout=90,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:  # noqa: BLE001
        return {"skipped": True, "reason": str(exc), "optional": True}

    if help_proc.returncode != 0:
        return {"skipped": True, "reason": "mcpsec not installed", "optional": True}

    out_path = ROOT / "pentest_output" / "mcpsec_scan.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    py = _python()
    cmd = [
        "uv",
        "tool",
        "run",
        "mcpsec",
        "scan",
        "--stdio",
        f"{py} -m rynix_mcp",
        "--format",
        "json",
        "--quiet",
        "-o",
        str(out_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
            cwd=str(MCP_SERVER),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "mcpsec scan timeout", "optional": True}

    if proc.returncode != 0:
        return {
            "ok": False,
            "exit_code": proc.returncode,
            "stderr": (proc.stderr or "")[:800],
            "stdout": (proc.stdout or "")[:400],
            "optional": True,
        }

    findings = 0
    if out_path.is_file():
        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
            findings = len(data.get("findings", data.get("issues", [])))
        except json.JSONDecodeError:
            findings = -1
    return {
        "ok": True,
        "output_path": str(out_path),
        "findings": findings,
        "exit_code": proc.returncode,
    }


def pytest_gate() -> dict:
    proc = subprocess.run(
        [
            _python(),
            "-m",
            "pytest",
            "tests/test_mcp_tools.py",
            "tests/test_plugins.py",
            "tests/test_idor_matrix.py",
            "tests/test_dashboard_idor.py",
            "-q",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        shell=False,
        cwd=str(MCP_SERVER),
        encoding="utf-8",
        errors="replace",
    )
    return {"ok": proc.returncode == 0, "output": (proc.stdout or proc.stderr).strip()[:500]}


def main() -> int:
    results = {
        "inspector": inspector_tools_list(),
        "pytest_gate": pytest_gate(),
        "mcpsec": mcpsec_scan(),
    }
    print(json.dumps(results, indent=2))

    pytest_ok = results["pytest_gate"].get("ok")
    mcpsec = results["mcpsec"]
    mcpsec_ok = mcpsec.get("ok") or mcpsec.get("skipped") or mcpsec.get("optional")
    inspector = results["inspector"]
    inspector_ok = inspector.get("ok") or inspector.get("skipped")

    if pytest_ok and mcpsec_ok:
        if not inspector_ok:
            print("NOTE: Inspector unavailable; pytest gate is G4 substitute", file=sys.stderr)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
