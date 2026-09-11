"""G4 MCP self-audit gate — pytest substitute when Inspector unavailable."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_mcp_self_audit_pytest_gate():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "mcp_self_audit.py")],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
