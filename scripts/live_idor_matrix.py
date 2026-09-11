#!/usr/bin/env python3
"""
Live IDOR/RBAC matrix — credentials via environment ONLY.

  set RYNIX_TARGET_REPO=C:\\path\\to\\app
  set RYNIX_PROBE_BASE_URL=http://127.0.0.1:8001
  set RYNIX_PROBE_PASSWORD=<your-test-password>
  uv run --directory mcp-server python ..\\scripts\\live_idor_matrix.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))
sys.path.insert(0, str(ROOT / "scripts"))

from rynix_mcp.idor_matrix import run_idor_matrix
from target_env import engagement_profile, require_target_repo

BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
REPO = str(require_target_repo())
PROFILE = engagement_profile(require_target_repo())
SESSION = os.environ.get("RYNIX_IDOR_SESSION", "live-idor-matrix")


def main() -> int:
    result = run_idor_matrix(
        base_url=BASE,
        profile=PROFILE,
        repo_path=REPO,
        session_id=SESSION,
        allow_live=True,
    )
    if "error" in result:
        print(result["error"])
        return 1
    print(
        f"roles={result.get('roles_logged_in')} "
        f"comparisons={result.get('comparisons')} "
        f"signals={result.get('idor_signals')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
