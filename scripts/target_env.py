"""Shared bootstrap for operator scripts under scripts/."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from rynix_mcp.profiles import resolve_profile_name
from rynix_mcp.target_repo import (
    default_profile_name,
    target_repo_path,
)


def require_target_repo() -> Path:
    path = target_repo_path(required=True)
    assert path is not None
    return path


def engagement_profile(repo: Path | None = None) -> str | None:
    return resolve_profile_name(default_profile_name(), repo or target_repo_path(required=False))
