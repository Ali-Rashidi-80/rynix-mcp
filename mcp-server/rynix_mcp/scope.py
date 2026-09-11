"""Per-repo scope permissions (rynix.scope.toml) — deny-by-default live probes when configured."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


def _coerce_bool(value: Any) -> bool | None:

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        lowered = value.strip().lower()

        if lowered in ("false", "0", "no", "off", ""):
            return False

        if lowered in ("true", "1", "yes", "on"):
            return True

    return None


def load_repo_scope(repo_path: Path | None) -> dict[str, Any]:

    if repo_path is None:
        return {}

    for candidate in (
        repo_path / "rynix.scope.toml",
        repo_path / ".pentest" / "rynix.scope.toml",
    ):
        if candidate.is_file():
            try:
                with candidate.open("rb") as f:
                    data = tomllib.load(f)

            except (tomllib.TOMLDecodeError, OSError):
                return {"permissions": {"live_probe": False}, "_parse_error": True}

            return data if isinstance(data, dict) else {"permissions": {"live_probe": False}}

    return {}


def live_probe_allowed(
    repo_path: Path | None,
    allow_live: bool = False,
) -> tuple[bool, str]:
    """When rynix.scope.toml sets live_probe=false, require allow_live=true on probe tools."""

    if allow_live:
        return True, "allow_live=true"

    scope = load_repo_scope(repo_path)

    if scope.get("_parse_error"):
        return False, "rynix.scope.toml: parse error — live probes denied (fail-closed)"

    perms = scope.get("permissions", {})

    if isinstance(perms, dict) and "live_probe" in perms:
        coerced = _coerce_bool(perms.get("live_probe"))

        if coerced is False:
            return False, "rynix.scope.toml: live_probe=false — pass allow_live=true to probe"

    return True, "live_probe allowed"
