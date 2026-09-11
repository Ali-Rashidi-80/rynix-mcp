from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


def _validate_profile_name(name: str) -> None:

    if ".." in name or name.startswith(("/", "\\")):
        raise ValueError(f"invalid profile name: {name}")

    if not _NAME_RE.match(name):
        raise ValueError(f"invalid profile name: {name}")


def _resolve_profile_path(profiles_dir: Path, profile_name: str) -> Path:

    profiles_root = profiles_dir.resolve()

    bundled = (profiles_root / f"{profile_name}.toml").resolve()

    try:
        bundled.relative_to(profiles_root)

    except ValueError:
        raise ValueError(f"profile path escapes profiles_dir: {profile_name}") from None

    return bundled


_MERGEABLE_REPO_KEYS = frozenset({"auth", "paths", "brief"})
_REPO_RISK_ALLOW = frozenset({"extra_endpoints", "notes"})


def _filter_repo_profile_overrides(merged: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for k, v in merged.items():
        if k in _MERGEABLE_REPO_KEYS:
            safe[k] = v
        elif k == "risk" and isinstance(v, dict):
            safe["risk"] = {rk: rv for rk, rv in v.items() if rk in _REPO_RISK_ALLOW}
    return safe


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:

    out = dict(base)

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)

        else:
            out[key] = value

    return out


def load_profile(
    name: str | None, profiles_dir: Path, repo_path: Path | None = None
) -> dict[str, Any]:

    profile_name = name or "generic-fastapi-react"

    if name:
        _validate_profile_name(profile_name)

    bundled = _resolve_profile_path(profiles_dir, profile_name)

    fallback_from: str | None = None

    if not bundled.is_file():
        fallback_from = profile_name

        bundled = _resolve_profile_path(profiles_dir, "generic-fastapi-react")

    data: dict[str, Any] = {}

    if bundled.is_file():
        with bundled.open("rb") as f:
            data = tomllib.load(f)

        _validate_profile_shape(data)

    if fallback_from is not None:
        data["_profile_fallback_from"] = fallback_from

    if repo_path:
        override = repo_path / ".pentest" / "profile.toml"

        if override.is_file():
            with override.open("rb") as f:
                merged = tomllib.load(f)

            _validate_profile_shape(merged)

            safe = _filter_repo_profile_overrides(merged)
            data = _deep_merge(data, safe)

    return data


def _validate_profile_shape(data: dict[str, Any]) -> None:
    """R-59 — lightweight structural checks (no runtime jsonschema dependency)."""

    if not isinstance(data, dict):
        raise ValueError("profile must be a TOML table")

    name = data.get("name")

    if name is not None and not isinstance(name, str):
        raise ValueError("profile.name must be a string")

    scope = data.get("scope")

    if scope is not None and not isinstance(scope, dict):
        raise ValueError("profile.scope must be a table")

    if isinstance(scope, dict):
        hosts = scope.get("allow_hosts")

        if hosts is not None and not isinstance(hosts, list):
            raise ValueError("profile.scope.allow_hosts must be an array")

        cidrs = scope.get("allow_cidrs")

        if cidrs is not None and not isinstance(cidrs, list):
            raise ValueError("profile.scope.allow_cidrs must be an array")

    risk_kw = data.get("risk_keywords")

    if risk_kw is not None and not isinstance(risk_kw, dict):
        raise ValueError("profile.risk_keywords must be a table")


def list_profiles(profiles_dir: Path) -> list[dict[str, str]]:

    profiles: list[dict[str, str]] = []

    if not profiles_dir.is_dir():
        return profiles

    for path in sorted(profiles_dir.glob("*.toml")):
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)

        except (tomllib.TOMLDecodeError, OSError):
            continue

        profiles.append(
            {
                "name": data.get("name", path.stem),
                "display_name": data.get("display_name", path.stem),
                "stack": ",".join(data.get("stack", []))
                if isinstance(data.get("stack"), list)
                else "",
            }
        )

    return profiles


def resolve_profile_name(profile: str | None, repo_path: Path | None = None) -> str | None:
    """Pick profile: explicit arg → RYNIX_PROFILE env → target .pentest/profile.toml name."""
    if profile:
        return profile
    from rynix_mcp.target_repo import default_profile_name

    env_name = default_profile_name()
    if env_name:
        return env_name
    if repo_path:
        override = repo_path / ".pentest" / "profile.toml"
        if override.is_file():
            try:
                with override.open("rb") as f:
                    data = tomllib.load(f)
            except (tomllib.TOMLDecodeError, OSError):
                data = {}
            name = data.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    return None
