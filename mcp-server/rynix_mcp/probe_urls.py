"""Central extraction and scope validation for URL-bearing probe parameters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rynix_mcp.config import PROFILES_DIR, SCOPE_ALLOWLIST_ENV
from rynix_mcp.options_util import parse_options
from rynix_mcp.profiles import load_profile
from rynix_mcp.scanner import scope_allowed, validate_repo_path

URL_BEARING_KEYS = (
    "url",
    "frontend_url",
    "base_url",
    "target",
    "api_root",
    "sitemap_url",
    "target_url",
)


def _coerce_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _walk_urls(obj: Any, depth: int = 0, out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    if depth > 2:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in URL_BEARING_KEYS and isinstance(v, str) and v.strip():
                out.append(v.strip())
            else:
                _walk_urls(v, depth + 1, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_urls(v, depth + 1, out)
    return out


def extract_probe_urls(
    target_url: str | None = None,
    options: Any = None,
    *,
    extra: dict[str, Any] | None = None,
) -> list[str]:
    """Collect all URL strings from tool arguments and nested options."""
    opts = parse_options(options) if options is not None else {}
    if extra:
        opts = {**opts, **extra}
    seen: set[str] = set()
    urls: list[str] = []

    target_coerced = _coerce_url(target_url)
    if target_coerced and target_coerced not in seen:
        seen.add(target_coerced)
        urls.append(target_coerced)

    for u in _walk_urls(opts):
        if u not in seen:
            seen.add(u)
            urls.append(u)

    return urls


def require_all_in_scope(
    urls: list[str],
    profile_name: str | None,
    repo_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Return (allowed, reason) — fail-closed on first URL outside scope."""
    if not urls:
        return True, ""
    repo: Path | None = None
    if repo_path:
        try:
            repo = validate_repo_path(str(repo_path))
        except ValueError:
            repo = None
    try:
        profile = load_profile(profile_name, PROFILES_DIR, repo)
    except ValueError as exc:
        return False, str(exc)
    for url in urls:
        allowed, reason = scope_allowed(url, profile, SCOPE_ALLOWLIST_ENV)
        if not allowed:
            return False, reason or f"host not in scope profile: {url}"
    return True, ""
