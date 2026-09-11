"""Build rynix-scan JSON config from merged profile TOML."""

from __future__ import annotations

from typing import Any

_DEFAULT_AUTH_MARKERS = [
    "get_current_user",
    "get_current_active_user",
    "require_roles",
    "require_admin",
    "check_case_access",
    "get_current_active_superuser",
]


def _prune_nested_roots(roots: list[str]) -> list[str]:
    if not roots:
        return roots
    normalized = [(r, r.rstrip("/\\").replace("\\", "/")) for r in roots]
    kept: list[str] = []
    for i, (original, norm) in enumerate(normalized):
        nested = False
        for j, (_, other) in enumerate(normalized):
            if i == j:
                continue
            if norm == other or norm.startswith(other + "/"):
                nested = True
                break
        if not nested and original not in kept:
            kept.append(original)
    return kept


def scan_config_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    paths = profile.get("paths") if isinstance(profile.get("paths"), dict) else {}
    risk = profile.get("risk_keywords") if isinstance(profile.get("risk_keywords"), dict) else {}
    auth = profile.get("auth") if isinstance(profile.get("auth"), dict) else {}
    scanner = profile.get("scanner") if isinstance(profile.get("scanner"), dict) else {}

    profile_block = profile.get("profile") if isinstance(profile.get("profile"), dict) else {}
    stealth = profile_block.get("stealth") if isinstance(profile_block.get("stealth"), dict) else {}

    api_root = str(paths.get("api_endpoints", "backend/app/api/v1/endpoints"))
    extra_api_roots = [str(r) for r in scanner.get("api_roots", []) if r]
    default_roots = [
        "backend/app/api/v1/endpoints",
        "app/api/v1/endpoints",
        "app/api",
    ]
    if scanner.get("exclusive_api_roots") or extra_api_roots:
        merged_roots = [api_root, *extra_api_roots]
    else:
        merged_roots = [api_root, *extra_api_roots, *default_roots]
    api_roots = _prune_nested_roots(list(dict.fromkeys(merged_roots)))

    frontend_src = str(paths.get("frontend_src", "src"))
    extra_frontend = [str(r) for r in scanner.get("frontend_roots", []) if r]
    frontend_roots = list(dict.fromkeys([frontend_src, *extra_frontend, "frontend", "apps/web"]))

    if isinstance(auth.get("auth_markers"), list):
        markers = [str(m) for m in auth["auth_markers"]]
    elif isinstance(scanner.get("auth_markers"), list):
        markers = [str(m) for m in scanner["auth_markers"]]
    else:
        markers = list(_DEFAULT_AUTH_MARKERS)

    stack_hints = [str(s) for s in profile.get("stack", []) if s]
    if isinstance(scanner.get("stack_hints"), list):
        stack_hints = list(dict.fromkeys([*stack_hints, *[str(s) for s in scanner["stack_hints"]]]))

    return {
        "api_roots": api_roots,
        "frontend_root": frontend_src,
        "frontend_roots": frontend_roots,
        "auth_markers": markers,
        "risk_keywords_high": [str(k) for k in risk.get("high", [])],
        "risk_keywords_block": [str(k) for k in risk.get("block_unless_flag", [])],
        "stealth_public_prefixes": [str(p) for p in stealth.get("public_prefixes", [])],
        "stack_hints": stack_hints,
    }
