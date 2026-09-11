"""Resolve missing probe usernames via admin API (production) or mirror DB."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from rynix_mcp.probe_accounts import _ROLE_ENV_MAP, load_probe_accounts, password_for
from rynix_mcp.profiles import resolve_profile_name
from rynix_mcp.session import STORE
from rynix_mcp.target_repo import target_repo_env

ROLE_ENUM = {
    "admin": "ADMIN",
    "ceo": "CEO",
    "lawyer": "LAWYER",
    "secretary": "SECRETARY",
    "legal_deputy": "LEGAL_DEPUTY",
    "psychologist": "PSYCHOLOGIST",
    "intern": "INTERN",
    "client": "CLIENT",
}


def missing_roles(roles: tuple[str, ...] | None = None, session_id: str | None = None) -> list[str]:
    wanted = roles or tuple(_ROLE_ENV_MAP.keys())
    accounts = load_probe_accounts(session_id=session_id)
    return [r for r in wanted if r not in accounts]


def resolve_via_admin_api(
    base_url: str,
    session_id: str | None = None,
    roles: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Use admin/ceo token to list users by role and fill missing probe env vars."""
    from rynix_mcp.http_session import request as session_request
    from rynix_mcp.server import auth_login

    missing = missing_roles(roles, session_id=session_id)
    if not missing:
        return {"resolved": {}, "missing": [], "skipped": True, "reason": "all roles configured"}

    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)
    accounts = load_probe_accounts(session_id=session_id)
    if not default_pwd or not accounts:
        return {"resolved": {}, "missing": missing, "error": "missing_credentials"}

    repo = target_repo_env()
    repo_path = Path(repo) if repo else None
    profile = resolve_profile_name(None, repo_path)
    session = STORE.get(session_id)
    privileged = None
    for role in ("admin", "ceo"):
        if role not in accounts:
            continue
        username, env_key = accounts[role]
        result = auth_login(
            base_url,
            username,
            password_for(env_key, default_pwd, ceo_pwd),
            profile=profile,
            role_label=role,
            session_id=session_id,
            allow_live=True,
            repo_path=repo or None,
        )
        if "error" not in result:
            privileged = session.tokens.get(role)
            break

    if not privileged:
        return {"resolved": {}, "missing": missing, "error": "privileged_login_failed"}

    resolved: dict[str, str] = {}
    for role in missing:
        enum_name = ROLE_ENUM.get(role)
        if not enum_name:
            continue
        resp = session_request(
            base_url,
            "GET",
            f"/api/v1/users/?role={enum_name}&page_size=1&is_active=true",
            session_id=session_id,
            headers={"Authorization": f"Bearer {privileged}"},
            follow_redirects=False,
        )
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        items = data.get("items") if isinstance(data, dict) else None
        if not items and isinstance(data, dict):
            items = data.get("results") or data.get("data")
        if not items or not isinstance(items, list):
            continue
        row = items[0]
        if isinstance(row, dict):
            username = str(row.get("username", "")).strip()
            if username:
                session.probe_usernames[role] = username
                resolved[role] = username

    still_missing = missing_roles(roles, session_id=session_id)
    return {"resolved": resolved, "missing": still_missing, "privileged": bool(privileged)}
