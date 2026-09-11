"""Load pentest probe accounts from environment — no hardcoded production usernames."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from rynix_mcp.session import STORE

# role -> (username_env, password_env_key)
_ROLE_ENV_MAP: dict[str, tuple[str, str]] = {
    "client": ("RYNIX_PROBE_USER_CLIENT", "RYNIX_PROBE_PASSWORD"),
    "secretary": ("RYNIX_PROBE_USER_SECRETARY", "RYNIX_PROBE_PASSWORD"),
    "intern": ("RYNIX_PROBE_USER_INTERN", "RYNIX_PROBE_PASSWORD"),
    "lawyer": ("RYNIX_PROBE_USER_LAWYER", "RYNIX_PROBE_PASSWORD"),
    "ceo": ("RYNIX_PROBE_USER_CEO", "RYNIX_PROBE_PASSWORD_CEO"),
    "admin": ("RYNIX_PROBE_USER_ADMIN", "RYNIX_PROBE_PASSWORD"),
    "legal_deputy": ("RYNIX_PROBE_USER_LEGAL_DEPUTY", "RYNIX_PROBE_PASSWORD"),
    "psychologist": ("RYNIX_PROBE_USER_PSYCHOLOGIST", "RYNIX_PROBE_PASSWORD"),
}

_DEFAULT_ROLES = tuple(_ROLE_ENV_MAP.keys())


def load_probe_accounts(
    roles: tuple[str, ...] | None = None,
    session_id: str | None = None,
) -> dict[str, tuple[str, str]]:
    """Return {role: (username, password_env_key)} from env or accounts file.

    Priority:
    1. RYNIX_PROBE_ACCOUNTS_FILE JSON: {"client": {"username": "...", "password_env": "..."}}
    2. Per-role RYNIX_PROBE_USER_<ROLE> environment variables
    3. Session-resolved usernames (probe_user_resolver)
    """
    accounts: dict[str, tuple[str, str]] = {}
    file_path = os.environ.get("RYNIX_PROBE_ACCOUNTS_FILE", "").strip()
    if file_path:
        path = Path(file_path)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
            if isinstance(data, dict):
                for role, spec in data.items():
                    if not isinstance(spec, dict):
                        continue
                    username = str(spec.get("username", "")).strip()
                    pwd_env = str(spec.get("password_env", "RYNIX_PROBE_PASSWORD")).strip()
                    if username:
                        accounts[str(role)] = (username, pwd_env or "RYNIX_PROBE_PASSWORD")

    for role, (user_env, pwd_env) in _ROLE_ENV_MAP.items():
        if role in accounts:
            continue
        username = os.environ.get(user_env, "").strip()
        if username:
            accounts[role] = (username, pwd_env)

    session = STORE.get(session_id)
    for role, username in session.probe_usernames.items():
        if role in accounts or not str(username).strip():
            continue
        pwd_env = _ROLE_ENV_MAP.get(role, ("", "RYNIX_PROBE_PASSWORD"))[1]
        accounts[role] = (str(username).strip(), pwd_env)

    if roles:
        return {r: accounts[r] for r in roles if r in accounts}
    return accounts


def password_for(env_key: str, default_pwd: str, ceo_pwd: str) -> str:
    custom = os.environ.get(env_key, "").strip()
    if custom:
        return custom
    if env_key == "RYNIX_PROBE_PASSWORD_CEO":
        return ceo_pwd
    return default_pwd


def accounts_have_passwords(accounts: dict[str, tuple[str, str]]) -> bool:
    if not accounts:
        return False
    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)
    return all(password_for(pwd_env, default_pwd, ceo_pwd) for _, pwd_env in accounts.values())


def missing_credentials_message(accounts: dict[str, Any]) -> str:
    return (
        "Set RYNIX_PROBE_PASSWORD and per-role RYNIX_PROBE_USER_* "
        "(or RYNIX_PROBE_ACCOUNTS_FILE JSON). "
        f"Configured roles: {list(accounts.keys()) or 'none'}"
    )
