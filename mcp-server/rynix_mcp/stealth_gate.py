"""Profile-driven API stealth gate unlock for authorized live probes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from rynix_mcp.profile_hooks import gate_settings, load_gate_secret_from_profile

_REDACTED = "[REDACTED]"


def _redact_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 6:
        return _REDACTED
    return value[:3] + _REDACTED


def load_gate_secret(
    profile: dict[str, Any] | None = None,
    repo_path: Path | str | None = None,
) -> str:
    if profile:
        secret = load_gate_secret_from_profile(profile, repo_path)
        if secret:
            return secret
    # Legacy env-only fallback when no profile gate block is configured.
    for env_name in ("RYNIX_STEALTH_GATE_SECRET", "RYNIX_REMOTE_GATE_SECRET"):
        secret = os.environ.get(env_name, "").strip()
        if secret:
            return secret
    return ""


def _gate_request(
    base_url: str,
    gate_secret: str,
    gate: dict[str, Any] | None,
) -> tuple[str, dict[str, str], dict[str, str] | None]:
    """Build URL, headers, and optional JSON body for gate unlock."""
    query_param = str((gate or {}).get("query_param") or "rynix_stealth_gate")
    transport = str((gate or {}).get("transport") or "header").strip().lower()
    header_name = str((gate or {}).get("header_name") or "X-Gate-Secret").strip()

    root = f"{base_url.rstrip('/')}/"
    if transport == "header":
        return root, {header_name: gate_secret}, None
    if transport in ("post_body", "post"):
        return root, {}, {query_param: gate_secret}
    return f"{root}?{urlencode({query_param: gate_secret})}", {}, None


def unlock_stealth_gate(
    base_url: str,
    gate_secret: str,
    client: httpx.Client | None = None,
    gate: dict[str, Any] | None = None,
) -> bool:
    if not gate_secret:
        return False
    query_param = str((gate or {}).get("query_param") or "rynix_stealth_gate")
    cookie_name = str((gate or {}).get("cookie_name") or query_param)
    url, headers, json_body = _gate_request(base_url, gate_secret, gate)

    def _has_cookie(c: httpx.Client, resp: httpx.Response | None = None) -> bool:
        if any(cookie.name == cookie_name for cookie in c.cookies.jar):
            return True
        if resp is not None and cookie_name in resp.cookies:
            return True
        return False

    def _do_request(c: httpx.Client) -> httpx.Response:
        if json_body is not None:
            return c.post(url, json=json_body, headers=headers, follow_redirects=False)
        return c.get(url, headers=headers, follow_redirects=False)

    if client is None:
        with httpx.Client(timeout=30.0, follow_redirects=False) as c:
            resp = _do_request(c)
            if resp.status_code not in (200, 302):
                return False
            return _has_cookie(c, resp)
    resp = _do_request(client)
    if resp.status_code not in (200, 302):
        return False
    return _has_cookie(client, resp)


def profile_has_stealth_gate(profile: dict[str, Any]) -> bool:
    return gate_settings(profile) is not None


def gate_audit_entry(gate_secret: str) -> dict[str, str]:
    """Safe audit/log payload — never include raw gate secret."""
    return {"gate_secret": _redact_secret(gate_secret)}
