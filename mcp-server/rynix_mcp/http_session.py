"""Shared HTTP session with stealth-gate cookies for production probes."""

from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from rynix_mcp.config import DEFAULT_TIMEOUT_SEC
from rynix_mcp.session import STORE
from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate

GATE_FAIL_TTL_SEC = 300


def _host(base_url: str) -> str:
    return urlparse(base_url).netloc or base_url.rstrip("/")


def _hostname(base_url: str) -> str:
    host = urlparse(base_url).hostname or ""
    return host.strip("[]").lower()


def _is_local(base_url: str) -> bool:
    h = _hostname(base_url)
    if h in {"localhost", "::1"}:
        return True
    try:
        addr = ipaddress.ip_address(h)
        mapped = getattr(addr, "ipv4_mapped", None)
        return addr.is_loopback or bool(mapped and mapped.is_loopback)
    except ValueError:
        return False


def _resolve_url(base_url: str, path_or_url: str) -> str:
    parsed = urlparse(path_or_url)
    if parsed.scheme in ("http", "https"):
        return path_or_url
    return urljoin(base_url.rstrip("/") + "/", path_or_url.lstrip("/"))


def _same_host(base_url: str, url: str) -> bool:
    return _host(base_url).lower() == _host(url).lower()


def _cookie_matches_host(cookie: dict[str, str], host: str) -> bool:
    domain = cookie.get("domain", host).lstrip(".").lower()
    host_l = host.lower()
    return host_l == domain or host_l.endswith("." + domain)


def _cookies_from_client(
    client: httpx.Client, host: str
) -> tuple[dict[str, str], list[dict[str, str]]]:
    flat: dict[str, str] = {}
    details: list[dict[str, str]] = []
    for cookie in client.cookies.jar:
        row = {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain or host,
            "path": cookie.path or "/",
        }
        details.append(row)
        if _cookie_matches_host(row, host):
            flat[cookie.name] = cookie.value
    return flat, details


def _httpx_cookies_for_host(host: str, details: list[dict[str, str]]) -> httpx.Cookies:
    jar = httpx.Cookies()
    for row in details:
        if not _cookie_matches_host(row, host):
            continue
        jar.set(
            row["name"],
            row["value"],
            domain=row.get("domain") or host,
            path=row.get("path") or "/",
        )
    return jar


def ensure_stealth_gate(
    base_url: str,
    session_id: str | None = None,
    profile: dict[str, Any] | None = None,
    repo_path: str | None = None,
) -> bool:
    """Unlock production stealth gate once per session host when profile defines one."""
    from rynix_mcp.profile_hooks import gate_settings

    if _is_local(base_url):
        return True

    gate = gate_settings(profile or {}) if profile else None
    if profile and not gate:
        return True
    secret = load_gate_secret(profile, repo_path)
    if not secret:
        return True

    host = _host(base_url)
    session = STORE.get(session_id)
    fail_ts = session.gate_fail_ts.get(host)
    if fail_ts is not None and time.time() - fail_ts < GATE_FAIL_TTL_SEC:
        return False
    if session.gate_unlocked.get(host):
        return True
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC, follow_redirects=False) as client:
            ok = unlock_stealth_gate(base_url, secret, client, gate=gate)
            if ok:
                flat, details = _cookies_from_client(client, host)
                session.gate_cookies[host] = flat
                session.gate_cookie_jar[host] = details
                session.gate_unlocked[host] = True
                session.gate_fail_ts.pop(host, None)
                session.audit_log("stealth_gate_unlock", {"host": host, "ok": True})
            else:
                session.gate_fail_ts[host] = time.time()
                session.audit_log(
                    "stealth_gate_unlock", {"host": host, "ok": False, "reason": "unlock_failed"}
                )
    except (httpx.HTTPError, ValueError) as exc:
        session.gate_fail_ts[host] = time.time()
        session.audit_log("stealth_gate_unlock", {"host": host, "ok": False, "error": str(exc)})
        return False
    return ok


def store_client_cookies(
    base_url: str, client: httpx.Client, session_id: str | None = None
) -> None:
    """Copy cookies from an unlocked httpx client into the MCP session."""
    host = _host(base_url)
    session = STORE.get(session_id)
    flat, details = _cookies_from_client(client, host)
    session.gate_cookies[host] = flat
    session.gate_cookie_jar[host] = details
    session.gate_unlocked[host] = True


def session_cookies(base_url: str, session_id: str | None = None) -> dict[str, str]:
    host = _host(base_url)
    return dict(STORE.get(session_id).gate_cookies.get(host, {}))


def _request_cookies(base_url: str, session_id: str | None = None) -> httpx.Cookies:
    host = _host(base_url)
    session = STORE.get(session_id)
    details = session.gate_cookie_jar.get(host)
    if details:
        return _httpx_cookies_for_host(host, details)
    jar = httpx.Cookies()
    for name, value in session.gate_cookies.get(host, {}).items():
        jar.set(name, value, domain=host, path="/")
    return jar


def _dispatch(
    client: httpx.Client,
    method_u: str,
    url: str,
    *,
    headers: dict[str, str],
    data: dict[str, str] | None,
    json_body: Any,
) -> httpx.Response:
    if method_u == "GET":
        return client.get(url, headers=headers)
    if method_u == "HEAD":
        return client.head(url, headers=headers)
    if method_u == "POST":
        if data is not None:
            return client.post(url, data=data, headers=headers)
        return client.post(url, json=json_body, headers=headers)
    if method_u in ("PUT", "PATCH"):
        if data is not None:
            return client.request(method_u, url, data=data, headers=headers)
        return client.request(method_u, url, json=json_body, headers=headers)
    return client.request(method_u, url, headers=headers, json=json_body)


def request(
    base_url: str,
    method: str,
    path_or_url: str,
    session_id: str | None = None,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    json_body: Any = None,
    follow_redirects: bool = False,
    auto_gate: bool = True,
    profile: dict[str, Any] | None = None,
    repo_path: str | None = None,
) -> httpx.Response:
    """HTTP request with optional stealth-gate cookies from session."""
    if auto_gate and not _is_local(base_url):
        ensure_stealth_gate(base_url, session_id, profile=profile, repo_path=repo_path)
    url = _resolve_url(base_url, path_or_url)
    if not _same_host(base_url, url):
        raise ValueError(f"Cross-host request refused: {base_url!r} -> {url!r}")
    cookies = _request_cookies(base_url, session_id)
    with httpx.Client(
        timeout=DEFAULT_TIMEOUT_SEC,
        cookies=cookies,
        follow_redirects=follow_redirects,
    ) as client:
        return _dispatch(
            client,
            method.upper(),
            url,
            headers=headers or {},
            data=data,
            json_body=json_body,
        )
