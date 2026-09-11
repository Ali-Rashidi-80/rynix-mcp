"""Engagement session MCP helpers — scope, WSTG coverage, probe steps, context."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from rynix_mcp.session import STORE


def _normalize_and_validate_host(raw_host: str) -> str | None:
    raw = raw_host.strip()
    if not raw:
        return None
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    if raw.startswith("[") and "]" in raw:
        raw = raw[1 : raw.index("]")]
    elif ":" in raw and "/" not in raw:
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            raw = raw.split(":", 1)[0]

    try:
        ipaddress.ip_network(raw, strict=False)
        return raw.lower()
    except ValueError:
        # Not a CIDR network notation; fall through to single IP check
        pass

    try:
        ipaddress.ip_address(raw)
        return raw.lower()
    except ValueError:
        # Not an IP address; fall through to domain/hostname check
        pass

    clean_name = raw.lstrip("*.")
    parts = clean_name.split(".")
    if parts and all(p and all(c.isalnum() or c == "-" for c in p) for p in parts):
        return raw.lower()

    return None


def register_scope(
    host: str,
    scope_type: str = "host",
    session_id: str | None = None,
) -> dict[str, Any]:
    session = STORE.get(session_id)
    clean_host = _normalize_and_validate_host(host)
    if not clean_host:
        return {
            "ok": False,
            "error": "INVALID_HOST",
            "message": f"host '{host}' is not a valid hostname, IP, or CIDR",
            "session_id": session.session_id,
        }
    entry = {"host": clean_host, "scope_type": scope_type.strip() or "host"}
    session.scopes.append(entry)
    session.audit_log("register_scope", entry)
    return {"ok": True, "scopes": session.scopes, "session_id": session.session_id}


def track_wstg_test(
    test_id: str,
    status: str,
    notes: str = "",
    session_id: str | None = None,
) -> dict[str, Any]:
    session = STORE.get(session_id)
    tid = test_id.strip().upper()
    session.wstg_coverage[tid] = {"status": status.strip(), "notes": notes[:2000]}
    session.audit_log("track_wstg_test", {"test_id": tid, "status": status})
    return {"ok": True, "test_id": tid, "coverage": session.wstg_coverage[tid]}


def track_probe_step(
    name: str,
    status: str,
    detail: str = "",
    session_id: str | None = None,
) -> dict[str, Any]:
    session = STORE.get(session_id)
    step = {"name": name.strip(), "status": status.strip(), "detail": detail[:4000]}
    session.probe_steps.append(step)
    session.audit_log("track_probe_step", {"name": name, "status": status})
    return {"ok": True, "step": step, "count": len(session.probe_steps)}


def save_engagement_context(
    key: str,
    content: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    session = STORE.get(session_id)
    k = key.strip()
    session.context[k] = content[:16000]
    session.audit_log("save_engagement_context", {"key": k})
    return {"ok": True, "key": k}


def get_engagement_context(session_id: str | None = None) -> dict[str, Any]:
    session = STORE.get(session_id)
    return {"session_id": session.session_id, "context": dict(session.context)}


def list_engagement_progress(session_id: str | None = None) -> dict[str, Any]:
    session = STORE.get(session_id)
    total_wstg = len(session.wstg_coverage)
    passed = sum(1 for v in session.wstg_coverage.values() if v.get("status") == "pass")
    return {
        "session_id": session.session_id,
        "scopes_count": len(session.scopes),
        "wstg_tracked": total_wstg,
        "wstg_pass": passed,
        "wstg_coverage_pct": round(100.0 * passed / total_wstg, 1) if total_wstg else 0.0,
        "probe_steps": len(session.probe_steps),
        "context_keys": list(session.context.keys()),
    }
