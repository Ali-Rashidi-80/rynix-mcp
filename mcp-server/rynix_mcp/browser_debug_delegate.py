"""Rynix browser debug bridge — health check for headless browser stack."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from rynix_mcp.config import DEFAULT_TIMEOUT_SEC, ROOT

BROWSER_DEBUG_ROOT = Path(
    os.environ.get("RYNIX_BROWSER_DEBUG_ROOT", str(ROOT / "optional" / "browser-debug"))
)
DEFAULT_DEBUG_URL = os.environ.get("RYNIX_BROWSER_DEBUG_URL", "http://127.0.0.1:9222")


def browser_debug_health() -> dict[str, Any]:
    root_exists = BROWSER_DEBUG_ROOT.is_dir()
    compose = BROWSER_DEBUG_ROOT / "docker-compose.yml"
    compose_exists = compose.is_file()
    debug_url = DEFAULT_DEBUG_URL.rstrip("/")
    reachable = False
    status = None
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC) as client:
            resp = client.get(f"{debug_url}/json/version")
            status = resp.status_code
            reachable = resp.status_code == 200
    except Exception as exc:
        return {
            "action": "health",
            "plugin_id": "browser-debug",
            "architecture": "host_agent",
            "optional_root": str(BROWSER_DEBUG_ROOT),
            "optional_root_exists": root_exists,
            "compose_exists": compose_exists,
            "debug_url": debug_url,
            "reachable": False,
            "ready": False,
            "error": str(exc),
            "note": "Host agent runs browser steps via playbook when debug port is up",
        }

    return {
        "action": "health",
        "plugin_id": "browser-debug",
        "architecture": "host_agent",
        "optional_root": str(BROWSER_DEBUG_ROOT),
        "optional_root_exists": root_exists,
        "compose_exists": compose_exists,
        "debug_url": debug_url,
        "reachable": reachable,
        "http_status": status,
        "ready": reachable,
    }


def browser_debug_delegate(
    *,
    action: str = "health",
    target_url: str | None = None,
) -> dict[str, Any]:
    if action == "health":
        return browser_debug_health()

    if action == "proxy_check":
        return {
            "action": "proxy_check",
            "plugin_id": "browser-debug",
            "health": browser_debug_health(),
            "target_url": target_url,
            "note": "Use host-agent playbook browser steps when debug port is reachable",
        }

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown action {action}. Use: health, proxy_check",
            "retryable": False,
        }
    }
