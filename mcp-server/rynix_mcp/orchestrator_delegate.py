"""Rynix agent orchestrator — optional REST health for self-hosted flow stacks."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import httpx

from rynix_mcp.config import DEFAULT_TIMEOUT_SEC, ROOT

logger = logging.getLogger(__name__)

ORCHESTRATOR_ROOT = Path(
    os.environ.get("RYNIX_ORCHESTRATOR_ROOT", str(ROOT / "optional" / "orchestrator"))
)
DEFAULT_URL = os.environ.get("RYNIX_ORCHESTRATOR_URL", "https://127.0.0.1:8443")


def _probe_url(url: str) -> dict[str, Any]:
    verify = os.environ.get("RYNIX_ORCHESTRATOR_INSECURE", "").lower() not in ("1", "true", "yes")
    candidates = (f"{url}/health", f"{url}/api/health", url)
    for endpoint in candidates:
        try:
            with httpx.Client(
                timeout=DEFAULT_TIMEOUT_SEC, verify=verify, follow_redirects=True
            ) as client:
                resp = client.get(endpoint)
            if resp.status_code < 500:
                return {
                    "reachable": True,
                    "endpoint": endpoint,
                    "http_status": resp.status_code,
                    "verify_tls": verify,
                }
        except (httpx.HTTPError, OSError) as exc:
            logger.debug("Orchestrator probe to %s failed: %s", endpoint, exc)
            continue
    return {"reachable": False, "verify_tls": verify}


def orchestrator_health() -> dict[str, Any]:
    root_exists = ORCHESTRATOR_ROOT.is_dir()
    compose = ORCHESTRATOR_ROOT / "docker-compose.yml"
    compose_exists = compose.is_file()
    url = DEFAULT_URL.rstrip("/")
    probe = _probe_url(url)

    base = {
        "action": "health",
        "plugin_id": "agent-orchestrator",
        "architecture": "host_agent",
        "optional_root": str(ORCHESTRATOR_ROOT),
        "optional_root_exists": root_exists,
        "compose_exists": compose_exists,
        "service_url": url,
        "reachable": probe.get("reachable", False),
    }
    if probe.get("reachable"):
        base["ready"] = True
        base["http_status"] = probe.get("http_status")
        base["health_endpoint"] = probe.get("endpoint")
    else:
        base["ready"] = False
        base["note"] = (
            "Default: host agent multi-role playbook; optional REST when stack is self-hosted"
        )
    return base


def orchestrator_delegate(
    *,
    action: str = "health",
    target_url: str | None = None,
    engagement_path: str | None = None,
) -> dict[str, Any]:
    if action == "health":
        return orchestrator_health()

    if action == "probe":
        if not target_url:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "target_url required for probe",
                    "retryable": False,
                }
            }
        return {
            "action": "probe",
            "plugin_id": "agent-orchestrator",
            "target_url": target_url,
            "orchestrator": orchestrator_health(),
            "delegation": "host_agent",
            "note": "Multi-role flows run via host agent + MCP tools",
        }

    if action in ("assign_role", "list_flows", "flow_status"):
        return {
            "action": action,
            "plugin_id": "agent-orchestrator",
            "architecture": "host_agent",
            "engagement_path": engagement_path,
            "note": "Use agent_engagement_playbook MCP tool with role phases",
        }

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown action {action}. Use: health, probe, assign_role, list_flows, flow_status",
            "retryable": False,
        }
    }
