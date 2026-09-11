"""Rynix engagement guard — validate scope and drive host-agent engagement (no upstream CLI)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from rynix_mcp.agent_playbook import build_agent_playbook
from rynix_mcp.config import ROOT
from rynix_mcp.engagement import validate_engagement_yaml
from rynix_mcp.path_safety import resolve_export_output_dir


def _resolve_engagement(
    path: str | None, *, allow_default: bool = True
) -> tuple[Path | None, str | None]:
    if path:
        p = Path(path)
        if p.is_file():
            return p, None
        return None, f"Engagement file not found: {path}"
    if allow_default:
        default = ROOT / "examples" / "example-law-firm" / "engagement-mirror.yaml"
        if default.is_file():
            return default, None
        fallback = ROOT / "schemas" / "engagements" / "example.yaml"
        if fallback.is_file():
            return fallback, None
    return None, "No engagement YAML found — pass engagement_path explicitly"


def _load_engagement_data(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return data if isinstance(data, dict) else {}


def engagement_check_scope(engagement_path: str, url: str) -> dict[str, Any]:
    eng, err = _resolve_engagement(engagement_path or None)
    if err or eng is None:
        return {
            "error": {
                "code": "ENGAGEMENT_NOT_FOUND",
                "message": err or "engagement missing",
                "retryable": False,
            }
        }
    validation = validate_engagement_yaml(str(eng))
    if not validation.get("valid"):
        return {
            "validation": validation,
            "error": {"code": "INVALID_ENGAGEMENT", "message": str(validation.get("issues"))},
        }

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    allowed = [str(h).lower() for h in validation.get("allowed_hosts", [])]
    allowed_match = host in allowed or any(
        h.startswith("*.") and host.endswith(h[1:]) for h in allowed if h.startswith("*.")
    )
    deny_paths = validation.get("deny_paths", []) or []
    path_denied = any(
        dp.replace("*", "") in parsed.path for dp in deny_paths if isinstance(dp, str)
    )
    permitted = bool(host) and allowed_match and not path_denied

    return {
        "plugin_id": "engagement",
        "action": "check",
        "engagement": str(eng),
        "url": url,
        "allowed": permitted,
        "reason": "host in scope.allow.hosts" if permitted else "host or path not permitted",
        "allowed_hosts": allowed,
    }


def engagement_list_scopes(engagement_path: str | None = None) -> dict[str, Any]:
    eng, err = _resolve_engagement(engagement_path)
    if err or eng is None:
        return {
            "error": {
                "code": "ENGAGEMENT_NOT_FOUND",
                "message": err or "engagement missing",
                "retryable": False,
            }
        }
    data = _load_engagement_data(eng)
    scopes = data.get("scopes_to_run", [])
    if not isinstance(scopes, list):
        scopes = []
    return {
        "plugin_id": "engagement",
        "action": "scopes",
        "scopes": [str(s) for s in scopes],
        "count": len(scopes),
        "engagement": str(eng),
    }


def engagement_run(
    engagement_path: str,
    output_dir: str | None = None,
    session_id: str | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    eng, err = _resolve_engagement(engagement_path or None)
    if err or eng is None:
        return {
            "error": {
                "code": "ENGAGEMENT_NOT_FOUND",
                "message": err or "engagement missing",
                "retryable": False,
            }
        }
    validation = validate_engagement_yaml(str(eng))
    if not validation.get("valid"):
        return {"error": {"code": "INVALID_ENGAGEMENT", "message": str(validation.get("issues"))}}

    out = resolve_export_output_dir(output_dir or "engagement-run")
    out.mkdir(parents=True, exist_ok=True)
    base_url = str(validation.get("base_url") or "")
    playbook = build_agent_playbook(
        scan_mode="standard",
        target_url=base_url or None,
        repo_path=str(ROOT),
        profile=profile,
        session_id=session_id,
    )
    return {
        "plugin_id": "engagement",
        "action": "run",
        "architecture": "host_agent",
        "engagement": str(eng),
        "output_dir": str(out),
        "playbook": playbook,
        "note": "Host agent executes engagement via MCP tools; no external orchestrator subprocess",
    }


def engagement_delegate(
    action: str,
    engagement_path: str | None = None,
    url: str | None = None,
    output_dir: str | None = None,
    session_id: str | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    act = (action or "validate").lower()
    if act == "validate":
        path_in = engagement_path or ""
        if path_in:
            p = Path(path_in)
            if not p.is_file():
                return {
                    "plugin_id": "engagement",
                    "action": "validate",
                    "error": {
                        "code": "ENGAGEMENT_NOT_FOUND",
                        "message": f"Engagement file not found: {path_in}",
                        "retryable": False,
                    },
                }
            return {
                "plugin_id": "engagement",
                "action": "validate",
                **validate_engagement_yaml(path_in),
            }
        eng, err = _resolve_engagement(None)
        if err or eng is None:
            return {
                "error": {
                    "code": "ENGAGEMENT_NOT_FOUND",
                    "message": err or "engagement missing",
                    "retryable": False,
                }
            }
        return {
            "plugin_id": "engagement",
            "action": "validate",
            **validate_engagement_yaml(str(eng)),
        }
    if act == "check":
        if not url:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "url required for check action",
                    "retryable": False,
                }
            }
        return engagement_check_scope(engagement_path or "", url)
    if act == "scopes":
        return engagement_list_scopes(engagement_path)
    if act == "run":
        return engagement_run(engagement_path or "", output_dir, session_id, profile)
    return {
        "error": {
            "code": "UNKNOWN_ACTION",
            "message": f"Unknown engagement action {action}; use validate|check|scopes|run",
            "retryable": False,
        }
    }
