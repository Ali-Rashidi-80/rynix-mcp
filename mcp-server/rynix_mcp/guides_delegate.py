"""Rynix technique guides — host-agent only (no external LLM subprocess)."""

from __future__ import annotations

from typing import Any

from rynix_mcp.agent_playbook import build_agent_playbook
from rynix_mcp.config import ROOT
from rynix_mcp.knowledge import get_technique_guide, list_vuln_classes


def guides_health() -> dict[str, Any]:
    skills = list_vuln_classes()
    count = len(skills)
    ready = count >= 50 and "idor" in skills
    return {
        "action": "health",
        "plugin_id": "agent-guides",
        "architecture": "host_agent",
        "no_external_llm_required": True,
        "skills_in_mcp": count,
        "skills_ready": ready,
        "ready": ready,
        "host_agent": "Cursor / IDE agent executes playbook; MCP supplies tools + evidence",
    }


def guides_list_skills(prefix: str | None = None, limit: int = 50) -> dict[str, Any]:
    skills = list_vuln_classes()
    if prefix:
        skills = [s for s in skills if s.startswith(prefix)]
    return {
        "action": "skills",
        "plugin_id": "agent-guides",
        "count": len(skills),
        "skills": skills[:limit],
        "architecture": "host_agent",
    }


def guides_delegate(
    *,
    action: str = "health",
    target_url: str | None = None,
    session_id: str | None = None,
    scan_mode: str = "standard",
    repo_path: str | None = None,
    profile: str | None = None,
    vuln_class: str | None = None,
) -> dict[str, Any]:
    if action == "health":
        return guides_health()

    if action == "skills":
        return guides_list_skills()

    if action == "guide":
        if not vuln_class:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "vuln_class required",
                    "retryable": False,
                }
            }
        return {
            "action": "guide",
            "plugin_id": "agent-guides",
            "result": get_technique_guide(vuln_class),
            "architecture": "host_agent",
        }

    if action in ("playbook", "scan"):
        return build_agent_playbook(
            scan_mode=scan_mode,
            target_url=target_url,
            repo_path=repo_path or str(ROOT),
            profile=profile,
            session_id=session_id,
        )

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown action {action}. Use: health, skills, guide, playbook",
            "retryable": False,
        }
    }
