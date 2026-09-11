"""Agent-native engagement playbooks — host agent (Cursor) provides LLM; MCP provides tools + evidence."""

from __future__ import annotations

from typing import Any

from rynix_mcp.knowledge import (
    get_technique_guide,
    get_wstg_test as load_wstg_test,
    list_vuln_classes,
)

# Scan mode → ordered MCP tool steps for the host agent to execute.
_PLAYBOOKS: dict[str, list[dict[str, Any]]] = {
    "quick": [
        {
            "phase": "orient",
            "objective": "Fast static triage + critical surfaces",
            "tools": [
                {"tool": "health_check", "required": True},
                {"tool": "analyze_repo", "required": True, "note": "Use repo_path from workspace"},
                {"tool": "high_risk_surfaces", "required": True},
                {"tool": "generate_pentest_brief", "required": True},
            ],
        },
        {
            "phase": "live_idor",
            "objective": "Dual-token matrix on auth endpoints",
            "tools": [
                {"tool": "scope_check", "required": True, "note": "Before any live probe"},
                {"tool": "auth_login", "required": True, "note": "Per role: client, lawyer, ceo"},
                {
                    "tool": "run_idor_matrix",
                    "required": True,
                    "note": "allow_live=true, pass session_id",
                },
                {
                    "tool": "compare_role_response",
                    "required": True,
                    "note": "Object paths /cases/{id}, /clients/{id}",
                },
            ],
            "guides": ["idor", "broken-function-level-authorization"],
        },
        {
            "phase": "close",
            "objective": "Verified findings only",
            "tools": [
                {
                    "tool": "record_finding",
                    "required": True,
                    "note": "verified=true when evidence conclusive",
                },
                {"tool": "export_report", "required": True},
            ],
        },
    ],
    "standard": [
        {
            "phase": "static",
            "objective": "Full static + RBAC map",
            "tools": [
                {"tool": "health_check", "required": True},
                {"tool": "analyze_repo", "required": True},
                {"tool": "list_api_routes", "required": True},
                {"tool": "rbac_matrix", "required": True},
                {"tool": "high_risk_surfaces", "required": True},
                {"tool": "generate_pentest_brief", "required": True},
            ],
            "wstg": ["WSTG-ATHN-01", "WSTG-ATHZ-02", "WSTG-APIT-01"],
        },
        {
            "phase": "live_matrix",
            "objective": "IDOR + object-level + purge RBAC",
            "tools": [
                {"tool": "scope_check", "required": True},
                {"tool": "auth_login", "required": True},
                {"tool": "run_idor_matrix", "required": True},
                {"tool": "compare_role_response", "required": True},
                {"tool": "check_access", "required": False, "note": "Spot-check denied routes"},
                {"tool": "http_probe", "required": False},
            ],
            "guides": ["idor", "broken-function-level-authorization", "mass-assignment", "csrf"],
        },
        {
            "phase": "plugins",
            "objective": "Optional template-scan + wstg checklist",
            "tools": [
                {"tool": "rynix_plugin_run", "plugin_id": "wstg", "required": False},
                {
                    "tool": "rynix_plugin_run",
                    "plugin_id": "template-scan",
                    "required": False,
                    "note": "Mirror/staging only",
                },
            ],
        },
        {
            "phase": "close",
            "objective": "SARIF + markdown export",
            "tools": [
                {"tool": "record_finding", "required": True},
                {"tool": "export_report", "required": True},
            ],
        },
    ],
    "deep": [
        {
            "phase": "exhaustive_static",
            "objective": "Full repo scan + all risk surfaces",
            "tools": [
                {"tool": "health_check", "required": True},
                {"tool": "analyze_repo", "required": True},
                {"tool": "list_api_routes", "required": True},
                {"tool": "list_frontend_routes", "required": True},
                {"tool": "rbac_matrix", "required": True},
                {"tool": "high_risk_surfaces", "required": True},
                {"tool": "generate_pentest_brief", "required": True},
            ],
            "guides": ["idor", "sql-injection", "xss", "ssrf", "insecure-deserialization", "xxe"],
        },
        {
            "phase": "full_live",
            "objective": "Complete dual-token + object probes + finance purge",
            "tools": [
                {"tool": "scope_check", "required": True},
                {"tool": "auth_login", "required": True, "note": "All probe roles from env"},
                {"tool": "run_idor_matrix", "required": True},
                {"tool": "compare_role_response", "required": True},
                {"tool": "compare_role_response", "required": True, "note": "Finance purge paths"},
                {"tool": "check_access", "required": True},
                {"tool": "http_probe", "required": True},
                {"tool": "rynix_plugin_run", "plugin_id": "template-scan", "required": False},
            ],
            "wstg": [
                "WSTG-ATHN-01",
                "WSTG-ATHZ-02",
                "WSTG-APIT-01",
                "WSTG-BUSL-01",
                "WSTG-INPV-01",
            ],
        },
        {
            "phase": "close",
            "objective": "Full evidence pack",
            "tools": [
                {"tool": "record_finding", "required": True},
                {"tool": "export_report", "required": True},
            ],
        },
    ],
}

_SCAN_MODE_GUIDES = {
    "quick": "scan_modes--quick",
    "standard": "scan_modes--standard",
    "deep": "scan_modes--deep",
}


def build_agent_playbook(
    scan_mode: str = "standard",
    target_url: str | None = None,
    repo_path: str | None = None,
    profile: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Return structured steps for the host agent — no external LLM API key."""
    mode = scan_mode.strip().lower()
    if mode not in _PLAYBOOKS:
        mode = "standard"

    guide_slug = _SCAN_MODE_GUIDES.get(mode, "scan_modes--standard")
    guide = get_technique_guide(guide_slug)

    steps = []
    for block in _PLAYBOOKS[mode]:
        enriched = dict(block)
        if "guides" in enriched:
            enriched["technique_guides"] = {
                g: get_technique_guide(g)
                for g in enriched["guides"]
                if "error" not in get_technique_guide(g)
            }
        if "wstg" in enriched:
            enriched["wstg_guides"] = {
                tid: load_wstg_test(tid)
                for tid in enriched["wstg"]
                if "error" not in load_wstg_test(tid)
            }
        steps.append(enriched)

    return {
        "architecture": "host_agent",
        "philosophy": (
            "Host agent (Cursor, Anti-gravity, etc.) provides reasoning and orchestration. "
            "Rynix MCP provides tools, knowledge, probes, and evidence — no AGENT_GUIDES_LLM or LLM_API_KEY."
        ),
        "no_external_llm_required": True,
        "scan_mode": mode,
        "target_url": target_url,
        "repo_path": repo_path,
        "profile": profile,
        "session_id": session_id,
        "skills_available": len(list_vuln_classes()),
        "steps": steps,
        "scan_mode_guide": guide if "error" not in guide else None,
        "completion_criteria": [
            "All required tool steps executed with session_id for evidence",
            "IDOR claims backed by compare_role_response or run_idor_matrix",
            "record_finding only with verified=true when conclusive",
            "export_report produces markdown + json + sarif",
        ],
        "host_agent_instructions": (
            "Execute each phase in order using Rynix MCP tools. "
            "You (the host agent) perform analysis, chaining, and judgment — "
            "call get_technique_guide for agent-guides knowledge on demand."
        ),
    }
