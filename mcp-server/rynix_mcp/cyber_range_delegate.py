"""Rynix cyber-range — bench scenarios for host-agent execution."""

from __future__ import annotations

from typing import Any

from rynix_mcp.session import STORE

SCENARIOS = [
    {"id": "auth-bypass-lab", "difficulty": "medium"},
    {"id": "idor-matrix-lab", "difficulty": "medium"},
    {"id": "xss-dom-lab", "difficulty": "low"},
]


def cyber_range_delegate(
    action: str = "list_scenarios", opts: dict[str, Any] | None = None
) -> dict[str, Any]:
    opts = opts or {}
    if action == "list_scenarios":
        return {"plugin_id": "cyber-range", "action": "list_scenarios", "scenarios": SCENARIOS}

    if action == "start_scenario":
        sid = str(opts.get("scenario_id", SCENARIOS[0]["id"]))
        session = STORE.get(opts.get("session_id"))
        session.context["cyber_range"] = {"scenario_id": sid, "score": 0, "steps": []}
        return {"plugin_id": "cyber-range", "action": "start_scenario", "scenario_id": sid}

    if action == "log_step":
        session = STORE.get(opts.get("session_id"))
        cr = session.context.setdefault("cyber_range", {"steps": []})
        step = {"name": opts.get("name"), "status": opts.get("status")}
        cr.setdefault("steps", []).append(step)
        return {"plugin_id": "cyber-range", "action": "log_step", "step": step}

    if action == "score":
        session = STORE.get(opts.get("session_id"))
        cr = session.context.get("cyber_range", {})
        return {"plugin_id": "cyber-range", "action": "score", "score": cr.get("score", 0)}

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown cyber-range action {action}",
            "retryable": False,
        }
    }
