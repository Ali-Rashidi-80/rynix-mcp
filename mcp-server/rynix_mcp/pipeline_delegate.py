"""Rynix pipeline-runner — recon→analyze→exploit→report via host agent."""

from __future__ import annotations

from typing import Any

from rynix_mcp.session import STORE

STAGES = ("recon", "analyze", "exploit", "report")


def pipeline_delegate(
    *,
    action: str = "status",
    session_id: str | None = None,
    opts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opts = opts or {}
    session = STORE.get(session_id)
    pipeline = session.context.setdefault(
        "pipeline",
        {"stage": "recon", "checkpoint": {}, "history": []},
    )

    if action == "status":
        return {"plugin_id": "pipeline-runner", "action": "status", "pipeline": pipeline}

    if action == "advance_stage":
        current = str(pipeline.get("stage", "recon"))
        idx = STAGES.index(current) if current in STAGES else 0
        next_stage = STAGES[min(idx + 1, len(STAGES) - 1)]
        pipeline["stage"] = next_stage
        pipeline["history"].append({"from": current, "to": next_stage})
        session.audit_log("pipeline_advance", {"stage": next_stage})
        return {"plugin_id": "pipeline-runner", "action": "advance_stage", "pipeline": pipeline}

    if action == "save_checkpoint":
        key = str(opts.get("key", "default"))
        pipeline["checkpoint"][key] = opts.get("content", "")
        return {"plugin_id": "pipeline-runner", "action": "save_checkpoint", "key": key}

    if action == "load_checkpoint":
        key = str(opts.get("key", "default"))
        return {
            "plugin_id": "pipeline-runner",
            "action": "load_checkpoint",
            "key": key,
            "content": pipeline["checkpoint"].get(key, ""),
        }

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown pipeline action {action}",
            "retryable": False,
        }
    }
