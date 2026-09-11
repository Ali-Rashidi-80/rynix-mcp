"""Rynix whitebox-scan — static queue + host-agent exploit validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rynix_mcp.scanner import run_scan
from rynix_mcp.session import STORE


def whitebox_delegate(
    *,
    action: str = "queue_from_repo",
    session_id: str | None = None,
    repo_path: str | None = None,
    opts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    opts = opts or {}
    session = STORE.get(session_id)
    wb = session.context.setdefault("whitebox_scan", {"queue": [], "validated": []})

    if action == "queue_from_repo":
        if not repo_path:
            return {
                "error": {
                    "code": "MISSING_ARG",
                    "message": "repo_path required",
                    "retryable": False,
                }
            }
        scan = run_scan(Path(repo_path), opts.get("profile"))
        queue = [
            {"method": r.get("method"), "path": r.get("path"), "file": r.get("file")}
            for r in scan.get("routes", [])[:100]
        ]
        wb["queue"] = queue
        wb["index"] = 0
        return {"plugin_id": "whitebox-scan", "action": "queue_from_repo", "count": len(queue)}

    if action == "next_target":
        idx = int(wb.get("index", 0))
        queue = wb.get("queue", [])
        if idx >= len(queue):
            return {"plugin_id": "whitebox-scan", "action": "next_target", "done": True}
        target = queue[idx]
        wb["index"] = idx + 1
        return {
            "plugin_id": "whitebox-scan",
            "action": "next_target",
            "target": target,
            "remaining": len(queue) - idx - 1,
        }

    if action == "mark_validated":
        entry = opts.get("target") or {}
        wb.setdefault("validated", []).append(entry)
        return {
            "plugin_id": "whitebox-scan",
            "action": "mark_validated",
            "validated_count": len(wb["validated"]),
        }

    if action == "export_sarif":
        return {
            "plugin_id": "whitebox-scan",
            "action": "export_sarif",
            "validated": wb.get("validated", []),
            "note": "Use export_report MCP tool for SARIF output",
        }

    return {
        "error": {
            "code": "UNSUPPORTED_ACTION",
            "message": f"Unknown whitebox action {action}",
            "retryable": False,
        }
    }
