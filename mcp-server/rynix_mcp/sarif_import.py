"""Import external SARIF runs into Rynix session."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rynix_mcp.session import STORE, Finding, new_finding_id

_SEV_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def merge_sarif_file(
    sarif_path: str, session_id: str | None = None, source_plugin: str = "sarif-import"
) -> dict[str, Any]:
    path = Path(sarif_path)
    if not path.is_file():
        return {
            "error": {
                "code": "NOT_FOUND",
                "message": f"SARIF file not found: {sarif_path}",
                "retryable": False,
            }
        }

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": {"code": "JSON_PARSE", "message": str(exc), "retryable": False}}
    except OSError as exc:
        return {"error": {"code": "READ_FAILED", "message": str(exc), "retryable": True}}

    if not isinstance(doc, dict):
        return {
            "error": {
                "code": "INVALID_SHAPE",
                "message": "SARIF root must be a JSON object",
                "retryable": False,
            }
        }

    runs = doc.get("runs")
    if runs is None:
        return {
            "error": {
                "code": "INVALID_SHAPE",
                "message": "SARIF document missing runs[]",
                "retryable": False,
            }
        }
    if not isinstance(runs, list):
        return {
            "error": {
                "code": "INVALID_SHAPE",
                "message": "SARIF runs must be a list",
                "retryable": False,
            }
        }

    session = STORE.get(session_id)
    recorded: list[str] = []
    skipped = 0

    for run in doc.get("runs", []):
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            msg = result.get("message", {})
            title = msg.get("text") if isinstance(msg, dict) else str(msg)
            if not title:
                title = "SARIF finding"
            level = str(result.get("level", "warning")).lower()
            severity = _SEV_MAP.get(level, "medium")
            locs = result.get("locations", [])
            endpoint = ""
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                if isinstance(phys, dict):
                    art = phys.get("artifactLocation", {})
                    if isinstance(art, dict):
                        endpoint = str(art.get("uri", ""))
            rule_id = ""
            rid = result.get("ruleId")
            if rid:
                rule_id = str(rid)
            elif isinstance(result.get("rule"), dict):
                rule_id = str(result["rule"].get("id", ""))

            fid = new_finding_id()
            session.findings.append(
                Finding(
                    id=fid,
                    severity=severity,
                    title=title[:200],
                    endpoint=endpoint,
                    evidence=json.dumps({"rule_id": rule_id, "level": level}, ensure_ascii=False),
                    verified=False,
                    source_plugin=source_plugin,
                )
            )
            recorded.append(fid)

    if not recorded:
        skipped = 1

    session.audit_log(
        "sarif_merge",
        {"path": str(path), "imported": len(recorded), "source_plugin": source_plugin},
    )

    return {
        "plugin_id": source_plugin,
        "sarif_path": str(path),
        "imported_count": len(recorded),
        "recorded_finding_ids": recorded,
        "skipped": skipped,
        "session_id": session.session_id,
    }
