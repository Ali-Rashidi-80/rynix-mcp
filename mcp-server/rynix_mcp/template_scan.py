"""Rynix template scanner plugin — binary via RYNIX_TEMPLATE_SCAN_BIN only."""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from rynix_mcp.config import ROOT
from rynix_mcp.session import STORE, Finding, new_finding_id

logger = logging.getLogger(__name__)

MAX_TEMPLATE_FINDINGS = 500
MAX_TOTAL_SEC = 300
SILENCE_TIMEOUT_SEC = 30.0
MAX_STDERR_LINES = 200


def _cleanup_proc(
    proc: subprocess.Popen[str],
    stderr_thread: threading.Thread | None = None,
    stdout_thread: threading.Thread | None = None,
) -> None:
    try:
        proc.kill()
    except OSError as exc:
        logger.debug(
            "Failed to kill template scanner process %s: %s", getattr(proc, "pid", None), exc
        )
    try:
        proc.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug(
            "Failed waiting on template scanner process %s: %s", getattr(proc, "pid", None), exc
        )
    if stderr_thread and stderr_thread.is_alive():
        stderr_thread.join(timeout=2)
    if stdout_thread and stdout_thread.is_alive():
        stdout_thread.join(timeout=2)


def _valid_template_scan_candidate(candidate: Path) -> str | None:
    if not candidate.is_file():
        return None
    try:
        if candidate.stat().st_size <= 1024:
            return None
    except OSError:
        return None
    try:
        proc = subprocess.run(
            [str(candidate), "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode == 0 or (proc.stdout or proc.stderr):
            return str(candidate)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return None


def resolve_template_scan_bin() -> str | None:
    explicit = os.environ.get("RYNIX_TEMPLATE_SCAN_BIN", "").strip()
    if explicit:
        return _valid_template_scan_candidate(Path(explicit))
    for candidate in (
        ROOT / "bin" / "template-scan.exe",
        ROOT / "bin" / "template-scan",
    ):
        validated = _valid_template_scan_candidate(candidate)
        if validated:
            return validated
    return None


def _record_findings(
    rows: list[dict[str, Any]], session_id: str | None, plugin_id: str
) -> list[str]:
    session = STORE.get(session_id)
    ids: list[str] = []
    for row in rows:
        fid = new_finding_id()
        sev = str(row.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        session.findings.append(
            Finding(
                id=fid,
                severity=sev,
                title=str(row.get("name") or row.get("template_id") or "plugin finding"),
                endpoint=str(row.get("matched_at") or ""),
                evidence=json.dumps(row, ensure_ascii=False)[:800],
                verified=False,
                source_plugin=plugin_id,
            )
        )
        ids.append(fid)
    if ids:
        session.audit_log("plugin_findings", {"plugin_id": plugin_id, "count": len(ids)})
    return ids


def run_template_scan(
    target_url: str,
    templates: str = "http/cves/",
    tags: str = "",
    session_id: str | None = None,
) -> dict[str, Any]:
    from rynix_mcp.plugins import load_manifest, plugin_health_check

    manifest = load_manifest("template-scan")
    if not manifest:
        return {
            "error": {
                "code": "NOT_FOUND",
                "message": "template-scan manifest missing",
                "retryable": False,
            }
        }
    if not manifest.get("enabled", False):
        return {
            "error": {
                "code": "PLUGIN_DISABLED",
                "message": "Enable plugins/template-scan.toml enabled=true",
                "retryable": False,
            }
        }

    health = plugin_health_check("template-scan")
    if not health.get("ok"):
        return {"error": {"code": "PLUGIN_UNHEALTHY", "message": str(health), "retryable": True}}

    scan_bin = resolve_template_scan_bin()
    if not scan_bin:
        return {
            "error": {
                "code": "PLUGIN_UNHEALTHY",
                "message": "Set RYNIX_TEMPLATE_SCAN_BIN or place binary in bin/template-scan",
                "retryable": True,
            }
        }

    cmd = [
        scan_bin,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-timeout",
        "10",
        "-rate-limit",
        "10",
    ]
    if templates:
        cmd.extend(["-t", templates])
    if tags:
        cmd.extend(["-tags", tags])

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    stderr_lines: deque[str] = deque(maxlen=MAX_STDERR_LINES)
    exit_code = 1
    deadline = time.monotonic() + MAX_TOTAL_SEC

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        def _pump_stderr() -> None:
            for err_line in proc.stderr:
                stderr_lines.append(err_line)

        stderr_thread = threading.Thread(target=_pump_stderr, daemon=True)
        stderr_thread.start()

        stdout_queue: queue.Queue[str | None] = queue.Queue()

        def _pump_stdout() -> None:
            for out_line in proc.stdout:
                stdout_queue.put(out_line)
            stdout_queue.put(None)

        stdout_thread = threading.Thread(target=_pump_stdout, daemon=True)
        stdout_thread.start()

        last_output_time = time.monotonic()

        while True:
            remaining_wall = deadline - time.monotonic()
            if remaining_wall <= 0:
                _cleanup_proc(proc, stderr_thread, stdout_thread)
                return {
                    "error": {
                        "code": "SCAN_TIMEOUT",
                        "message": f"template scan exceeded {MAX_TOTAL_SEC}s wall clock",
                        "retryable": True,
                    }
                }

            remaining_silence = SILENCE_TIMEOUT_SEC - (time.monotonic() - last_output_time)
            if remaining_silence <= 0:
                _cleanup_proc(proc, stderr_thread, stdout_thread)
                return {
                    "error": {
                        "code": "SCANNER_SILENCE_TIMEOUT",
                        "message": f"template scan produced no output for {SILENCE_TIMEOUT_SEC}s",
                        "retryable": True,
                    }
                }

            wait_time = max(0.05, min(remaining_wall, remaining_silence, 1.0))
            try:
                line = stdout_queue.get(timeout=wait_time)
            except queue.Empty:
                continue

            if line is None:
                break

            last_output_time = time.monotonic()
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            template_id = str(row.get("template-id") or row.get("templateID") or "")
            matched_at = str(row.get("matched-at") or row.get("host") or "")
            dedup_key = (template_id, matched_at)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            findings.append(
                {
                    "template_id": template_id or None,
                    "name": info.get("name") or row.get("matcher-name"),
                    "severity": info.get("severity", "unknown"),
                    "matched_at": matched_at or None,
                    "source_plugin": "template-scan",
                }
            )
            if len(findings) >= MAX_TEMPLATE_FINDINGS:
                _cleanup_proc(proc, stderr_thread, stdout_thread)
                break

        _cleanup_proc(proc, stderr_thread, stdout_thread)
        exit_code = proc.returncode if proc.returncode is not None else 0
    except OSError as exc:
        return {
            "error": {
                "code": "SPAWN_FAILED",
                "message": str(exc),
                "retryable": True,
            }
        }

    stderr = "".join(stderr_lines)
    recorded_ids = _record_findings(findings, session_id, "template-scan")

    return {
        "plugin_id": "template-scan",
        "exit_code": exit_code,
        "findings_count": len(findings),
        "findings": findings[:50],
        "truncated": len(findings) >= MAX_TEMPLATE_FINDINGS,
        "recorded_finding_ids": recorded_ids,
        "stderr_preview": stderr[:500] if stderr else "",
        "session_id": session_id,
    }
