#!/usr/bin/env python3
"""example-law-firm profile — full live engagement (health, scope, IDOR matrix, report)."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
DEFAULT_ACCOUNTS = ROOT / "examples" / "probe-accounts.example.json"


def _resolve_target_repo() -> Path:
    raw = os.environ.get("RYNIX_TARGET_REPO", "").strip()
    if not raw:
        raise SystemExit("Set RYNIX_TARGET_REPO to the target application repo root")
    return Path(raw)


def _resolve_base_url(repo: Path) -> str:
    if os.environ.get("RYNIX_PROBE_BASE_URL", "").strip():
        return os.environ["RYNIX_PROBE_BASE_URL"].strip().rstrip("/")
    ports_file = repo / ".local-mirror-ports.json"
    if ports_file.is_file():
        data = json.loads(ports_file.read_text(encoding="utf-8"))
        port = data.get("backend") or data.get("LOCAL_BACKEND_PORT")
        if port:
            return f"http://127.0.0.1:{port}"
    port = os.environ.get("LOCAL_BACKEND_PORT", "8001")
    return f"http://127.0.0.1:{port}"


def _bootstrap_probe_env(repo: Path) -> None:
    accounts_file = os.environ.get("RYNIX_PROBE_ACCOUNTS_FILE", "").strip()
    if not accounts_file:
        candidate = repo / ".pentest" / "probe-accounts.json"
        if candidate.is_file():
            accounts_file = str(candidate)
        elif DEFAULT_ACCOUNTS.is_file():
            accounts_file = str(DEFAULT_ACCOUNTS)
    if accounts_file:
        os.environ.setdefault("RYNIX_PROBE_ACCOUNTS_FILE", accounts_file)
    os.environ.setdefault("RYNIX_PROBE_PROFILE", "example-law-firm")
    os.environ.setdefault("RYNIX_GATE10_LIVE", "1")


def main() -> int:
    repo = _resolve_target_repo()
    base = _resolve_base_url(repo)
    _bootstrap_probe_env(repo)
    os.environ.setdefault("RYNIX_TARGET_REPO", str(repo))

    sys.path.insert(0, str(MCP))
    from rynix_mcp.http_session import request as http_request
    from rynix_mcp.idor_matrix import run_idor_matrix
    from rynix_mcp.server import (
        analyze_repo,
        export_report,
        generate_pentest_brief,
        health_check,
        list_profiles,
        register_scope,
        scope_check,
        unlock_stealth_gate,
    )

    session_id = f"example-law-firm-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    profile = os.environ.get("RYNIX_PROBE_PROFILE", "example-law-firm")
    out_dir = ROOT / "pentest_output" / "example-law-firm-live"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Target repo: {repo}")
    print(f"Base URL:    {base}")
    print(f"Session:     {session_id}")

    health = health_check()
    if not health.get("ok"):
        print(f"FAIL MCP health: {health}", file=sys.stderr)
        return 1
    print("PASS MCP health")

    profiles = list_profiles()
    if profile not in {p.get("name") for p in profiles.get("profiles", [])}:
        print(f"WARN profile {profile} not in list_profiles", file=sys.stderr)

    try:
        resp = http_request(base, "GET", "/health", session_id=session_id, follow_redirects=False)
        if resp.status_code != 200:
            print(f"FAIL backend /health status={resp.status_code}", file=sys.stderr)
            return 1
        print(f"PASS backend /health {resp.status_code}")
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL backend unreachable: {exc}", file=sys.stderr)
        return 1

    scope = scope_check(base_url=base, profile=profile)
    if not scope.get("allowed"):
        print(f"FAIL scope_check: {scope}", file=sys.stderr)
        return 1
    print("PASS scope_check")

    register_scope(host="127.0.0.1", session_id=session_id)
    gate = unlock_stealth_gate(base_url=base, session_id=session_id)
    print(f"stealth gate: {gate.get('ok', gate.get('unlocked', gate))}")

    repo_scan = analyze_repo(repo_path=str(repo), profile=profile)
    print(
        f"analyze_repo modules={repo_scan.get('modules_scanned', 0)} routes={len(repo_scan.get('routes', []))}"
    )

    brief = generate_pentest_brief(repo_path=str(repo), profile=profile)
    brief_path = out_dir / f"brief-{session_id}.json"
    brief_path.write_text(json.dumps(brief, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {brief_path}")

    matrix = run_idor_matrix(
        base_url=base,
        profile=profile,
        session_id=session_id,
        repo_path=str(repo),
        allow_live=True,
    )
    matrix_path = out_dir / f"idor-matrix-{session_id}.json"
    matrix_path.write_text(json.dumps(matrix, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {matrix_path}")

    if matrix.get("error"):
        print(f"FAIL idor_matrix: {matrix['error']}", file=sys.stderr)
        return 1

    comparisons = matrix.get("comparisons", 0)
    signals = matrix.get("idor_signals", 0)
    print(f"IDOR matrix comparisons={comparisons} idor_signals={signals}")

    report = export_report(
        output_dir=str(out_dir / session_id),
        session_id=session_id,
        formats="json",
    )
    print(f"export_report: {report}")

    if signals != 0:
        print(f"WARN idor_signals={signals} (review matrix JSON)", file=sys.stderr)
        return 2

    print("PASS example-law-firm live engagement — idor_signals=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
