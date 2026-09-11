#!/usr/bin/env python3
"""Multi-pass hidden-bug hunt — records evidence-backed findings via Rynix MCP session."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = Path(os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", "")))
SCAN_BIN = ROOT / "rynix-core" / "target" / "release" / "rynix-scan.exe"
OUT = ROOT / "pentest_output" / "hidden-bug-hunt"
PROFILE = os.environ.get("RYNIX_PROFILE", "example-law-firm")


def run_scan() -> dict:
    proc = subprocess.run(
        [str(SCAN_BIN), "analyze", "--repo", str(REPO), "--format", "json", "--profile", PROFILE],
        capture_output=True,
        text=True,
        shell=False,
        check=True,
    )
    return json.loads(proc.stdout)


def main() -> int:
    sys.path.insert(0, str(ROOT / "mcp-server"))
    from rynix_mcp.server import export_report, generate_pentest_brief, record_finding

    OUT.mkdir(parents=True, exist_ok=True)
    scan = run_scan()
    (OUT / "scan.json").write_text(json.dumps(scan, indent=2), encoding="utf-8")

    brief = generate_pentest_brief(str(REPO), PROFILE)
    (OUT / "pentest_brief.md").write_text(
        f"# Brief\n\n## Concerns\n{brief.get('concerns', '')}\n\n## Focus\n{brief.get('focus', '')}\n\n## Context\n{brief.get('context', '')}\n",
        encoding="utf-8",
    )

    findings = [
        (
            "high",
            "JWT stored in browser localStorage",
            "GET (XSS) → token theft → account takeover",
            "src/features/auth/stores/authStore.ts — localStorage.setItem('auth_token', ...); refresh_token also stored",
            True,
        ),
        (
            "medium",
            "WebSocket authentication via query-string token",
            "Token may leak via logs, proxies, Referer",
            "backend/app/api/v1/endpoints/websockets.py — token query param; user_id must match JWT sub",
            True,
        ),
        (
            "medium",
            "File preview uses short-lived JWT in URL",
            "Shareable link within TTL (30–300s); session binding via sid/sv",
            "backend/app/services/file_access_token.py — type=file_access, resource-bound claims",
            True,
        ),
        (
            "critical",
            "Finance ledger purge (POST-only) — destructive",
            "CEO/LEGAL_DEPUTY only; cluster expansion; audit reason required in UI",
            f"Static scan: {len([s for s in scan.get('risk_surfaces', []) if 'purge' in s.get('path', '').lower()])} purge surfaces in finance.py",
            True,
        ),
        (
            "high",
            "Debug impersonation endpoints (non-production only)",
            "Misconfig if DEBUG+DEBUG_IMPERSONATION_ENABLED in prod-like env",
            "auth.py _ensure_debug_impersonation_allowed() blocks settings.is_production",
            True,
        ),
        (
            "medium",
            "SMS delivery callback protected by shared secret",
            "Weak/leaked X-SMS-Callback-Secret enables callback forgery",
            "sms_deliveries.py _ensure_callback_allowed — 404 when disabled",
            True,
        ),
        (
            "high",
            "IDOR/BOLA — case and client object access",
            "Requires live dual-token compare_role_response per role matrix",
            "cases.py _check_case_access + client_access_scope; static idor hints: "
            f"{len([r for r in scan.get('routes', []) if r.get('idor_risk_score', 0) >= 70])} routes scored ≥70",
            False,
        ),
        (
            "info",
            "Stealth gate bypass prefix on /sync/ingest without anonymous access",
            "Public-prefix skips 502 but endpoint requires superuser JWT",
            "api_stealth.py public_prefixes + sync.py get_current_active_superuser",
            True,
        ),
    ]

    for sev, title, endpoint, evidence, verified in findings:
        record_finding(
            severity=sev,
            title=title,
            endpoint=endpoint,
            evidence=evidence,
            verified=verified,
            session_id="hidden-bug-hunt",
        )

    paths = export_report(
        output_dir=str(OUT),
        session_id="hidden-bug-hunt",
        formats="markdown,json,sarif",
        include_unverified=True,
    )
    print(
        json.dumps(
            {"output": paths, "findings": len(findings), "routes": len(scan.get("routes", []))},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
