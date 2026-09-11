#!/usr/bin/env python3
"""Full mirror + production engagement — read-only prod, live mirror IDOR/finance."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
sys.path.insert(0, str(MCP_SERVER))
sys.path.insert(0, str(ROOT / "scripts"))

from target_env import engagement_profile, require_target_repo

TARGET_REPO = require_target_repo()
MIRROR_BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
PROD_BASE = os.environ.get("RYNIX_REMOTE_URL", os.environ.get("RYNIX_PROD_BASE_URL", "")).strip()
PROFILE = engagement_profile(TARGET_REPO)
OUT = ROOT / "pentest_output" / f"full-engagement-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"


def _save(name: str, data: object) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  wrote {path.name}")


def main() -> int:
    from rynix_mcp.config import PROFILES_DIR
    from rynix_mcp.http_session import request as http_request
    from rynix_mcp.idor_matrix import run_idor_matrix
    from rynix_mcp.probe_accounts import load_probe_accounts, password_for
    from rynix_mcp.profiles import load_profile
    from rynix_mcp.server import (
        analyze_repo,
        auth_login,
        compare_role_response,
        generate_pentest_brief,
        health_check,
        scope_check,
    )
    from rynix_mcp.session import STORE
    from rynix_mcp.stealth_gate import load_gate_secret

    prof = load_profile(PROFILE, PROFILES_DIR, TARGET_REPO)
    report: dict[str, object] = {"started_at": datetime.now(UTC).isoformat()}
    repo = str(TARGET_REPO)
    accounts = load_probe_accounts()
    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)

    print("== static ==")
    report["health"] = health_check(repo_path=repo)
    scan = analyze_repo(repo, profile=PROFILE)
    report["analyze_repo"] = {
        "routes": len(scan.get("routes", [])),
        "modules": scan.get("modules_scanned"),
    }
    report["brief"] = generate_pentest_brief(repo, profile=PROFILE)

    print("== production read-only ==")
    if not PROD_BASE:
        report["prod_skipped"] = "RYNIX_REMOTE_URL not set"
    else:
        prod_scope = scope_check(PROD_BASE, PROFILE, repo_path=repo)
        report["prod_scope"] = prod_scope
        gate = load_gate_secret(prof, repo)
        report["prod_gate_secret_loaded"] = bool(gate)
        if prod_scope.get("allowed"):
            from rynix_mcp.http_session import ensure_stealth_gate, session_cookies

            if gate:
                report["prod_gate_unlock"] = ensure_stealth_gate(
                    PROD_BASE, session_id="prod-engagement", profile=prof, repo_path=repo
                )
                report["prod_gate_cookies"] = list(
                    session_cookies(PROD_BASE, session_id="prod-engagement").keys()
                )
            for path in ("/health", "/ready"):
                try:
                    resp = http_request(
                        PROD_BASE,
                        "GET",
                        path,
                        session_id="prod-engagement",
                        follow_redirects=False,
                    )
                    report[f"prod_{path.strip('/')}"] = {"status": resp.status_code}
                except Exception as exc:  # noqa: BLE001
                    report[f"prod_{path.strip('/')}"] = {"error": str(exc)}
            try:
                cases_resp = http_request(
                    PROD_BASE,
                    "GET",
                    "/api/v1/cases/",
                    session_id="prod-engagement",
                )
                report["prod_cases_unauth"] = {"status": cases_resp.status_code}
            except Exception as exc:  # noqa: BLE001
                report["prod_cases_unauth"] = {"error": str(exc)}

            if default_pwd and accounts.get("client") and accounts.get("ceo"):
                print("== production read-only IDOR sample (GET) ==")
                psid = "prod-readonly"
                prod_logins: list[str] = []
                prod_login_errors: list[dict[str, object]] = []
                import time as _time

                for role in ("client", "ceo"):
                    username, env_key = accounts[role]
                    login = auth_login(
                        PROD_BASE,
                        username,
                        password_for(env_key, default_pwd, ceo_pwd),
                        profile=PROFILE,
                        role_label=role,
                        session_id=psid,
                        allow_live=True,
                        repo_path=repo,
                    )
                    if "error" in login:
                        prod_login_errors.append({"role": role, "error": login["error"]})
                    elif STORE.get(psid).tokens.get(role):
                        prod_logins.append(role)
                    _time.sleep(0.75)
                report["prod_roles_logged_in"] = prod_logins
                report["prod_login_errors"] = prod_login_errors
                tokens_prod = STORE.get(psid).tokens
                if tokens_prod.get("client") and tokens_prod.get("ceo"):
                    prod_cmp = compare_role_response(
                        PROD_BASE,
                        "/api/v1/cases/",
                        "GET",
                        tokens_prod["client"],
                        tokens_prod["ceo"],
                        profile=PROFILE,
                        role_a="client",
                        role_b="ceo",
                        allow_live=True,
                        repo_path=repo,
                        session_id=psid,
                    )
                    report["prod_idor_sample"] = {
                        "path": "/api/v1/cases/",
                        "verdict": prod_cmp.get("verdict"),
                        "idor_likely": prod_cmp.get("idor_likely"),
                        "diff": prod_cmp.get("diff"),
                    }
                elif prod_login_errors:
                    report["prod_idor_sample"] = {
                        "skipped": "production login failed — use mirror IDOR matrix as authoritative",
                        "errors": prod_login_errors,
                    }
            else:
                report["prod_idor_sample"] = {"skipped": "probe credentials not configured"}
        else:
            report["prod_skipped"] = "scope denied"

    print("== mirror live ==")
    mirror_scope = scope_check(MIRROR_BASE, PROFILE, repo_path=repo)
    report["mirror_scope"] = mirror_scope
    if mirror_scope.get("allowed"):
        for path in ("/health", "/ready"):
            resp = http_request(MIRROR_BASE, "GET", path, follow_redirects=False)
            report[f"mirror_{path.strip('/')}"] = {"status": resp.status_code}

        matrix = run_idor_matrix(
            MIRROR_BASE,
            profile=PROFILE,
            repo_path=repo,
            session_id="full-engagement",
            allow_live=True,
            export_dir=str(OUT / "idor-matrix"),
        )
        report["idor_matrix"] = {
            k: matrix.get(k)
            for k in (
                "roles_logged_in",
                "login_errors",
                "warnings",
                "coverage_note",
                "comparisons",
                "idor_signals",
                "error",
            )
        }

        print("== finance purge (real event discovery) ==")
        sid = "finance-real"
        for role in ("client", "ceo", "legal_deputy"):
            if role not in accounts:
                continue
            username, env_key = accounts[role]
            auth_login(
                MIRROR_BASE,
                username,
                password_for(env_key, default_pwd, ceo_pwd),
                profile=PROFILE,
                role_label=role,
                session_id=sid,
                allow_live=True,
                repo_path=repo,
            )
        tokens = STORE.get(sid).tokens
        event_id = None
        discover = tokens.get("ceo") or tokens.get("legal_deputy")
        if discover:
            resp = http_request(
                MIRROR_BASE,
                "GET",
                "/api/v1/finance/ledgers/receipts?page_size=5",
                session_id=sid,
                headers={"Authorization": f"Bearer {discover}"},
            )
            report["finance_list_status"] = resp.status_code
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items") if isinstance(data, dict) else data
                if isinstance(items, list) and items:
                    row = items[0]
                    if isinstance(row, dict):
                        event_id = row.get("id") or row.get("event_id")
        report["finance_event_id"] = event_id
        if event_id:
            purge_path = f"/api/v1/finance/case-fee-receipts/{event_id}/purge"
            for ra, rb in (("client", "ceo"), ("client", "legal_deputy"), ("intern", "ceo")):
                if ra in tokens and rb in tokens:
                    cmp = compare_role_response(
                        MIRROR_BASE,
                        purge_path,
                        "POST",
                        tokens[ra],
                        tokens[rb],
                        profile=PROFILE,
                        role_a=ra,
                        role_b=rb,
                        allow_live=True,
                        allow_write=True,
                        repo_path=repo,
                        session_id=sid,
                    )
                    report.setdefault("finance_purge", {})[f"{ra}_vs_{rb}"] = {
                        "verdict": cmp.get("verdict"),
                        "idor_likely": cmp.get("idor_likely"),
                        "diff": cmp.get("diff"),
                    }
        else:
            report["finance_purge"] = {"skipped": "no reversible finance event on mirror"}

    print("== export report ==")
    from rynix_mcp.server import export_report

    export_paths = export_report(
        str(OUT / "report"),
        session_id="full-engagement",
        formats="markdown,json,sarif,html",
    )
    report["export"] = export_paths

    _save("engagement-report.json", report)
    print(f"\nFull engagement complete -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
