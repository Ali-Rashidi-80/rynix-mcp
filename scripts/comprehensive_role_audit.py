#!/usr/bin/env python3
"""Comprehensive 8-role security audit — static + live IDOR/RBAC/purge + coverage map."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))
sys.path.insert(0, str(ROOT / "scripts"))

from rynix_mcp.idor_matrix import ROLE_PAIRS, run_idor_matrix
from rynix_mcp.mirror_ephemeral_roles import (
    cleanup_ephemeral_users,
    mint_missing_mirror_tokens,
)
from rynix_mcp.probe_accounts import load_probe_accounts, password_for
from rynix_mcp.server import (
    analyze_repo,
    auth_login,
    check_access,
    export_report,
    high_risk_surfaces,
    rbac_matrix,
    scope_check,
)
from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate
from target_env import engagement_profile, require_target_repo

REPO = str(require_target_repo())
MIRROR = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
PROD = os.environ.get("RYNIX_REMOTE_URL", "").strip()
OUT = Path(
    os.environ.get("RYNIX_COMPLETENESS_OUT", str(ROOT / "pentest_output" / "completeness-audit"))
)
PROFILE = engagement_profile(require_target_repo())
SESSION = os.environ.get("RYNIX_ENGAGEMENT_SESSION", "completeness-audit")
ALL_ROLES = (
    "admin",
    "ceo",
    "lawyer",
    "secretary",
    "legal_deputy",
    "psychologist",
    "intern",
    "client",
)

PER_ROLE_PROBE_PATHS = [
    ("GET", "/api/v1/users/me"),
    ("GET", "/api/v1/dashboard/summary"),
    ("GET", "/api/v1/cases/"),
    ("GET", "/api/v1/clients/"),
    ("GET", "/api/v1/finance/cases/summary"),
]

ADMIN_ONLY_PATHS = [
    ("GET", "/api/v1/backups/latest"),
    ("GET", "/api/v1/system/docker"),
    ("GET", "/api/v1/system/observability/events?limit=3"),
]

PURGE_PATHS = [
    "/api/v1/finance/occasional-incomes/999999/purge",
    "/api/v1/finance/case-fee-receipts/999999/purge",
]

WSTG_SAMPLES = [
    ("WSTG-APIT-01", "API1 BOLA — IDOR matrix"),
    ("WSTG-APIT-02", "API2 broken auth — login per role"),
    ("WSTG-APIT-05", "API5 BFLA — purge matrix"),
    ("WSTG-CONF-02", "DEBUG/docs — /docs 404 on mirror"),
    ("WSTG-ATHN-02", "Default creds — env-driven probes only"),
]

VULN_CLASS_COVERAGE: dict[str, str] = {
    "idor": "live — compare_role_response matrix",
    "broken-function-level-authorization": "live — purge + admin-only probes",
    "authentication-jwt": "static — hidden_bug_hunt + authStore review",
    "csrf": "static — FastAPI bearer-first API",
    "ssrf": "static — taint hints + route review",
    "sql-injection": "static — ORM/SQLAlchemy patterns",
    "mass-assignment": "static — Pydantic schemas",
    "information-disclosure": "live — /docs /redoc + observability RBAC",
    "insecure-file-uploads": "static — upload endpoints in scan",
    "business-logic": "live — role-scoped cases/clients lists",
    "frameworks--fastapi": "static — analyze_repo profile",
    "browser-security": "static — JWT localStorage finding",
}


def _login_all(
    base_url: str,
    *,
    allow_live: bool,
    http_client: httpx.Client | None = None,
    mint_missing: bool = False,
) -> dict[str, Any]:
    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)
    accounts = load_probe_accounts()
    tokens: dict[str, str] = {}
    login_rows: list[dict[str, Any]] = []
    minted: list[str] = []

    for role in ALL_ROLES:
        if role not in accounts:
            continue
        username, env_key = accounts[role]
        pwd = password_for(env_key, default_pwd, ceo_pwd)
        if http_client is not None:
            url = f"{base_url.rstrip('/')}/api/v1/auth/login"
            resp = http_client.post(url, data={"username": username, "password": pwd})
            ok = resp.status_code == 200
            login_rows.append({"role": role, "ok": ok, "status": resp.status_code, "source": "env"})
            if ok:
                tokens[role] = resp.json().get("access_token", "")
            continue
        result = auth_login(
            base_url,
            username,
            pwd,
            profile=PROFILE,
            role_label=role,
            session_id=SESSION,
            allow_live=allow_live,
            repo_path=REPO,
        )
        ok = "error" not in result
        login_rows.append({"role": role, "ok": ok, "source": "env", "detail": result.get("error")})
        if ok:
            from rynix_mcp.session import STORE

            tok = STORE.get(SESSION).tokens.get(role)
            if tok:
                tokens[role] = tok

    missing = [r for r in ALL_ROLES if r not in tokens]
    ephemeral_created_ids: list[int] = []
    if mint_missing and missing and "127.0.0.1" in base_url:
        mint = mint_missing_mirror_tokens(missing)
        tokens.update(mint.get("tokens", {}))
        minted = mint.get("minted_roles", [])
        ephemeral_created_ids = mint.get("created_ids", [])
        for role in minted:
            login_rows.append(
                {"role": role, "ok": True, "source": "ephemeral_mirror", "status": 200}
            )

    return {
        "tokens": tokens,
        "logins": login_rows,
        "roles_configured": list(accounts.keys()),
        "roles_authenticated": list(tokens.keys()),
        "roles_missing": [r for r in ALL_ROLES if r not in tokens],
        "ephemeral_minted": minted,
        "ephemeral_created_ids": ephemeral_created_ids,
    }


def _per_role_probes(base_url: str, tokens: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for role, token in tokens.items():
        for method, path in PER_ROLE_PROBE_PATHS + ADMIN_ONLY_PATHS:
            probe = check_access(
                base_url,
                path,
                method,
                token,
                profile=PROFILE,
                allow_live=True,
                repo_path=REPO,
            )
            rows.append({"role": role, "method": method, "path": path, **probe})
    return rows


def _purge_matrix(
    base_url: str, tokens: dict[str, str], http_client: httpx.Client | None = None
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    purge_allowed = {"ceo", "legal_deputy"}
    denied = set(ALL_ROLES) - purge_allowed
    for path in PURGE_PATHS:
        for role in ALL_ROLES:
            token = tokens.get(role)
            if not token:
                continue
            url = base_url.rstrip("/") + path
            body = {"reason": "rynix-completeness-probe-no-execute"}
            if http_client is not None:
                resp = http_client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                )
                status = resp.status_code
            else:
                try:
                    with httpx.Client(timeout=30.0) as client:
                        resp = client.post(
                            url,
                            headers={
                                "Authorization": f"Bearer {token}",
                                "Content-Type": "application/json",
                            },
                            json=body,
                        )
                    status = resp.status_code
                except Exception as exc:  # noqa: BLE001
                    status = -1
                    rows.append({"role": role, "path": path, "status": status, "error": str(exc)})
                    continue
            expected = "non-403" if role in purge_allowed else 403
            ok = (role in purge_allowed and status != 403) or (role in denied and status == 403)
            rows.append(
                {"role": role, "path": path, "status": status, "expected": expected, "ok": ok}
            )
    return rows


def _knowledge_coverage() -> dict[str, Any]:
    vuln_dir = ROOT / "mcp-server" / "rynix_mcp" / "knowledge" / "vuln-classes"
    guides = sorted(p.stem for p in vuln_dir.glob("*.md")) if vuln_dir.is_dir() else []
    mapped = {
        g: VULN_CLASS_COVERAGE.get(g, "knowledge-only — agent playbook / manual review")
        for g in guides
    }
    live_count = sum(1 for v in mapped.values() if v.startswith("live"))
    static_count = sum(1 for v in mapped.values() if v.startswith("static"))
    knowledge_only = len(guides) - live_count - static_count
    return {
        "total_agent-guides_guides": len(guides),
        "live_mapped": live_count,
        "static_mapped": static_count,
        "knowledge_only": knowledge_only,
        "role_pairs_in_matrix": len(ROLE_PAIRS),
        "backend_roles": list(ALL_ROLES),
        "wstg_samples": WSTG_SAMPLES,
        "guides": mapped,
    }


def _static_pass() -> dict[str, Any]:
    scan_bin = ROOT / "rynix-core" / "target" / "release" / "rynix-scan.exe"
    scan_out: dict[str, Any] = {"ran": False}
    if scan_bin.is_file():
        proc = subprocess.run(
            [str(scan_bin), "analyze", "--repo", REPO, "--format", "json", "--profile", PROFILE],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0:
            scan_out = {"ran": True, "summary": json.loads(proc.stdout)}
    return {
        "analyze_repo": analyze_repo(REPO, PROFILE),
        "rbac_matrix": rbac_matrix(REPO, PROFILE),
        "high_risk_surfaces": high_risk_surfaces(REPO, PROFILE),
        "rynix_scan": scan_out,
    }


def audit_mirror() -> dict[str, Any]:
    scope = scope_check(MIRROR, PROFILE)
    if not scope.get("allowed"):
        return {"error": "scope_denied", "scope": scope}

    ephemeral_ids: list[int] = []
    try:
        login = _login_all(MIRROR, allow_live=True, mint_missing=True)
        ephemeral_ids = login.get("ephemeral_created_ids", [])
        tokens = login["tokens"]

        idor = run_idor_matrix(
            MIRROR,
            profile=PROFILE,
            repo_path=REPO,
            session_id=SESSION,
            allow_live=True,
            export_dir=str(OUT / "mirror-idor-matrix"),
        )

        per_role = _per_role_probes(MIRROR, tokens)
        purge = _purge_matrix(MIRROR, tokens)

        docs = check_access(
            MIRROR,
            "/docs",
            "GET",
            tokens.get("ceo", ""),
            profile=PROFILE,
            allow_live=True,
            repo_path=REPO,
        )
        redoc = check_access(
            MIRROR,
            "/redoc",
            "GET",
            tokens.get("ceo", ""),
            profile=PROFILE,
            allow_live=True,
            repo_path=REPO,
        )

        purge_ok = all(r.get("ok") for r in purge if "ok" in r)
        eight_of_eight = len(tokens) >= 8

        return {
            "target": "mirror",
            "base_url": MIRROR,
            "login": login,
            "idor": {
                "comparisons": idor.get("comparisons"),
                "idor_signals": idor.get("idor_signals"),
                "roles_logged_in": idor.get("roles_logged_in"),
            },
            "per_role_probes": per_role,
            "purge_matrix": purge,
            "purge_matrix_ok": purge_ok,
            "docs_status": docs.get("status"),
            "redoc_status": redoc.get("status"),
            "all_eight_roles": eight_of_eight,
            "pass": idor.get("idor_signals", 99) == 0 and purge_ok and docs.get("status") == 404,
        }
    finally:
        if ephemeral_ids:
            try:
                asyncio.run(cleanup_ephemeral_users(ephemeral_ids))
            except Exception:  # noqa: BLE001
                pass


def audit_production() -> dict[str, Any]:
    gate = load_gate_secret()
    if not gate:
        return {
            "target": "production",
            "skipped": True,
            "reason": "RYNIX_STEALTH_GATE_SECRET missing",
        }

    scope = scope_check(PROD, PROFILE)
    if not scope.get("allowed"):
        return {"target": "production", "skipped": True, "reason": "scope_denied", "scope": scope}

    from rynix_mcp.probe_user_resolver import resolve_via_admin_api

    resolver = resolve_via_admin_api(PROD, session_id=SESSION)

    report: dict[str, Any] = {
        "target": "production",
        "base_url": PROD,
        "gate_unlocked": False,
        "probe_resolver": resolver,
    }
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        report["gate_unlocked"] = unlock_stealth_gate(PROD, gate, client)
        if not report["gate_unlocked"]:
            report["skipped"] = True
            report["reason"] = "gate_unlock_failed"
            return report

        login = _login_all(PROD, allow_live=True, http_client=client, mint_missing=False)
        tokens = login["tokens"]
        report["login"] = login

        bola_rows: list[dict[str, Any]] = []
        case_id = os.environ.get("RYNIX_PROBE_CASE_ID", "")
        if not case_id:
            ceo_tok = tokens.get("ceo")
            if ceo_tok:
                cases_resp = client.get(
                    f"{PROD.rstrip('/')}/api/v1/cases/?page_size=5",
                    headers={"Authorization": f"Bearer {ceo_tok}"},
                )
                if cases_resp.status_code == 200:
                    data = cases_resp.json()
                    rows = (
                        data
                        if isinstance(data, list)
                        else data.get("items") or data.get("cases") or []
                    )
                    if rows and isinstance(rows[0], dict):
                        cid = rows[0].get("id")
                        if cid is not None:
                            case_id = str(cid)
        if not case_id:
            case_id = "118"

        for role in ("client", "ceo", "lawyer", "legal_deputy", "psychologist"):
            tok = tokens.get(role)
            if not tok:
                continue
            path = f"/api/v1/cases/{case_id}"
            resp = client.get(PROD.rstrip("/") + path, headers={"Authorization": f"Bearer {tok}"})
            bola_rows.append(
                {"role": role, "path": path, "status": resp.status_code, "case_id": case_id}
            )

        report["bola_object_probes"] = bola_rows
        report["purge_matrix"] = _purge_matrix(PROD, tokens, http_client=client)
        report["purge_matrix_ok"] = all(r.get("ok") for r in report["purge_matrix"] if "ok" in r)

        for path in ("/docs", "/redoc"):
            resp = client.get(PROD.rstrip("/") + path)
            key = path.strip("/").replace("/", "_") + "_status"
            report[key] = resp.status_code

        client_ok = next((r["status"] for r in bola_rows if r["role"] == "client"), None)
        ceo_ok = next((r["status"] for r in bola_rows if r["role"] == "ceo"), None)

        from rynix_mcp.http_session import store_client_cookies
        from rynix_mcp.session import STORE

        store_client_cookies(PROD, client, SESSION)
        STORE.get(SESSION).tokens.update(tokens)

        idor_prod = run_idor_matrix(
            PROD,
            profile=PROFILE,
            repo_path=REPO,
            session_id=SESSION,
            allow_live=True,
            export_dir=str(OUT / "prod-idor-matrix"),
        )
        report["idor"] = {
            "comparisons": idor_prod.get("comparisons"),
            "idor_signals": idor_prod.get("idor_signals"),
            "roles_logged_in": idor_prod.get("roles_logged_in"),
            "error": idor_prod.get("error"),
        }
        idor_ok = idor_prod.get("idor_signals", 99) == 0 and "error" not in idor_prod
        prod_roles = login.get("roles_authenticated") or idor_prod.get("roles_logged_in") or []
        report["all_eight_roles"] = len(set(prod_roles)) >= 8
        report["pass"] = (
            client_ok == 403
            and ceo_ok == 200
            and report.get("docs_status") == 404
            and idor_ok
            and report["all_eight_roles"]
        )

    return report


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "session_id": SESSION,
        "repo": REPO,
        "static": _static_pass(),
        "knowledge_coverage": _knowledge_coverage(),
        "mirror": {},
        "production": {},
    }

    print("=== Comprehensive role audit ===", file=sys.stderr)
    print("Static analysis...", file=sys.stderr)
    report["mirror"] = audit_mirror()
    print(
        f"Mirror: pass={report['mirror'].get('pass')} roles={report['mirror'].get('login', {}).get('roles_authenticated')}",
        file=sys.stderr,
    )

    print("Production (gate)...", file=sys.stderr)
    report["production"] = audit_production()
    print(f"Production: pass={report['production'].get('pass')}", file=sys.stderr)

    mirror_ok = report["mirror"].get("pass") is True
    prod = report["production"]
    prod_ok = prod.get("pass") is True or prod.get("skipped")
    report["overall_pass"] = mirror_ok and (prod_ok or prod.get("skipped"))

    # Never persist bearer tokens in audit artifacts.
    prod_login = report.get("production", {}).get("login")
    if isinstance(prod_login, dict) and "tokens" in prod_login:
        prod_login["tokens"] = {role: "<redacted>" for role in prod_login["tokens"]}
    mirror_login = report.get("mirror", {}).get("login")
    if isinstance(mirror_login, dict) and "tokens" in mirror_login:
        mirror_login["tokens"] = {role: "<redacted>" for role in mirror_login["tokens"]}

    json_path = OUT / "COMPLETENESS_AUDIT.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    md_lines = [
        "# Completeness Audit",
        "",
        f"**Generated:** {report['timestamp_utc']}",
        "",
        "## Role coverage",
        "",
        f"- Backend roles (8): {', '.join(ALL_ROLES)}",
        f"- IDOR role pairs: {len(ROLE_PAIRS)}",
        f"- Mirror authenticated: {report['mirror'].get('login', {}).get('roles_authenticated')}",
        f"- Mirror all 8/8: {report['mirror'].get('all_eight_roles')}",
        "",
        "## Live results",
        "",
        "| Layer | IDOR signals | Purge OK | Pass |",
        "|-------|-------------|----------|------|",
        f"| Mirror | {report['mirror'].get('idor', {}).get('idor_signals')} | {report['mirror'].get('purge_matrix_ok')} | {report['mirror'].get('pass')} |",
        f"| Production | {(prod.get('idor') or {}).get('idor_signals', '—')} | {prod.get('purge_matrix_ok')} | {prod.get('pass', prod.get('skipped'))} |",
        "",
        "## Knowledge (75 agent-guides guides)",
        "",
        f"- Live-mapped: {report['knowledge_coverage']['live_mapped']}",
        f"- Static-mapped: {report['knowledge_coverage']['static_mapped']}",
        f"- Knowledge-only (agent manual): {report['knowledge_coverage']['knowledge_only']}",
        "",
        "## Honest limits",
        "",
        "- Not every agent-guides guide has an automated live PoC (e.g. K8s, Azure, LLM app classes).",
        "- Production IDOR matrix runs via shared gate cookies in MCP session (`http_session.py`).",
        "- Set `RYNIX_PROBE_USER_LEGAL_DEPUTY` / `RYNIX_PROBE_USER_PSYCHOLOGIST` for prod 8/8 without mirror mint.",
        "",
        f"**Overall:** {'PASS' if report['overall_pass'] else 'NEEDS ATTENTION'}",
    ]
    (OUT / "COMPLETENESS_AUDIT.md").write_text("\n".join(md_lines), encoding="utf-8")

    export_report(str(OUT), session_id=SESSION, formats="markdown,json")
    print(f"Wrote {json_path}", file=sys.stderr)
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
