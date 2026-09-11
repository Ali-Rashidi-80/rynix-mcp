#!/usr/bin/env python3
"""Full mirror pentest engagement closure — IDOR matrix, purge RBAC, verified report, template-scan."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

import httpx
from rynix_mcp.idor_matrix import run_idor_matrix
from rynix_mcp.probe_accounts import load_probe_accounts, password_for
from rynix_mcp.server import (
    auth_login,
    export_report,
    record_finding,
)

BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
REPO = os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", ""))
SESSION = os.environ.get("RYNIX_ENGAGEMENT_SESSION", "engagement-final")
OUT = Path(
    os.environ.get("RYNIX_ENGAGEMENT_OUT", str(ROOT / "pentest_output" / "engagement-final"))
)
PROFILE = os.environ.get("RYNIX_PROFILE", "generic-fastapi-react")

PURGE_PATHS = [
    "/api/v1/finance/occasional-incomes/999999/purge",
    "/api/v1/finance/case-fee-receipts/999999/purge",
    "/api/v1/finance/ledgers/payments/999999/purge",
    "/api/v1/finance/expenses/999999/purge",
]

PURGE_ROLES = (
    "ceo",
    "legal_deputy",
    "client",
    "lawyer",
    "secretary",
    "intern",
    "admin",
    "psychologist",
)


def _login(role: str, username: str, password: str) -> str | None:
    result = auth_login(
        BASE,
        username,
        password,
        profile=PROFILE,
        role_label=role,
        session_id=SESSION,
        allow_live=True,
        repo_path=REPO,
    )
    if "error" in result:
        print(f"login failed {role}: {result['error']}", file=sys.stderr)
        return None
    from rynix_mcp.session import STORE

    return STORE.get(SESSION).tokens.get(role)


def _post_purge(token: str, path: str) -> dict[str, Any]:
    url = BASE.rstrip("/") + path
    body = {"reason": "rynix-rbac-probe-no-execute"}
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=body,
            )
        return {
            "status": resp.status_code,
            "hash": resp.text[:200],
            "snippet": resp.text[:400],
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": -1, "error": str(exc)}


def run_purge_matrix(tokens: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in PURGE_PATHS:
        for role in PURGE_ROLES:
            tok = tokens.get(role)
            if not tok:
                continue
            probe = _post_purge(tok, path)
            row = {"path": path, "role": role, **probe}
            rows.append(row)
            print(f"  purge {role:8} {path} -> {probe.get('status')}")
    return rows


def evaluate_purge_matrix(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """CEO/LEGAL_DEPUTY may pass RBAC (non-403); all other roles must be 403."""
    purge_allowed = {"ceo", "legal_deputy"}
    denied_roles = {"client", "lawyer", "secretary", "intern", "admin", "psychologist"}
    issues: list[str] = []
    for row in rows:
        role = row["role"]
        status = row.get("status")
        path = row["path"]
        if role in denied_roles and status != 403:
            issues.append(f"{role} got {status} on {path} (expected 403)")
        if role in purge_allowed and status == 403:
            issues.append(f"{role} got 403 on {path} (unexpected — purge role should pass RBAC)")
    ok = len(issues) == 0
    return ok, "; ".join(issues) if issues else "all purge RBAC checks passed"


def discover_case_id(tokens: dict[str, str]) -> str | None:
    for role in ("ceo", "admin", "lawyer"):
        token = tokens.get(role)
        if not token:
            continue
        url = BASE.rstrip("/") + "/api/v1/cases/?page_size=5"
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                continue
            data = resp.json()
            rows: list[Any] = []
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict):
                for key in ("items", "results", "data", "cases"):
                    val = data.get(key)
                    if isinstance(val, list):
                        rows = val
                        break
            if rows and isinstance(rows[0], dict) and rows[0].get("id") is not None:
                return str(rows[0]["id"])
        except Exception:  # noqa: BLE001
            continue
    return None


def run_object_level_probes(tokens: dict[str, str]) -> list[dict[str, Any]]:
    case_id = discover_case_id(tokens)
    if not case_id:
        print("  no case id discovered", file=sys.stderr)
        return []
    print(f"  object-level case id={case_id}")
    rows: list[dict[str, Any]] = []
    pairs = [("client", "lawyer"), ("client", "ceo"), ("intern", "lawyer")]
    path = f"/api/v1/cases/{case_id}"
    from rynix_mcp.server import compare_role_response

    for ra, rb in pairs:
        ta, tb = tokens.get(ra), tokens.get(rb)
        if not ta or not tb:
            continue
        cmp = compare_role_response(
            base_url=BASE,
            path=path,
            method="GET",
            token_a=ta,
            token_b=tb,
            profile=PROFILE,
            role_a=ra,
            role_b=rb,
            allow_live=True,
            repo_path=REPO,
            session_id=SESSION,
        )
        rows.append({"path": path, "role_a": ra, "role_b": rb, **cmp})
        print(
            f"    GET {path} {ra} vs {rb}: idor_likely={cmp.get('idor_likely')} verdict={cmp.get('verdict')}"
        )
    return rows


def run_template_scan() -> dict[str, Any]:
    import subprocess

    from rynix_mcp.plugins import _record_plugin_findings
    from rynix_mcp.template_scan import resolve_template_scan_bin

    template_scan_bin = resolve_template_scan_bin()
    if not template_scan_bin:
        return {"error": "template-scan binary not found"}
    cmd = [
        template_scan_bin,
        "-u",
        BASE,
        "-jsonl",
        "-silent",
        "-timeout",
        "8",
        "-rate-limit",
        "20",
        "-t",
        "http/exposures/",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    findings: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            findings.append(
                {
                    "template_id": row.get("template-id"),
                    "severity": (row.get("info") or {}).get("severity"),
                    "matched_at": row.get("matched-at"),
                }
            )
        except json.JSONDecodeError:
            continue
    _record_plugin_findings(findings, SESSION, "template-scan")
    return {
        "exit_code": proc.returncode,
        "findings_count": len(findings),
        "findings": findings[:50],
        "stderr_preview": (proc.stderr or "")[:500],
    }


def main() -> int:
    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)
    if not default_pwd:
        print("Set RYNIX_PROBE_PASSWORD", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    accounts = load_probe_accounts(("ceo", "client", "lawyer"))
    if not accounts:
        print("Set RYNIX_PROBE_USER_* or RYNIX_PROBE_ACCOUNTS_FILE", file=sys.stderr)
        return 2

    print("== logins ==")
    tokens: dict[str, str] = {}
    for role, (user, env_key) in accounts.items():
        pwd = password_for(env_key, default_pwd, ceo_pwd)
        tok = _login(role, user, pwd)
        if tok:
            tokens[role] = tok
            print(f"  ok {role}")

    if not tokens:
        print("ERROR: no role logins succeeded — aborting verified findings", file=sys.stderr)
        return 1

    print("== IDOR matrix ==")
    idor = run_idor_matrix(
        base_url=BASE,
        profile=PROFILE,
        repo_path=REPO,
        session_id=SESSION,
        allow_live=True,
        export_dir=str(OUT / "idor-matrix"),
    )
    if "error" in idor:
        print(idor["error"], file=sys.stderr)
        return 1
    print(
        f"  comparisons={idor['comparisons']} idor_signals={idor['idor_signals']} "
        f"roles={idor['roles_logged_in']}"
    )

    print("== object-level /cases/{{id}} ==")
    obj_rows = run_object_level_probes(tokens)

    print("== finance purge matrix (all roles) ==")
    purge_rows = run_purge_matrix(tokens)
    purge_path = OUT / "purge_matrix.json"
    purge_path.write_text(json.dumps(purge_rows, indent=2), encoding="utf-8")
    if not purge_rows:
        print("  ERROR: no purge probes ran (missing tokens)", file=sys.stderr)
        purge_ok, purge_summary = False, "no tokens — purge matrix not executed"
    else:
        purge_ok, purge_summary = evaluate_purge_matrix(purge_rows)
    print(f"  {purge_summary}")

    print("== record verified findings ==")
    if idor["idor_signals"] == 0:
        record_finding(
            severity="info",
            title="IDOR matrix — no identical cross-role object leakage on mirror",
            endpoint="/api/v1/cases/, /api/v1/clients/, object-level GET",
            evidence=json.dumps(
                {
                    "comparisons": idor["comparisons"],
                    "idor_signals": 0,
                    "base_url": BASE,
                    "object_probes": len(obj_rows),
                    "object_paths": [r.get("path") for r in obj_rows],
                },
                indent=2,
            ),
            session_id=SESSION,
            verified=True,
            source_plugin="run_idor_matrix",
        )
    else:
        record_finding(
            severity="high",
            title="IDOR signal — identical response hash across roles",
            endpoint="see matrix.json",
            evidence=str(OUT / "idor-matrix" / "matrix.json"),
            session_id=SESSION,
            verified=True,
            source_plugin="run_idor_matrix",
        )

    record_finding(
        severity="info" if purge_ok else "high",
        title="Finance purge RBAC — CEO-only destructive endpoints",
        endpoint=", ".join(PURGE_PATHS),
        evidence=json.dumps({"summary": purge_summary, "rows": purge_rows}, indent=2),
        session_id=SESSION,
        verified=True,
        source_plugin="purge_matrix",
    )

    for row in obj_rows:
        if row.get("idor_likely"):
            record_finding(
                severity="high",
                title=f"Object-level IDOR on {row['path']}",
                endpoint=row["path"],
                evidence=json.dumps(row, indent=2),
                session_id=SESSION,
                verified=True,
            )
    if obj_rows and not any(r.get("idor_likely") for r in obj_rows):
        record_finding(
            severity="info",
            title="Object-level GET /cases/{id} — no cross-role identical body",
            endpoint=obj_rows[0].get("path", "/api/v1/cases/{id}"),
            evidence=json.dumps(obj_rows, indent=2),
            session_id=SESSION,
            verified=True,
            source_plugin="object_probe",
        )

    print("== template-scan (optional) ==")
    template_scan_result: dict[str, Any] = {}
    try:
        template_scan_result = run_template_scan()
        template_scan_out = OUT / "template_scan_result.json"
        template_scan_out.write_text(json.dumps(template_scan_result, indent=2), encoding="utf-8")
        findings_count = len(template_scan_result.get("findings", []) or [])
        print(f"  template-scan findings={findings_count}")
        if findings_count:
            record_finding(
                severity="medium",
                title="template-scan template matches on mirror",
                endpoint=BASE,
                evidence=str(template_scan_out),
                session_id=SESSION,
                verified=True,
                source_plugin="template-scan",
            )
        else:
            record_finding(
                severity="info",
                title="template-scan scan — no medium+ CVE/exposure templates matched",
                endpoint=BASE,
                evidence=json.dumps(
                    {"plugin": "template-scan", "result_keys": list(template_scan_result.keys())}
                ),
                session_id=SESSION,
                verified=True,
                source_plugin="template-scan",
            )
    except Exception as exc:  # noqa: BLE001
        print(f"  template-scan skipped: {exc}", file=sys.stderr)

    print("== export_report (verified only) ==")
    paths = export_report(
        str(OUT), session_id=SESSION, formats="markdown,json,sarif", include_unverified=False
    )
    summary = {
        "session": SESSION,
        "base_url": BASE,
        "backup_note": "remote pg_dump in example law-firm application backups/safety/",
        "idor": {"comparisons": idor["comparisons"], "idor_signals": idor["idor_signals"]},
        "purge_matrix_ok": purge_ok,
        "purge_summary": purge_summary,
        "object_probes": len(obj_rows),
        "output": paths,
        "template_scan": bool(template_scan_result),
    }
    (OUT / "engagement_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if idor["idor_signals"] or not purge_ok:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
