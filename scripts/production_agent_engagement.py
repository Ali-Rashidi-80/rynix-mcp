#!/usr/bin/env python3
"""Production agent engagement — stealth gate unlock + live probes (read-only)."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from rynix_mcp.probe_accounts import load_probe_accounts, password_for
from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate

OUT = Path(
    os.environ.get(
        "RYNIX_PROD_ENGAGEMENT_OUT", str(ROOT / "pentest_output" / "cursor-agent-prod-1")
    )
)
BASE = os.environ.get("RYNIX_REMOTE_URL", "").strip()
PWD = os.environ.get("RYNIX_PROBE_PASSWORD", "")
PWD_CEO = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", PWD)


def main() -> int:
    gate = load_gate_secret()
    if not gate:
        print("RYNIX_STEALTH_GATE_SECRET required", file=sys.stderr)
        return 2
    if not PWD:
        print("RYNIX_PROBE_PASSWORD required", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)
    report: dict = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "base_url": BASE,
        "gate_unlocked": False,
        "steps": [],
        "bola_probes": [],
        "routes": [],
        "idor_summary": None,
    }

    accounts = load_probe_accounts(("client", "ceo", "lawyer"))
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        report["gate_unlocked"] = unlock_stealth_gate(BASE, gate, client)
        report["steps"].append({"name": "gate_unlock", "ok": report["gate_unlocked"]})
        if not report["gate_unlocked"]:
            OUT.joinpath("engagement_summary.json").write_text(
                json.dumps(report, indent=2), encoding="utf-8"
            )
            return 1

        live = client.get(f"{BASE.rstrip('/')}/health/live")
        live_ok = live.status_code == 200
        report["steps"].append({"name": "health_live", "ok": live_ok, "status": live.status_code})

        tokens: dict[str, str] = {}
        for role in ("client", "ceo", "lawyer"):
            if role not in accounts:
                continue
            username, pwd_env = accounts[role]
            r = client.post(
                f"{BASE.rstrip('/')}/api/v1/auth/login",
                data={"username": username, "password": password_for(pwd_env, PWD, PWD_CEO)},
            )
            ok = r.status_code == 200
            report["steps"].append({"name": f"login_{role}", "ok": ok, "status": r.status_code})
            if ok:
                tokens[role] = r.json().get("access_token", "")

        for path in (
            "/api/v1/users/me",
            "/api/v1/dashboard/summary",
            "/api/v1/cases/",
            "/docs",
            "/redoc",
        ):
            tok = tokens.get("ceo") or tokens.get("client")
            headers = {"Authorization": f"Bearer {tok}"} if tok else {}
            resp = client.get(BASE.rstrip("/") + path, headers=headers)
            report["routes"].append(
                {"path": path, "status": resp.status_code, "with_token": bool(tok)}
            )

        for case_id in (118, 50):
            for role, tok in tokens.items():
                resp = client.get(
                    f"{BASE.rstrip('/')}/api/v1/cases/{case_id}",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                report["bola_probes"].append(
                    {"case_id": case_id, "role": role, "status": resp.status_code}
                )

    client_blocked = all(p["status"] == 403 for p in report["bola_probes"] if p["role"] == "client")
    ceo_ok = any(p["status"] == 200 for p in report["bola_probes"] if p["role"] == "ceo")
    report["bola_ok"] = client_blocked and ceo_ok and bool(report["bola_probes"])
    report["steps"].append({"name": "bola_verdict", "ok": report["bola_ok"]})

    # Optional IDOR matrix on production when explicitly allowed
    if os.environ.get("RYNIX_PROD_IDOR_MATRIX", "").strip() == "1":
        from rynix_mcp.idor_matrix import run_idor_matrix

        matrix = run_idor_matrix(
            base_url=BASE,
            profile="example-law-firm",
            repo_path=os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", "")),
            session_id="cursor-agent-prod-1",
            allow_live=True,
        )
        signals = sum(1 for row in matrix.get("comparisons", []) if row.get("idor_likely"))
        report["idor_summary"] = {
            "comparisons": len(matrix.get("comparisons", [])),
            "idor_signals": signals,
        }
        OUT.joinpath("idor_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    summary_path = OUT / "engagement_summary.json"
    summary_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report.get("bola_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
