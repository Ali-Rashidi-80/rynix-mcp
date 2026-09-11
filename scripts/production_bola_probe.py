"""Production BOLA probe through authorized stealth gate unlock."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from rynix_mcp.probe_accounts import load_probe_accounts, password_for
from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate

OUT = ROOT / "pentest_output" / "remote-production" / "production_bola_probe.json"
BASE = os.environ.get("RYNIX_REMOTE_URL", "").strip()
PWD = os.environ.get("RYNIX_PROBE_PASSWORD", "")
PWD_CEO = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", PWD)


def main() -> int:
    gate = load_gate_secret()
    if not gate:
        print("RYNIX_STEALTH_GATE_SECRET required", file=sys.stderr)
        return 2
    accounts = load_probe_accounts(("client", "ceo"))
    if "client" not in accounts or "ceo" not in accounts:
        print("RYNIX_PROBE_USER_CLIENT and RYNIX_PROBE_USER_CEO required", file=sys.stderr)
        return 2

    report: dict = {"base_url": BASE, "gate_unlocked": False, "probes": []}
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        report["gate_unlocked"] = unlock_stealth_gate(BASE, gate, client)
        if not report["gate_unlocked"]:
            OUT.parent.mkdir(parents=True, exist_ok=True)
            OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 1

        tokens: dict[str, str] = {}
        for role in ("client", "ceo"):
            username, pwd_env = accounts[role]
            r = client.post(
                f"{BASE.rstrip('/')}/api/v1/auth/login",
                data={"username": username, "password": password_for(pwd_env, PWD, PWD_CEO)},
            )
            if r.status_code == 200:
                tokens[role] = r.json().get("access_token", "")

        for case_id in (118, 50):
            for role in ("client", "ceo"):
                tok = tokens.get(role)
                if not tok:
                    continue
                resp = client.get(
                    f"{BASE.rstrip('/')}/api/v1/cases/{case_id}",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                report["probes"].append(
                    {"case_id": case_id, "role": role, "status": resp.status_code},
                )

    client_ok = all(
        p["role"] == "client" and p["status"] == 403
        for p in report["probes"]
        if p["role"] == "client"
    )
    ceo_ok = any(p["role"] == "ceo" and p["status"] == 200 for p in report["probes"])
    report["bola_ok"] = client_ok and ceo_ok and bool(report["probes"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["bola_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
