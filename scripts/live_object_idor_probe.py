#!/usr/bin/env python3
"""Deep IDOR probe: fetch object IDs from privileged role, test cross-role access."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER = ROOT / "mcp-server"
if str(MCP_SERVER) not in sys.path:
    sys.path.insert(0, str(MCP_SERVER))

from rynix_mcp.probe_accounts import (
    load_probe_accounts,
    missing_credentials_message,
    password_for,
)

OUT = ROOT / "pentest_output" / "live-idor-matrix"
BASE = os.environ.get("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
PWD = os.environ.get("RYNIX_PROBE_PASSWORD", "")
PWD_CEO = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", PWD)
LOGIN = f"{BASE.rstrip('/')}/api/v1/auth/login"


def login(username: str, password: str) -> str:
    r = httpx.post(LOGIN, data={"username": username, "password": password}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def get_json(token: str, path: str) -> tuple[int, dict | list | None]:
    r = httpx.get(
        f"{BASE.rstrip('/')}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=30
    )
    try:
        body = r.json()
    except Exception:
        body = None
    return r.status_code, body


def main() -> int:
    if not PWD:
        print("Set RYNIX_PROBE_PASSWORD", file=sys.stderr)
        return 1

    accounts = load_probe_accounts(("lawyer", "client", "intern"))
    for role in ("lawyer", "client", "intern"):
        if role not in accounts:
            print(missing_credentials_message(accounts), file=sys.stderr)
            return 1

    OUT.mkdir(parents=True, exist_ok=True)

    def token_for(role: str) -> str:
        username, pwd_env = accounts[role]
        return login(username, password_for(pwd_env, PWD, PWD_CEO))

    lawyer = token_for("lawyer")
    client = token_for("client")
    intern = token_for("intern")

    results: list[dict] = []

    st, cases = get_json(lawyer, "/api/v1/cases/")
    case_ids: list[int] = []
    if st == 200 and isinstance(cases, list):
        case_ids = [c["id"] for c in cases[:5] if isinstance(c, dict) and "id" in c]

    st, clients = get_json(lawyer, "/api/v1/clients/")
    client_ids: list[int] = []
    if st == 200 and isinstance(clients, list):
        client_ids = [c["id"] for c in clients[:5] if isinstance(c, dict) and "id" in c]

    for cid in case_ids:
        for role, tok in [("client", client), ("intern", intern)]:
            st, body = get_json(tok, f"/api/v1/cases/{cid}")
            results.append(
                {
                    "resource": "case",
                    "id": cid,
                    "role": role,
                    "status": st,
                    "leaked": st == 200 and body is not None,
                    "title": (body or {}).get("title") if isinstance(body, dict) else None,
                }
            )

    for cid in client_ids:
        for role, tok in [("client", client), ("intern", intern)]:
            st, body = get_json(tok, f"/api/v1/clients/{cid}")
            results.append(
                {
                    "resource": "client",
                    "id": cid,
                    "role": role,
                    "status": st,
                    "leaked": st == 200 and body is not None,
                }
            )

    leaks = [r for r in results if r.get("leaked")]
    (OUT / "object_probe.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"case_ids={case_ids} client_ids={client_ids} leaks={len(leaks)}")
    for row in leaks:
        print(f"LEAK {row['resource']} {row['id']} as {row['role']} status={row['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
