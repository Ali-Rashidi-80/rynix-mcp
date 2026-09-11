#!/usr/bin/env python3
"""Run engagement_closure against local mirror and remote production (scoped)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from rynix_mcp.stealth_gate import load_gate_secret, unlock_stealth_gate

CLOSURE = ROOT / "scripts" / "engagement_closure.py"
OUT = ROOT / "pentest_output"

TARGETS = [
    {
        "label": "local-mirror",
        "base_url": os.environ.get("RYNIX_LOCAL_URL", "http://127.0.0.1:8001"),
        "session": "engagement-local-final",
        "repo": os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", "")),
        "full_matrix": True,
    },
    {
        "label": "remote-production",
        "base_url": os.environ.get("RYNIX_REMOTE_URL", "").strip(),
        "session": "engagement-remote-final",
        "repo": os.environ.get("RYNIX_TARGET_REPO", os.environ.get("RYNIX_TARGET_REPO", "")),
        "full_matrix": False,
    },
]


def remote_stealth_probe(base_url: str) -> dict:
    """Auth + data-route probe when stealth gate may block data paths."""
    result: dict = {
        "base_url": base_url,
        "login": {},
        "routes": [],
        "docs": {},
    }
    client = os.environ.get("RYNIX_PROBE_USER_CLIENT", "")
    pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    if client and pwd:
        try:
            r = httpx.post(
                f"{base_url.rstrip('/')}/api/v1/auth/login",
                data={"username": client, "password": pwd},
                timeout=25,
            )
            result["login"] = {"status": r.status_code, "ok": r.status_code == 200}
            token = r.json().get("access_token") if r.status_code == 200 else None
        except Exception as exc:  # noqa: BLE001
            result["login"] = {"status": -1, "error": str(exc)}
            token = None
    else:
        token = None
        result["login"] = {"skipped": True, "reason": "missing RYNIX_PROBE_USER_CLIENT"}

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    for path in (
        "/api/v1/cases/118",
        "/api/v1/users/me",
        "/api/v1/dashboard/summary",
        "/docs",
        "/redoc",
        "/api/v1/openapi.json",
    ):
        try:
            resp = httpx.get(base_url.rstrip("/") + path, headers=headers, timeout=25)
            result["routes"].append({"path": path, "status": resp.status_code})
            if path in ("/docs", "/redoc"):
                result["docs"][path] = resp.status_code
        except Exception as exc:  # noqa: BLE001
            result["routes"].append({"path": path, "status": -1, "error": str(exc)})

    return result


def production_bola_probe(base_url: str) -> dict:
    """BOLA verification after stealth gate unlock (requires RYNIX_STEALTH_GATE_SECRET)."""
    from rynix_mcp.probe_accounts import load_probe_accounts, password_for

    result: dict = {"base_url": base_url, "gate_unlocked": False, "probes": [], "bola_ok": False}
    gate = load_gate_secret()
    if not gate:
        result["skipped"] = True
        result["reason"] = "RYNIX_STEALTH_GATE_SECRET not configured"
        return result
    pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    pwd_ceo = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", pwd)
    accounts = load_probe_accounts(("client", "ceo"))
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        result["gate_unlocked"] = unlock_stealth_gate(base_url, gate, client)
        if not result["gate_unlocked"]:
            result["reason"] = "gate unlock failed"
            return result
        tokens: dict[str, str] = {}
        for role in ("client", "ceo"):
            if role not in accounts:
                continue
            username, pwd_env = accounts[role]
            r = client.post(
                f"{base_url.rstrip('/')}/api/v1/auth/login",
                data={"username": username, "password": password_for(pwd_env, pwd, pwd_ceo)},
            )
            if r.status_code == 200:
                tokens[role] = r.json().get("access_token", "")
        for case_id in (118, 50):
            for role, tok in tokens.items():
                resp = client.get(
                    f"{base_url.rstrip('/')}/api/v1/cases/{case_id}",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                result["probes"].append(
                    {"case_id": case_id, "role": role, "status": resp.status_code}
                )
    client_blocked = all(p["status"] == 403 for p in result["probes"] if p["role"] == "client")
    ceo_ok = any(p["status"] == 200 for p in result["probes"] if p["role"] == "ceo")
    result["bola_ok"] = client_blocked and ceo_ok and bool(result["probes"])
    return result


def run_target(target: dict) -> dict:
    out_dir = OUT / target["label"]
    out_dir.mkdir(parents=True, exist_ok=True)

    if not target.get("full_matrix", True):
        stealth = remote_stealth_probe(target["base_url"])
        stealth_path = out_dir / "remote_stealth_probe.json"
        stealth_path.write_text(json.dumps(stealth, indent=2), encoding="utf-8")
        bola = production_bola_probe(target["base_url"])
        bola_path = out_dir / "production_bola_probe.json"
        bola_path.write_text(json.dumps(bola, indent=2), encoding="utf-8")
        return {
            "label": target["label"],
            "base_url": target["base_url"],
            "exit_code": 0,
            "mode": "stealth_probe_only",
            "stealth_probe": stealth,
            "production_bola": bola,
            "summary": {
                "stealth_probe_path": str(stealth_path),
                "production_bola_path": str(bola_path),
                "bola_ok": bola.get("bola_ok"),
            },
        }

    env = os.environ.copy()
    env["RYNIX_PROBE_BASE_URL"] = target["base_url"]
    env["RYNIX_ENGAGEMENT_SESSION"] = target["session"]
    env["RYNIX_ENGAGEMENT_OUT"] = str(OUT / target["label"])
    if target["repo"]:
        env["RYNIX_TARGET_REPO"] = target["repo"]
        env.setdefault("RYNIX_TARGET_REPO", target["repo"])
    proc = subprocess.run(
        [sys.executable, str(CLOSURE)],
        cwd=str(ROOT / "mcp-server"),
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    summary_path = OUT / target["label"] / "engagement_summary.json"
    summary = {}
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    return {
        "label": target["label"],
        "base_url": target["base_url"],
        "exit_code": proc.returncode,
        "mode": "full_engagement_closure",
        "stdout_tail": proc.stdout[-4000:] if proc.stdout else "",
        "stderr_tail": proc.stderr[-2000:] if proc.stderr else "",
        "summary": summary,
    }


def main() -> int:
    if not os.environ.get("RYNIX_PROBE_PASSWORD"):
        print("Set RYNIX_PROBE_PASSWORD (and RYNIX_PROBE_PASSWORD_CEO)", file=sys.stderr)
        return 2
    required_users = [
        "RYNIX_PROBE_USER_CLIENT",
        "RYNIX_PROBE_USER_LAWYER",
        "RYNIX_PROBE_USER_CEO",
    ]
    missing = [k for k in required_users if not os.environ.get(k)]
    if missing:
        print(f"Set probe usernames: {', '.join(missing)}", file=sys.stderr)
        return 2
    results = [run_target(t) for t in TARGETS]
    report_path = OUT / "dual_engagement_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
    failed = [r for r in results if r["exit_code"] not in (0, 3)]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
