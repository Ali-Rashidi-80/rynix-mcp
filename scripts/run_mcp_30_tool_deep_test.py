#!/usr/bin/env python3
"""Deep live invocation test for all 30 Rynix MCP tools."""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp-server"
sys.path.insert(0, str(MCP))
sys.path.insert(0, str(ROOT / "scripts"))

from target_env import engagement_profile, require_target_repo


def _resolve_repo() -> Path:
    return require_target_repo()


def _resolve_base(repo: Path) -> str:
    if os.environ.get("RYNIX_PROBE_BASE_URL", "").strip():
        return os.environ["RYNIX_PROBE_BASE_URL"].strip().rstrip("/")
    ports = repo / ".local-mirror-ports.json"
    if ports.is_file():
        data = json.loads(ports.read_text(encoding="utf-8"))
        port = data.get("backend") or (data.get("ports") or {}).get("backend")
        if port:
            return f"http://127.0.0.1:{port}"
    return f"http://127.0.0.1:{os.environ.get('LOCAL_BACKEND_PORT', '8001')}"


def _bootstrap_env(repo: Path) -> None:
    os.environ.setdefault("RYNIX_TARGET_REPO", str(repo))
    accounts = repo / ".pentest" / "probe-accounts.json"
    if accounts.is_file():
        os.environ.setdefault("RYNIX_PROBE_ACCOUNTS_FILE", str(accounts))
    env_local = repo / ".env.local-mirror"
    if env_local.is_file():
        for line in env_local.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k in (
                "RYNIX_STEALTH_GATE_SECRET",
                "RYNIX_STEALTH_GATE_SECRET",
                "RYNIX_REMOTE_GATE_SECRET",
            ):
                os.environ.setdefault("RYNIX_STEALTH_GATE_SECRET", v)
    os.environ.setdefault("RYNIX_PROBE_PASSWORD", os.environ.get("RYNIX_PROBE_PASSWORD", ""))


class DeepTester:
    def __init__(self, repo: Path, base: str, profile: str, session_id: str) -> None:
        self.repo = repo
        self.base = base
        self.profile = profile
        self.session_id = session_id
        self.results: list[dict[str, Any]] = []
        self.token_client: str = ""
        self.token_lawyer: str = ""

    def _record(self, tool: str, ok: bool, detail: str, data: Any = None) -> None:
        self.results.append(
            {
                "tool": tool,
                "ok": ok,
                "detail": detail,
                "data_preview": _preview(data),
                "ts": datetime.now(UTC).isoformat(),
            }
        )
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {tool}: {detail}")

    def _run(self, tool: str, fn, *args, **kwargs) -> Any:
        try:
            out = fn(*args, **kwargs)
            if isinstance(out, dict) and out.get("error") and not out.get("ok", True):
                self._record(tool, False, str(out.get("error")), out)
                return out
            self._record(tool, True, "ok", out)
            return out
        except Exception as exc:  # noqa: BLE001
            self._record(tool, False, f"{type(exc).__name__}: {exc}")
            traceback.print_exc()
            return None

    def run_all(self, tools: dict[str, Any]) -> None:
        repo_s = str(self.repo)
        sid = self.session_id
        base = self.base
        prof = self.profile

        self._run("health_check", tools["health_check"], repo_path=repo_s)
        self._run("list_profiles", tools["list_profiles"])

        reg = self._run("register_scope", tools["register_scope"], host="127.0.0.1", session_id=sid)
        self._run(
            "scope_check", tools["scope_check"], base_url=base, profile=prof, repo_path=repo_s
        )

        scan = self._run("analyze_repo", tools["analyze_repo"], repo_path=repo_s, profile=prof)
        routes_n = len((scan or {}).get("routes", [])) if isinstance(scan, dict) else 0

        api = self._run("list_api_routes", tools["list_api_routes"], repo_path=repo_s, profile=prof)
        self._run(
            "list_frontend_routes", tools["list_frontend_routes"], repo_path=repo_s, profile=prof
        )
        self._run("rbac_matrix", tools["rbac_matrix"], repo_path=repo_s, profile=prof)
        self._run("high_risk_surfaces", tools["high_risk_surfaces"], repo_path=repo_s, profile=prof)
        self._run(
            "generate_pentest_brief",
            tools["generate_pentest_brief"],
            repo_path=repo_s,
            profile=prof,
        )

        self._run("get_technique_guide", tools["get_technique_guide"], vuln_class="idor")
        self._run("get_wstg_test", tools["get_wstg_test"], test_id="WSTG-ATHZ-01")
        self._run(
            "agent_engagement_playbook",
            tools["agent_engagement_playbook"],
            scan_mode="standard",
            target_url=base,
            repo_path=repo_s,
            profile=prof,
            session_id=sid,
        )

        plugins = self._run("list_plugins", tools["list_plugins"])
        plugin_ids = [
            p.get("id") for p in (plugins or {}).get("plugins", []) if isinstance(p, dict)
        ]
        if plugin_ids:
            self._run("plugin_health_check", tools["plugin_health_check"], plugin_id=plugin_ids[0])
            self._run(
                "rynix_plugin_run",
                tools["rynix_plugin_run"],
                plugin_id="wstg",
                options={"action": "health"},
            )

        gate = self._run(
            "unlock_stealth_gate",
            tools["unlock_stealth_gate"],
            base_url=base,
            profile=prof,
            session_id=sid,
            repo_path=repo_s,
            allow_live=True,
        )

        login_client = self._run(
            "auth_login",
            tools["auth_login"],
            base_url=base,
            username=os.environ.get("RYNIX_PROBE_USER_CLIENT", ""),
            password=os.environ.get("RYNIX_PROBE_PASSWORD", ""),
            profile=prof,
            role_label="client",
            session_id=sid,
            allow_live=True,
            repo_path=repo_s,
        )
        if isinstance(login_client, dict):
            self.token_client = str(
                login_client.get("access_token") or login_client.get("token_preview") or ""
            )

        login_lawyer = self._run(
            "auth_login",
            tools["auth_login"],
            base_url=base,
            username=os.environ.get("RYNIX_PROBE_USER_LAWYER", ""),
            password=os.environ.get("RYNIX_PROBE_PASSWORD", ""),
            profile=prof,
            role_label="lawyer",
            session_id=sid,
            allow_live=True,
            repo_path=repo_s,
        )
        if isinstance(login_lawyer, dict):
            self.token_lawyer = str(
                login_lawyer.get("access_token") or login_lawyer.get("token_preview") or ""
            )

        probe = self._run(
            "http_probe",
            tools["http_probe"],
            base_url=base,
            path="/health",
            method="GET",
            profile=prof,
            session_id=sid,
            allow_live=True,
            repo_path=repo_s,
        )

        if self.token_client:
            self._run(
                "check_access",
                tools["check_access"],
                base_url=base,
                path="/api/v1/cases/",
                method="GET",
                token=self.token_client,
                profile=prof,
                session_id=sid,
                repo_path=repo_s,
                allow_live=True,
            )

        if self.token_client and self.token_lawyer:
            self._run(
                "compare_role_response",
                tools["compare_role_response"],
                base_url=base,
                path="/api/v1/dashboard/summary",
                method="GET",
                token_a=self.token_client,
                token_b=self.token_lawyer,
                role_a="client",
                role_b="lawyer",
                profile=prof,
                session_id=sid,
                allow_live=True,
                repo_path=repo_s,
            )

        matrix = self._run(
            "run_idor_matrix",
            tools["run_idor_matrix"],
            base_url=base,
            profile=prof,
            session_id=sid,
            repo_path=repo_s,
            allow_live=True,
        )

        self._run(
            "save_engagement_context",
            tools["save_engagement_context"],
            key="deep_test",
            content=f"routes={routes_n} api_routes={len((api or {}).get('routes', []))}",
            session_id=sid,
        )
        self._run("get_engagement_context", tools["get_engagement_context"], session_id=sid)
        self._run(
            "track_wstg_test",
            tools["track_wstg_test"],
            test_id="WSTG-INFO-01",
            status="completed",
            session_id=sid,
            notes="deep test",
        )
        self._run(
            "track_probe_step",
            tools["track_probe_step"],
            name="deep-http-probe",
            status="ok",
            session_id=sid,
            detail=f"health status={(probe or {}).get('status') or (probe or {}).get('status_code')}",
        )
        self._run("list_engagement_progress", tools["list_engagement_progress"], session_id=sid)

        self._run(
            "record_finding",
            tools["record_finding"],
            title="Deep test informational",
            severity="info",
            endpoint="/health",
            evidence=f"http_probe returned {(probe or {}).get('status') or (probe or {}).get('status_code')}",
            session_id=sid,
            verified=True,
        )

        out_dir = ROOT / "pentest_output" / "mcp-30-deep-test" / sid
        self._run(
            "export_report",
            tools["export_report"],
            output_dir=str(out_dir),
            session_id=sid,
            formats="json,markdown",
        )
        self._run(
            "export_openapi_stub",
            tools["export_openapi_stub"],
            repo_path=repo_s,
            profile=prof,
        )

        # annotate extras
        if isinstance(reg, dict):
            self.results[1]["detail"] += f" scopes={len(reg.get('scopes', []))}"
        if isinstance(gate, dict):
            idx = next(i for i, r in enumerate(self.results) if r["tool"] == "unlock_stealth_gate")
            self.results[idx]["detail"] += f" unlocked={gate.get('ok', gate.get('unlocked'))}"
        if isinstance(matrix, dict):
            idx = next(i for i, r in enumerate(self.results) if r["tool"] == "run_idor_matrix")
            self.results[idx]["detail"] += (
                f" comparisons={matrix.get('comparisons')} signals={matrix.get('idor_signals')}"
            )


def _preview(data: Any, limit: int = 400) -> Any:
    if data is None:
        return None
    if isinstance(data, dict):
        slim = {k: data[k] for k in list(data.keys())[:12]}
        if "content" in data and isinstance(data["content"], str) and len(data["content"]) > limit:
            slim["content"] = data["content"][:limit] + "..."
        return slim
    if isinstance(data, list):
        return data[:5]
    s = str(data)
    return s[:limit] + ("..." if len(s) > limit else "")


def main() -> int:
    repo = _resolve_repo()
    base = _resolve_base(repo)
    _bootstrap_env(repo)
    session_id = f"mcp-deep-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    profile = (
        os.environ.get("RYNIX_PROBE_PROFILE") or engagement_profile(repo) or "example-law-firm"
    )

    from rynix_mcp.server import mcp

    tool_map = {t.name: t.fn for t in mcp._tool_manager.list_tools()}
    expected = sorted(tool_map.keys())
    print(f"Registered tools: {len(expected)}")
    for name in expected:
        print(f"  - {name}")

    tester = DeepTester(repo, base, profile, session_id)
    t0 = time.perf_counter()
    tester.run_all(tool_map)
    elapsed = time.perf_counter() - t0

    tested = {r["tool"] for r in tester.results}
    missing = sorted(set(expected) - tested)
    passed = sum(1 for r in tester.results if r["ok"])
    failed = [r for r in tester.results if not r["ok"]]

    summary = {
        "session_id": session_id,
        "base_url": base,
        "repo": str(repo),
        "profile": profile,
        "registered_tools": len(expected),
        "invoked_tools": len(tester.results),
        "passed": passed,
        "failed": len(failed),
        "missing_tools": missing,
        "elapsed_sec": round(elapsed, 2),
        "results": tester.results,
    }

    out_dir = ROOT / "pentest_output" / "mcp-30-deep-test"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"{session_id}.json"
    report_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n=== SUMMARY ===")
    print(f"tools registered: {len(expected)}")
    print(f"tools invoked:  {len(tester.results)}")
    print(f"PASS: {passed}  FAIL: {len(failed)}  missing: {missing}")
    print(f"elapsed: {elapsed:.1f}s")
    print(f"report: {report_path}")

    if missing or failed:
        for r in failed:
            print(f"  FAIL {r['tool']}: {r['detail']}")
        return 1 if failed else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
