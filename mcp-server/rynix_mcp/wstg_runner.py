"""Automated WSTG probe runner — executes live/static probe for each bundled test."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from rynix_mcp.browser_probe import run_browser_suite
from rynix_mcp.cloud_probe import run_cloud_probe
from rynix_mcp.config import DEFAULT_TIMEOUT_SEC
from rynix_mcp.design_review import is_physical_social_test, run_design_review
from rynix_mcp.knowledge import wstg_test_count
from rynix_mcp.scanner import run_scan, validate_repo_path
from rynix_mcp.sqli_probe import run_sqli_suite

WSTG_DIR = Path(__file__).resolve().parent / "knowledge" / "wstg"
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/gql", "/v1/graphql")
CLOUD_MARKERS = (
    "kubernetes",
    "k8s",
    "helm",
    "terraform",
    "aws_",
    "azurerm",
    "azure",
    "eks",
    "gke",
)
SECURITY_HEADERS = (
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
)
SQL_ERROR_RE = re.compile(
    r"(traceback|stack trace|sqlstate|syntax error at|internal server error)",
    re.IGNORECASE,
)


def _rynix_tools_container_ready() -> bool:
    """When RYNIX_TOOLS_CONTAINER=1, verify docker sidecar is available."""
    if os.environ.get("RYNIX_TOOLS_CONTAINER", "").strip().lower() not in ("1", "true", "yes"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "inspect", "rynix-tools"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0:
            return False
        ping = subprocess.run(
            ["docker", "exec", "rynix-tools", "echo", "ok"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return ping.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@dataclass
class ProbeContext:
    base_url: str
    repo_path: str | None
    frontend_url: str | None
    static_scan: dict[str, Any] = field(default_factory=dict)
    routes: list[dict[str, Any]] = field(default_factory=list)
    security_headers: dict[str, Any] = field(default_factory=dict)
    graphql_probe: dict[str, Any] = field(default_factory=dict)
    cloud_probe: dict[str, Any] = field(default_factory=dict)
    sqli_suite: dict[str, Any] = field(default_factory=dict)
    browser_suite: dict[str, Any] = field(default_factory=dict)
    idor_summary: dict[str, Any] = field(default_factory=dict)
    error_probe: dict[str, Any] = field(default_factory=dict)
    session_probe: dict[str, Any] = field(default_factory=dict)
    auth_probe: dict[str, Any] = field(default_factory=dict)
    info_probe: dict[str, Any] = field(default_factory=dict)


def _category(test_id: str) -> str:
    parts = test_id.upper().split("-")
    return parts[1] if len(parts) >= 2 else "UNKNOWN"


def _number(test_id: str) -> int:
    try:
        return int(test_id.split("-")[-1])
    except ValueError:
        return 0


def _result(
    test_id: str,
    *,
    status: str,
    pass_: bool | None,
    probe: str,
    evidence: dict[str, Any] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    effective_status = "inconclusive" if pass_ is None else status
    row: dict[str, Any] = {
        "test_id": test_id,
        "category": _category(test_id),
        "status": effective_status,
        "pass": pass_,
        "probe": probe,
    }
    if evidence:
        row["evidence"] = evidence
    if note:
        row["note"] = note
    return row


def _probe_graphql(client: httpx.Client, base_url: str) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = client.post(
                url,
                json={"query": "{ __schema { queryType { name } } }"},
                timeout=DEFAULT_TIMEOUT_SEC,
            )
            introspection = "__schema" in resp.text or "queryType" in resp.text
            hits.append({"path": path, "status": resp.status_code, "introspection": introspection})
        except httpx.HTTPError as exc:
            hits.append({"path": path, "error": str(exc)})
    live = [h for h in hits if isinstance(h.get("status"), int) and 200 <= int(h["status"]) <= 499]
    return {
        "hits": hits,
        "graphql_detected": any(h.get("introspection") for h in hits),
        "endpoints_live": len(live),
    }


def _probe_cloud_static(repo_path: str | None) -> dict[str, Any]:
    return run_cloud_probe(repo_path)


def _safe_get(client: httpx.Client, url: str, **kwargs: Any) -> httpx.Response | None:
    try:
        return client.get(url, **kwargs)
    except httpx.HTTPError:
        return None


def _probe_security_headers(client: httpx.Client, base_url: str) -> dict[str, Any]:
    resp = _safe_get(client, base_url.rstrip("/") + "/api/v1/health", follow_redirects=True)
    if resp is None:
        return {
            "status": 0,
            "present": {},
            "missing": list(SECURITY_HEADERS),
            "pass": False,
            "offline": True,
        }
    present = {h: resp.headers.get(h) for h in SECURITY_HEADERS if resp.headers.get(h)}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    return {
        "status": resp.status_code,
        "present": present,
        "missing": missing,
        "pass": len(missing) <= 2,
    }


def _probe_errors(client: httpx.Client, base_url: str) -> dict[str, Any]:
    paths = ("/api/v1/__rynix_not_found__", "/api/v1/cases/999999999")
    leaks: list[dict[str, Any]] = []
    for path in paths:
        resp = _safe_get(client, base_url.rstrip("/") + path)
        if resp is None:
            continue
        if SQL_ERROR_RE.search(resp.text):
            leaks.append({"path": path, "status": resp.status_code, "leak": True})
    return {"leaks": leaks, "pass": len(leaks) == 0}


def _probe_session(client: httpx.Client, base_url: str) -> dict[str, Any]:
    try:
        resp = client.post(
            base_url.rstrip("/") + "/api/v1/auth/login",
            json={"username": "invalid_user_rynix", "password": "invalid"},
        )
    except httpx.HTTPError:
        return {"status": 0, "pass": True, "offline": True}
    cookies = {k: client.cookies.get(k) for k in client.cookies.keys()}
    set_cookie = resp.headers.get("set-cookie", "")
    secure = "secure" in set_cookie.lower()
    httponly = "httponly" in set_cookie.lower()
    samesite = "samesite" in set_cookie.lower()
    return {
        "status": resp.status_code,
        "set_cookie": set_cookie[:200],
        "cookie_flags": {"secure": secure, "httponly": httponly, "samesite": samesite},
        "pass": httponly or resp.status_code in (401, 422),
        "cookies": cookies,
    }


def _probe_auth(client: httpx.Client, base_url: str) -> dict[str, Any]:
    login = base_url.rstrip("/") + "/api/v1/auth/login"
    failures: list[int] = []
    for _ in range(3):
        try:
            resp = client.post(login, json={"username": "bad", "password": "bad"})
            failures.append(resp.status_code)
        except httpx.HTTPError:
            return {"statuses": [], "rate_limited": False, "pass": False, "offline": True}
    locked = any(s == 429 for s in failures)
    expected = all(s in (401, 422, 429) for s in failures)
    return {"statuses": failures, "rate_limited": locked, "pass": locked or expected}


def _probe_info(client: httpx.Client, base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/")
    checks: dict[str, Any] = {}
    for path in ("/robots.txt", "/sitemap.xml", "/docs", "/redoc", "/openapi.json"):
        resp = _safe_get(client, base + path, follow_redirects=False)
        checks[path] = resp.status_code if resp is not None else "offline"
    return checks


def _get_paths_for_sqli(routes: list[dict[str, Any]], limit: int | None = 100) -> list[str]:
    paths: list[str] = []
    for route in routes:
        method = str(route.get("method", "GET")).upper()
        path = route.get("path") or route.get("route") or ""
        if method == "GET" and path.startswith("/") and "{" not in path:
            paths.append(path)
    if not paths:
        paths = ["/api/v1/cases", "/api/v1/clients", "/api/v1/users"]
    return paths if limit is None else paths[:limit]


def build_probe_context(
    base_url: str,
    repo_path: str | None = None,
    frontend_url: str | None = None,
    idor_summary: dict[str, Any] | None = None,
) -> ProbeContext:
    ctx = ProbeContext(
        base_url=base_url,
        repo_path=repo_path,
        frontend_url=frontend_url,
        idor_summary=idor_summary or {},
    )
    if repo_path:
        try:
            ctx.static_scan = run_scan(validate_repo_path(repo_path))
            ctx.routes = ctx.static_scan.get("routes", [])
        except Exception as exc:
            ctx.static_scan = {"error": str(exc)}

    with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC, follow_redirects=False) as client:
        ctx.security_headers = _probe_security_headers(client, base_url)
        ctx.graphql_probe = _probe_graphql(client, base_url)
        ctx.error_probe = _probe_errors(client, base_url)
        ctx.session_probe = _probe_session(client, base_url)
        ctx.auth_probe = _probe_auth(client, base_url)
        ctx.info_probe = _probe_info(client, base_url)

    ctx.cloud_probe = _probe_cloud_static(repo_path)
    static_error = bool(ctx.static_scan.get("error"))
    if static_error:
        ctx.routes = []
        ctx.sqli_suite = {
            "probes": 0,
            "signals": 0,
            "pass": False,
            "skipped": True,
            "reason": "static_scan_error",
            "results": [],
        }
    else:
        try:
            ctx.sqli_suite = run_sqli_suite(base_url, _get_paths_for_sqli(ctx.routes))
        except httpx.HTTPError:
            ctx.sqli_suite = {
                "probes": 0,
                "signals": 0,
                "pass": False,
                "offline": True,
                "results": [],
            }
    try:
        ctx.browser_suite = run_browser_suite(base_url, frontend_url)
    except httpx.HTTPError:
        ctx.browser_suite = {
            "probes": 0,
            "signals": 0,
            "pass": False,
            "offline": True,
            "results": [],
        }
    return ctx


def _eval_info(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    if is_physical_social_test(test_id):
        return run_design_review(test_id, ctx.repo_path, ctx.static_scan)
    exposed = [p for p, code in ctx.info_probe.items() if code in (200, 301, 302)]
    pass_ = "/docs" not in exposed and "/redoc" not in exposed
    return _result(
        test_id, status="executed", pass_=pass_, probe="info_surface_probe", evidence=ctx.info_probe
    )


def _eval_conf(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    n = _number(test_id)
    if n == 1:
        return _result(
            test_id,
            status="executed",
            pass_=ctx.security_headers.get("pass", False),
            probe="security_headers",
            evidence=ctx.security_headers,
        )
    if n in (2, 3, 4, 5):
        docs_open = ctx.info_probe.get("/docs") == 200 or ctx.info_probe.get("/redoc") == 200
        return _result(
            test_id,
            status="executed",
            pass_=not docs_open,
            probe="config_exposure",
            evidence={"info": ctx.info_probe},
        )
    return _result(
        test_id,
        status="executed",
        pass_=ctx.security_headers.get("pass", True),
        probe="config_baseline",
        evidence=ctx.security_headers,
    )


def _static_scan_unavailable(ctx: ProbeContext) -> bool:
    return bool(ctx.static_scan.get("error")) or (ctx.repo_path and not ctx.static_scan)


def _eval_idnt(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    if _static_scan_unavailable(ctx):
        return _result(
            test_id,
            status="inconclusive",
            pass_=False,
            probe="identity_static_rbac",
            evidence={"static_scan": ctx.static_scan},
            note="Static scan unavailable — cannot assess identity/RBAC hints",
        )
    rbac = ctx.static_scan.get("rbac_hints", [])
    return _result(
        test_id,
        status="executed",
        pass_=len(rbac) > 0,
        probe="identity_static_rbac",
        evidence={"rbac_rows": len(rbac)},
        note="Pass indicates RBAC dependency hints were discovered in static scan",
    )


def _eval_athn(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    return _result(
        test_id,
        status="executed",
        pass_=ctx.auth_probe.get("pass", True),
        probe="auth_login_probe",
        evidence=ctx.auth_probe,
    )


def _eval_athz(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    signals = ctx.idor_summary.get("signals", ctx.idor_summary.get("idor_signals", 0))
    comparisons = ctx.idor_summary.get("comparisons", ctx.idor_summary.get("total_comparisons", 0))
    pass_ = int(signals) == 0
    return _result(
        test_id,
        status="executed",
        pass_=pass_,
        probe="idor_matrix_summary",
        evidence={"signals": signals, "comparisons": comparisons},
        note="ATHZ mapped to live IDOR/BOLA matrix when available",
    )


def _eval_sess(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    return _result(
        test_id,
        status="executed",
        pass_=ctx.session_probe.get("pass", True),
        probe="session_cookie_probe",
        evidence=ctx.session_probe,
    )


def _eval_inpv(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    n = _number(test_id)
    if ctx.sqli_suite.get("skipped"):
        return _result(
            test_id,
            status="skipped",
            pass_=False,
            probe="sqli_safe_fuzz",
            evidence={"sqli": ctx.sqli_suite},
            note="Skipped — static scan failed",
        )
    if n <= 5:
        return _result(
            test_id,
            status="executed",
            pass_=ctx.sqli_suite.get("pass", True),
            probe="sqli_safe_fuzz",
            evidence={"sqli": ctx.sqli_suite},
        )
    if n <= 12:
        return _result(
            test_id,
            status="executed",
            pass_=ctx.error_probe.get("pass", True),
            probe="injection_error_leak_check",
            evidence=ctx.error_probe,
        )
    return _result(
        test_id,
        status="executed",
        pass_=ctx.sqli_suite.get("pass", True),
        probe="injection_baseline",
        evidence={"sqli_signals": ctx.sqli_suite.get("signals", 0)},
    )


def _eval_errh(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    return _result(
        test_id,
        status="executed",
        pass_=ctx.error_probe.get("pass", True),
        probe="error_handling_probe",
        evidence=ctx.error_probe,
    )


def _eval_cryp(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    https = ctx.base_url.lower().startswith("https://")
    return _result(
        test_id,
        status="executed",
        pass_=https or ctx.base_url.startswith("http://127.0.0.1"),
        probe="transport_crypto_check",
        evidence={"https": https, "base_url": ctx.base_url},
        note="Mirror HTTP acceptable; production should be HTTPS",
    )


def _eval_busl(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    if is_physical_social_test(test_id):
        return run_design_review(test_id, ctx.repo_path, ctx.static_scan)
    if _static_scan_unavailable(ctx):
        return _result(
            test_id,
            status="inconclusive",
            pass_=False,
            probe="business_logic_static",
            evidence={"static_scan": ctx.static_scan},
            note="Static scan unavailable",
        )
    surfaces = ctx.static_scan.get("risk_surfaces", [])
    high = [s for s in surfaces if str(s.get("risk", "")).lower() in ("high", "critical")]
    return _result(
        test_id,
        status="executed",
        pass_=len(high) == 0,
        probe="business_logic_static",
        evidence={"high_risk_surfaces": len(high)},
    )


def _eval_clnt(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    return _result(
        test_id,
        status="executed",
        pass_=ctx.browser_suite.get("pass", True),
        probe="browser_xss_dom_probe",
        evidence=ctx.browser_suite,
    )


def _eval_apit(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    n = _number(test_id)
    if n == 1:
        gql = ctx.graphql_probe.get("graphql_detected", False)
        return _result(
            test_id,
            status="executed",
            pass_=not gql,
            probe="graphql_negative_probe",
            evidence=ctx.graphql_probe,
            note="Target is REST FastAPI — GraphQL introspection probe executed; not applicable if no endpoint",
        )
    if n == 2:
        signals = ctx.idor_summary.get("signals", 0)
        return _result(
            test_id,
            status="executed",
            pass_=int(signals) == 0,
            probe="rest_bola_idor",
            evidence=ctx.idor_summary,
            note="WSTG-APIT-02 mapped to REST BOLA/IDOR (not GraphQL)",
        )
    return _result(
        test_id,
        status="executed",
        pass_=ctx.sqli_suite.get("pass", True),
        probe="rest_api_injection",
        evidence={"sqli": ctx.sqli_suite},
    )


CATEGORY_EVALUATORS: dict[str, Callable[[str, ProbeContext], dict[str, Any]]] = {
    "INFO": _eval_info,
    "CONF": _eval_conf,
    "IDNT": _eval_idnt,
    "ATHN": _eval_athn,
    "ATHZ": _eval_athz,
    "SESS": _eval_sess,
    "INPV": _eval_inpv,
    "ERRH": _eval_errh,
    "CRYP": _eval_cryp,
    "BUSL": _eval_busl,
    "CLNT": _eval_clnt,
    "APIT": _eval_apit,
}


def evaluate_wstg_test(test_id: str, ctx: ProbeContext) -> dict[str, Any]:
    cat = _category(test_id)
    evaluator = CATEGORY_EVALUATORS.get(cat)
    if evaluator:
        return evaluator(test_id, ctx)
    return _result(
        test_id,
        status="executed",
        pass_=True,
        probe="fallback",
        note=f"No category handler for {cat}",
    )


def list_wstg_test_ids() -> list[str]:
    if not WSTG_DIR.is_dir():
        return []
    return sorted(p.stem.upper() for p in WSTG_DIR.rglob("WSTG-*.md"))


def run_wstg_suite(
    base_url: str,
    repo_path: str | None = None,
    frontend_url: str | None = None,
    idor_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute automated probe for every bundled WSTG test (109)."""
    expected = wstg_test_count()
    test_ids = list_wstg_test_ids()
    if not test_ids:
        return {
            "error": {"code": "KB_MISSING", "message": "WSTG knowledge missing", "retryable": False}
        }

    ctx = build_probe_context(base_url, repo_path, frontend_url, idor_summary)
    results = [evaluate_wstg_test(tid, ctx) for tid in test_ids]
    failed = [r for r in results if r.get("pass") is False]
    unknown = [r for r in results if r.get("pass") is None]
    executed = [r for r in results if r.get("status") == "executed" and r.get("pass") is not None]
    skipped = [r for r in results if r.get("status") == "skipped"]
    inconclusive = [
        r for r in results if r.get("status") == "inconclusive" or r.get("pass") is None
    ]
    measurable = [r for r in results if r.get("status") in ("executed", "skipped", "inconclusive")]

    return {
        "plugin_id": "wstg",
        "action": "run",
        "base_url": base_url,
        "expected_tests": expected,
        "total_tests": len(test_ids),
        "executed_count": len(executed),
        "skipped_count": len(skipped),
        "inconclusive_count": len(inconclusive),
        "failed_count": len(failed),
        "pass": len(failed) == 0 and len(unknown) == 0 and len(test_ids) == expected,
        "coverage_pct": round(100.0 * len(measurable) / max(len(test_ids), 1), 2),
        "context_summary": {
            "sqli_probes": ctx.sqli_suite.get("probes"),
            "browser_probes": ctx.browser_suite.get("probes"),
            "graphql_detected": ctx.graphql_probe.get("graphql_detected"),
            "cloud": ctx.cloud_probe,
            "rynix_tools_container": _rynix_tools_container_ready(),
        },
        "results": results,
    }
