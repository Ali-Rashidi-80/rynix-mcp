"""Safe SQLi signal probes on read-only GET endpoints (no destructive writes)."""

from __future__ import annotations

import re
from typing import Any

import httpx

from rynix_mcp.config import DEFAULT_TIMEOUT_SEC

SAFE_PAYLOADS = (
    "'",
    '"',
    "1' OR '1'='1",
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
)

SQL_ERROR_PATTERNS = re.compile(
    r"(PSQLException|You have an error in your SQL syntax|syntax error at or near|"
    r"sqlstate|sqlite_error|ora-\d{5}|unclosed quotation)",
    re.IGNORECASE,
)


def probe_sqli_on_path(
    base_url: str,
    path: str,
    token: str | None = None,
    param: str = "q",
) -> dict[str, Any]:
    """Inject safe payloads into a single query param; flag SQL error leakage."""
    url_base = base_url.rstrip("/") + path
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    signals: list[dict[str, Any]] = []
    transport_errors: list[str] = []

    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC, follow_redirects=False) as client:
            baseline = client.get(url_base, headers=headers, params={param: "test"})
            base_len = len(baseline.text)

            for payload in SAFE_PAYLOADS:
                try:
                    resp = client.get(url_base, headers=headers, params={param: payload})
                except (httpx.HTTPError, ValueError) as exc:
                    transport_errors.append(f"{payload}: {exc}")
                    continue
                leaked = bool(
                    SQL_ERROR_PATTERNS.search(resp.text)
                    and (resp.status_code >= 500 or "syntax" in resp.text.lower())
                )
                anomaly = abs(len(resp.text) - base_len) > 5000 and resp.status_code >= 500
                if leaked or anomaly:
                    signals.append(
                        {
                            "payload": payload,
                            "status": resp.status_code,
                            "sql_error_leak": leaked,
                            "anomaly": anomaly,
                        }
                    )
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "path": path,
            "param": param,
            "offline": True,
            "signals": [],
            "transport_errors": [str(exc)],
            "pass": False,
            "error": str(exc),
        }

    row_pass = len(signals) == 0 and not transport_errors
    verdict = "clean"
    if not signals and transport_errors:
        verdict = "inconclusive"
    return {
        "path": path,
        "param": param,
        "baseline_status": baseline.status_code,
        "signals": signals,
        "transport_errors": transport_errors,
        "verdict": verdict,
        "pass": row_pass if verdict != "inconclusive" else None,
    }


def run_sqli_suite(
    base_url: str,
    paths: list[str],
    token: str | None = None,
) -> dict[str, Any]:
    rows = [probe_sqli_on_path(base_url, p, token=token) for p in paths]
    failed = [r for r in rows if r.get("pass") is False]
    inconclusive = [r for r in rows if r.get("pass") is None]
    transport = sum(len(r.get("transport_errors") or []) for r in rows)
    suite_pass: bool | None = True
    if failed:
        suite_pass = False
    elif inconclusive:
        suite_pass = None
    return {
        "probes": len(rows),
        "signals": len(failed),
        "inconclusive": len(inconclusive),
        "transport_errors": transport,
        "pass": suite_pass,
        "results": rows,
    }
