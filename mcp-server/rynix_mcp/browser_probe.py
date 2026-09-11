"""Client-side / XSS-oriented probes — Playwright DOM when available, httpx fallback."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx

from rynix_mcp.config import DEFAULT_TIMEOUT_SEC

XSS_CANARY = "rynix7xsscanary9"
XSS_PAYLOAD = f"<img src=x onerror=\"console.log('{XSS_CANARY}')\">"
DANGEROUS_PATTERNS = re.compile(
    r"(dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\(|eval\()",
    re.IGNORECASE,
)


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


def probe_reflected_xss_http(base_url: str, path: str = "/") -> dict[str, Any]:
    """GET with canary query param — check reflection in response body."""
    url = base_url.rstrip("/") + path
    params = {"q": XSS_CANARY, "search": XSS_CANARY}
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC, follow_redirects=True) as client:
            resp = client.get(url, params=params)
    except httpx.HTTPError as exc:
        return {
            "mode": "httpx_reflection",
            "path": path,
            "offline": True,
            "pass": False,
            "transport_error": str(exc),
        }
    reflected = XSS_CANARY in resp.text
    return {
        "mode": "httpx_reflection",
        "path": path,
        "status": resp.status_code,
        "reflected": reflected,
        "pass": not reflected,
    }


def probe_frontend_static(frontend_url: str) -> dict[str, Any]:
    """Fetch SPA shell / JS bundles and scan for dangerous DOM patterns."""
    hits: list[str] = []
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT_SEC, follow_redirects=True) as client:
            index = client.get(frontend_url.rstrip("/") + "/")
            if DANGEROUS_PATTERNS.search(index.text):
                hits.append("index.html")
            for asset in re.findall(r'src="(/assets/[^"]+\.js)"', index.text)[:5]:
                try:
                    js = client.get(frontend_url.rstrip("/") + asset)
                    if DANGEROUS_PATTERNS.search(js.text):
                        hits.append(asset)
                except httpx.HTTPError:
                    continue
    except httpx.HTTPError as exc:
        return {
            "mode": "static",
            "pass": False,
            "skipped": True,
            "transport_error": str(exc),
        }

    return {
        "mode": "static_dom_patterns",
        "frontend_url": frontend_url,
        "dangerous_hits": hits,
        "pass": len(hits) == 0,
        "note": "innerHTML/dangerouslySetInnerHTML in bundle is informational — verify sink sanitization",
    }


def probe_playwright_dom_xss(frontend_url: str) -> dict[str, Any]:
    """Headless Chromium — DOM XSS canary via query/hash routes."""
    if not _playwright_available():
        return {
            "mode": "playwright_dom",
            "skipped": True,
            "pass": True,
            "reason": "playwright not installed",
        }

    from playwright.sync_api import sync_playwright

    base = frontend_url.rstrip("/")
    test_urls = [
        f"{base}/?q={quote(XSS_PAYLOAD)}",
        f"{base}/login?q={quote(XSS_CANARY)}",
        f"{base}/#/{quote(XSS_CANARY)}",
    ]
    signals: list[dict[str, Any]] = []
    transport_errors: list[dict[str, Any]] = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            dialog_fired = False
            console_canary = False

            def _on_dialog(dialog: Any) -> None:
                nonlocal dialog_fired
                dialog_fired = True
                dialog.dismiss()

            def _on_console(msg: Any) -> None:
                nonlocal console_canary
                if XSS_CANARY in (msg.text or ""):
                    console_canary = True

            page.on("dialog", _on_dialog)
            page.on("console", _on_console)

            for url in test_urls:
                dialog_fired = False
                console_canary = False
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    content = page.content()
                    canary_in_dom = XSS_CANARY in content
                    if dialog_fired or console_canary:
                        signals.append(
                            {
                                "url": url,
                                "dialog": dialog_fired,
                                "console_canary": console_canary,
                                "canary_in_dom": canary_in_dom,
                            }
                        )
                except Exception as exc:
                    msg = str(exc)
                    if "ERR_CONNECTION_REFUSED" in msg or "ERR_NAME_NOT_RESOLVED" in msg:
                        transport_errors.append({"url": url, "offline": True, "error": msg})
                    else:
                        transport_errors.append({"url": url, "error": msg})

            browser.close()
    except Exception as exc:
        return {
            "mode": "playwright_dom",
            "skipped": True,
            "pass": False,
            "transport_error": str(exc),
        }

    if not signals and transport_errors:
        return {
            "mode": "playwright_dom",
            "frontend_url": frontend_url,
            "urls_tested": len(test_urls),
            "offline": True,
            "pass": False,
            "skipped": True,
            "transport_errors": transport_errors,
            "reason": "frontend not reachable — start Vite dev server on RYNIX_FRONTEND_URL",
        }

    return {
        "mode": "playwright_dom",
        "frontend_url": frontend_url,
        "urls_tested": len(test_urls),
        "signals": signals,
        "transport_errors": transport_errors,
        "pass": len(signals) == 0,
    }


def run_browser_suite(
    api_base: str,
    frontend_url: str | None = None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = [
        probe_reflected_xss_http(api_base, "/docs"),
        probe_reflected_xss_http(api_base, "/api/v1/auth/login"),
    ]
    if frontend_url:
        rows.append(probe_frontend_static(frontend_url))
        if _playwright_available():
            rows.append(probe_playwright_dom_xss(frontend_url))

    failed = [r for r in rows if not r.get("pass") and not r.get("skipped")]
    transport = sum(len(r.get("transport_errors") or []) for r in rows if r.get("transport_errors"))
    transport += sum(1 for r in rows if r.get("transport_error"))
    return {
        "playwright_available": _playwright_available(),
        "probes": len(rows),
        "signals": len(failed),
        "transport_errors": transport,
        "pass": len(failed) == 0,
        "results": rows,
    }
