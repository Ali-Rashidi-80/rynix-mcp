#!/usr/bin/env python3
"""Phase I — per-category WSTG deep enrichment (ASVS, tooling, test focus)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WSTG = ROOT / "mcp-server" / "rynix_mcp" / "knowledge" / "wstg"

# WSTG prefix -> (ASVS lines, CWE lines, tooling lines, focus bullets)
CATEGORY: dict[str, tuple[list[str], list[str], list[str], list[str]]] = {
    "INFO": (
        [
            "- V1 Architecture — document exposed surfaces found via recon.",
            "- V14 Configuration — verify no sensitive paths in robots/sitemap.",
        ],
        ["- CWE-200: Exposure of Sensitive Information"],
        ["`scope_check`", "`http_probe`", "`analyze_repo`", "`get_wstg_test`"],
        [
            "Passive recon only — no destructive probes.",
            "Correlate search-engine findings with live `http_probe` status.",
            "Save interesting URLs to engagement context for later phases.",
        ],
    ),
    "CONF": (
        [
            "- V14 Configuration — secure defaults for headers, TLS, methods.",
            "- V13 API and Web Service — admin interfaces not exposed.",
        ],
        ["- CWE-16: Configuration", "- CWE-319: Cleartext Transmission"],
        ["`http_probe`", "`compare_role_response`", "`record_finding`"],
        [
            "Test HTTP methods, security headers, and TLS cipher suites.",
            "Verify admin/debug interfaces return 404 or require auth in production.",
        ],
    ),
    "IDNT": (
        [
            "- V2 Authentication — identity lifecycle and enumeration resistance.",
            "- V4 Access Control — role assignment integrity.",
        ],
        ["- CWE-287: Improper Authentication", "- CWE-306: Missing Authentication"],
        ["`http_probe`", "`auth_login`", "`compare_role_response`"],
        ["Test username enumeration via response timing and error messages."],
    ),
    "ATHN": (
        [
            "- V2 Authentication — credential storage, lockout, MFA.",
            "- V3 Session Management — session binding and rotation.",
        ],
        [
            "- CWE-307: Improper Restriction of Excessive Authentication Attempts",
            "- CWE-798: Use of Hard-coded Credentials",
        ],
        ["`auth_login`", "`http_probe`", "`compare_role_response`", "`record_finding`"],
        [
            "Test password policy, lockout, and MFA bypass paths.",
            "Verify tokens/sessions invalidated on logout and password change.",
        ],
    ),
    "ATHZ": (
        [
            "- V4 Access Control — horizontal and vertical privilege checks.",
            "- V13 API — object-level authorization on every endpoint.",
        ],
        [
            "- CWE-639: Authorization Bypass Through User-Controlled Key",
            "- CWE-284: Improper Access Control",
        ],
        ["`run_idor_matrix`", "`compare_role_response`", "`rbac_matrix`", "`check_access`"],
        [
            "Mandatory cross-role comparison on every object ID parameter.",
            "Document 403 vs 404 behavior — both can indicate IDOR signals.",
        ],
    ),
    "SESS": (
        [
            "- V3 Session Management — fixation, timeout, secure cookie flags.",
            "- V2 Authentication — session binding to client fingerprint where applicable.",
        ],
        ["- CWE-384: Session Fixation", "- CWE-613: Insufficient Session Expiration"],
        ["`http_probe`", "`compare_role_response`", "`auth_login`"],
        ["Test cookie flags, rotation on login, and concurrent session limits."],
    ),
    "INPV": (
        [
            "- V5 Validation — input handling and parser differentials.",
            "- V12 Files and Resources — upload and inclusion controls.",
        ],
        [
            "- CWE-20: Improper Input Validation",
            "- CWE-89: SQL Injection",
            "- CWE-79: Cross-site Scripting",
        ],
        ["`http_probe`", "`rynix_plugin_run` (template-scan)", "`record_finding`"],
        [
            "Fuzz parameters with encoding variants (URL, Unicode, double-encoding).",
            "Switch Content-Type to traverse alternate validators.",
        ],
    ),
    "ERRH": (
        [
            "- V7 Error Handling — no stack traces or internal paths in responses.",
            "- V14 Configuration — custom error pages in production.",
        ],
        ["- CWE-209: Generation of Error Message Containing Sensitive Information"],
        ["`http_probe`", "`record_finding`"],
        ["Trigger edge-case inputs and verify generic error responses only."],
    ),
    "CRYP": (
        [
            "- V6 Stored Cryptography — algorithms, keys, and randomness.",
            "- V9 Communications — TLS configuration and HSTS.",
        ],
        ["- CWE-326: Inadequate Encryption Strength", "- CWE-327: Broken Crypto Algorithm"],
        ["`http_probe`", "`record_finding`"],
        ["Verify TLS versions, cipher suites, and sensitive data not in cleartext."],
    ),
    "BUSL": (
        [
            "- V11 Business Logic — workflow integrity and limit enforcement.",
            "- V4 Access Control — state transitions require proper authorization.",
        ],
        ["- CWE-840: Business Logic Errors", "- CWE-362: Race Condition"],
        ["`http_probe`", "`compare_role_response`", "`record_finding`"],
        [
            "Test price/quantity manipulation and workflow step skipping.",
            "Parallel requests for race windows on limits and balances.",
        ],
    ),
    "CLNT": (
        [
            "- V3 Session Management — client-side token storage.",
            "- V5 Validation — DOM sinks and postMessage origins.",
        ],
        ["- CWE-79: XSS", "- CWE-1021: Improper Restriction of Rendered UI Layers"],
        ["`list_frontend_routes`", "`http_probe`", "`rynix_plugin_run` (browser-debug)"],
        ["Map client routes; verify server enforces auth regardless of UI guards."],
    ),
    "APIT": (
        [
            "- V13 API and Web Service — schema, auth, and rate limiting.",
            "- V4 Access Control — BOLA/IDOR on API object references.",
        ],
        ["- CWE-285: Improper Authorization", "- CWE-770: Allocation of Resources Without Limits"],
        ["`list_api_routes`", "`export_openapi_stub`", "`run_idor_matrix`", "`http_probe`"],
        [
            "Diff OpenAPI spec vs live routes from `analyze_repo`.",
            "Test batch/GraphQL endpoints for authorization per field.",
        ],
    ),
}


def _category(test_id: str) -> str:
    # WSTG-ATHZ-01 -> ATHZ, WSTG-INFO-01 -> INFO
    m = re.match(r"WSTG-([A-Z]+)-\d+", test_id.upper())
    return m.group(1) if m else "CONF"


def _replace_section(text: str, heading: str, body: str) -> str:
    pattern = rf"(?m)^{heading}\n.*?(?=\n## |\Z)"
    block = heading + "\n\n" + body.strip() + "\n"
    if re.search(pattern, text, flags=re.DOTALL):
        return re.sub(pattern, block.rstrip() + "\n", text, count=1, flags=re.DOTALL)
    return text.rstrip() + "\n\n" + block


def enrich_file(path: Path) -> bool:
    test_id = path.stem.upper()
    cat = _category(test_id)
    asvs, cwe, tools, focus = CATEGORY.get(cat, CATEGORY["CONF"])
    text = path.read_text(encoding="utf-8")
    original = text

    asvs_body = "\n".join(asvs)
    cwe_body = "\n".join(cwe)
    tools_body = "- Primary tools: " + ", ".join(f"`{t}`" for t in tools)
    focus_body = "\n".join(f"- {line}" for line in focus)

    text = _replace_section(text, "## ASVS mapping", asvs_body)
    text = _replace_section(text, "## CWE references", cwe_body)
    text = _replace_section(text, "## Rynix tooling", tools_body)
    text = _replace_section(text, "## Test focus", focus_body)

    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main() -> int:
    updated = 0
    for path in sorted(WSTG.rglob("WSTG-*.md")):
        if enrich_file(path):
            updated += 1
    print(f"deep-enriched {updated} WSTG files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
