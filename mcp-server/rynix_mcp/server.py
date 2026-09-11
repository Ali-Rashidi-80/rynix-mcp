from __future__ import annotations

import html as _html
import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from rynix_mcp import __version__
from rynix_mcp.config import (
    PROFILES_DIR,
    ROOT,
    SCOPE_ALLOWLIST_ENV,
    resolve_scanner_bin,
)
from rynix_mcp.engagement_session import (
    get_engagement_context as _get_engagement_context,
    list_engagement_progress as _list_engagement_progress,
    register_scope as _register_scope,
    save_engagement_context as _save_engagement_context,
    track_probe_step as _track_probe_step,
    track_wstg_test as _track_wstg_test,
)
from rynix_mcp.idor_matrix import run_idor_matrix as _run_idor_matrix
from rynix_mcp.knowledge import (
    get_guide_section as load_guide_section,
    get_technique_guide as load_technique_guide,
    get_wstg_test as load_wstg_test,
)
from rynix_mcp.path_safety import resolve_evidence_path, resolve_export_output_dir
from rynix_mcp.plugins import (
    list_plugin_manifests,
    plugin_health_check as _plugin_health_check,
    rynix_plugin_run as _execute_plugin,
)
from rynix_mcp.probe_urls import extract_probe_urls, require_all_in_scope
from rynix_mcp.profile_risk import load_risk_profile
from rynix_mcp.profiles import list_profiles as list_profile_catalog, load_profile
from rynix_mcp.sarif import export_sarif
from rynix_mcp.scanner import profile_auth, run_scan, scope_allowed, validate_repo_path
from rynix_mcp.scope import live_probe_allowed
from rynix_mcp.session import (
    MAX_FINDINGS_ENTRIES,
    STORE,
    Finding,
    body_hash,
    json_field_overlap,
    new_finding_id,
)


def _html_safe(val: Any) -> str:
    s = str(val if val is not None else "")
    return _html.escape(s, quote=True)


def _md_safe(val: Any) -> str:
    s = str(val if val is not None else "").replace("\r", "")
    return re.sub(r"^(\s*)([#>\-*`]|\|)", r"\1\\\2", s, flags=re.M)


logging.basicConfig(level=logging.WARNING, stream=__import__("sys").stderr)
logger = logging.getLogger("rynix_mcp.server")
logging.getLogger("mcp").setLevel(logging.WARNING)
logger = logging.getLogger("rynix-mcp")

mcp = FastMCP("rynix-mcp")

_rate_lock = threading.Lock()
_rate_last_by_host: dict[str, float] = {}
_SMS_SEGMENT_RE = re.compile(r"(?:^|/)(?:sms|send-sms)(?:/|$|\?)", re.I)
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def _rate_limit(base_url: str) -> None:
    host = (urlparse(base_url).hostname or "default").lower()
    min_interval = 1.0 / 10.0
    with _rate_lock:
        now = time.monotonic()
        last = _rate_last_by_host.get(host, 0.0)
        elapsed = now - last
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        _rate_last_by_host[host] = time.monotonic()


def _err(code: str, message: str, retryable: bool = False) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "retryable": retryable}}


def _require_scope(
    base_url: str,
    profile_name: str | None,
    repo_path: str | Path | None = None,
) -> tuple[bool, str]:
    repo: Path | None = None
    if repo_path:
        try:
            repo = validate_repo_path(str(repo_path))
        except ValueError:
            repo = None
    try:
        profile = load_profile(profile_name, PROFILES_DIR, repo)
    except ValueError as exc:
        return False, str(exc)
    return scope_allowed(base_url, profile, SCOPE_ALLOWLIST_ENV)


@mcp.tool()
def health_check(repo_path: str | None = None) -> dict[str, Any]:
    """Verify Rust scanner binary, profiles dir, and optional repo smoke scan."""
    bin_path = resolve_scanner_bin()
    ok = bin_path.is_file()
    scan_version = "unknown"
    if ok:
        try:
            proc = subprocess.run(
                [str(bin_path), "version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                encoding="utf-8",
                errors="replace",
            )
            scan_version = (proc.stdout or proc.stderr or "").strip().splitlines()[0] or "unknown"
        except (subprocess.TimeoutExpired, OSError):
            scan_version = "unknown"
    result: dict[str, Any] = {
        "ok": ok,
        "rynix_scan_version": scan_version,
        "rynix_mcp_version": __version__,
        "python_ok": True,
        "profiles_dir": str(PROFILES_DIR),
        "scanner_bin": str(bin_path),
    }
    if repo_path and ok:
        try:
            scan = run_scan(validate_repo_path(repo_path))
            result["smoke_modules"] = scan.get("modules_scanned", 0)
        except Exception as exc:
            result["smoke_error"] = str(exc)
    return result


@mcp.tool()
def list_profiles() -> dict[str, Any]:
    """List bundled profile presets."""
    return {"profiles": list_profile_catalog(PROFILES_DIR)}


@mcp.tool()
def analyze_repo(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """Full Rust static scan: routes, RBAC hints, risk surfaces."""
    try:
        path = validate_repo_path(repo_path)
        return run_scan(path, profile)
    except Exception as exc:
        return _err("SCAN_FAILED", str(exc))


@mcp.tool()
def list_api_routes(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """API route inventory from static scan."""
    try:
        scan = run_scan(validate_repo_path(repo_path), profile)
        return {"routes": scan.get("routes", [])}
    except Exception as exc:
        return _err("SCAN_FAILED", str(exc))


@mcp.tool()
def list_frontend_routes(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """Frontend route map from static scan."""
    try:
        scan = run_scan(validate_repo_path(repo_path), profile)
        return {"routes": scan.get("frontend_routes", [])}
    except Exception as exc:
        return _err("SCAN_FAILED", str(exc))


@mcp.tool()
def rbac_matrix(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """RBAC/ABAC matrix with IDOR risk scores."""
    try:
        scan = run_scan(validate_repo_path(repo_path), profile)
        return {"matrix": scan.get("rbac_hints", [])}
    except Exception as exc:
        return _err("SCAN_FAILED", str(exc))


@mcp.tool()
def high_risk_surfaces(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """High-risk endpoints from static analysis."""
    try:
        scan = run_scan(validate_repo_path(repo_path), profile)
        return {"surfaces": scan.get("risk_surfaces", [])}
    except Exception as exc:
        return _err("SCAN_FAILED", str(exc))


@mcp.tool()
def generate_pentest_brief(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """Generate concerns/focus/context brief from profile + live scan."""
    try:
        path = validate_repo_path(repo_path)
        prof = load_profile(profile, PROFILES_DIR, path)
        scan = run_scan(path, profile)
        brief = prof.get("brief", {}) if isinstance(prof.get("brief"), dict) else {}

        concerns = list(brief.get("concerns", []))
        focus = list(brief.get("focus", []))
        context = list(brief.get("context", []))

        for surface in scan.get("risk_surfaces", [])[:15]:
            concerns.append(
                f"{surface.get('method')} {surface.get('path')}: {surface.get('reason')}"
            )

        for hit in scan.get("secret_hits", [])[:5]:
            concerns.append(
                f"Secret pattern {hit.get('pattern')} in {hit.get('file')}:{hit.get('line')}"
            )

        for hint in scan.get("rbac_hints", []):
            if hint.get("idor_risk_score", 0) >= 55:
                focus.append(f"IDOR test: {hint.get('endpoint')}")

        context.append(f"Modules scanned: {scan.get('modules_scanned', 0)}")
        context.append(f"Stack: {prof.get('stack', [])}")

        return {
            "concerns": "\n".join(f"- {c}" for c in concerns)
            if concerns
            else "No concerns configured.",
            "focus": "\n".join(f"- {f}" for f in focus)
            if focus
            else "Run compare_role_response on {{id}} endpoints.",
            "context": "\n".join(f"- {c}" for c in context),
        }
    except Exception as exc:
        return _err("BRIEF_FAILED", str(exc))


@mcp.tool()
def scope_check(
    base_url: str,
    profile: str | None = None,
    repo_path: str | None = None,
) -> dict[str, Any]:
    """Validate base_url against profile allowlist before live probes."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    return {"allowed": allowed, "matched_rule": reason if allowed else None, "reason": reason}


def _require_live_probe(
    repo_path: str | None,
    allow_live: bool,
) -> tuple[bool, str]:
    path = None
    if repo_path:
        try:
            path = validate_repo_path(repo_path)
        except ValueError as exc:
            return False, str(exc)
    return live_probe_allowed(path, allow_live)


@mcp.tool()
def http_probe(
    base_url: str,
    path: str,
    method: str = "GET",
    profile: str | None = None,
    allow_write: bool = False,
    allow_sms: bool = False,
    allow_live: bool = False,
    repo_path: str | None = None,
    token: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Controlled HTTP probe (GET/HEAD/OPTIONS by default)."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    if not allowed:
        return _err("SCOPE_DENIED", reason)

    live_ok, live_reason = _require_live_probe(repo_path, allow_live)
    if not live_ok:
        return _err("LIVE_PROBE_DENIED", live_reason)

    method = method.upper()
    destructive = method in {"POST", "PUT", "PATCH", "DELETE"}
    if destructive and not allow_write:
        return _err("WRITE_BLOCKED", "destructive methods require allow_write=true")

    if not allow_sms and _SMS_SEGMENT_RE.search(path):
        return _err("SMS_BLOCKED", "SMS endpoints blocked unless allow_sms=true")

    if method not in {"GET", "HEAD", "OPTIONS"} and not allow_write:
        return _err("METHOD_BLOCKED", f"{method} requires allow_write=true")

    _rate_limit(base_url)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        from rynix_mcp.http_session import request as session_request

        repo: Path | None = None
        if repo_path:
            try:
                repo = validate_repo_path(repo_path)
            except ValueError:
                repo = None
        prof = load_profile(profile, PROFILES_DIR, repo)
        resp = session_request(
            base_url,
            method,
            url,
            session_id=session_id,
            headers=headers,
            follow_redirects=False,
            profile=prof,
            repo_path=repo_path,
        )
        preview = resp.text[:2000]
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": preview,
            "hash": body_hash(resp.text),
        }
    except Exception as exc:
        return _err("HTTP_FAILED", str(exc), retryable=True)


@mcp.tool()
def auth_login(
    base_url: str,
    username: str,
    password: str,
    profile: str | None = None,
    role_label: str | None = None,
    session_id: str | None = None,
    allow_live: bool = False,
    repo_path: str | None = None,
) -> dict[str, Any]:
    """Login via profile auth settings; stores token in session memory only."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    if not allowed:
        return _err("SCOPE_DENIED", reason)

    live_ok, live_reason = _require_live_probe(repo_path, allow_live)
    if not live_ok:
        return _err("LIVE_PROBE_DENIED", live_reason)

    repo: Path | None = None
    if repo_path:
        try:
            repo = validate_repo_path(repo_path)
        except ValueError:
            repo = None
    prof = load_profile(profile, PROFILES_DIR, repo)
    auth = profile_auth(prof)
    url = base_url.rstrip("/") + auth["login_path"]
    data = {auth["username_field"]: username, auth["password_field"]: password}

    from rynix_mcp.auth_captcha import fetch_captcha_fields, response_needs_captcha
    from rynix_mcp.http_session import _is_local, request as session_request
    from rynix_mcp.profile_hooks import captcha_settings

    captcha_cfg = captcha_settings(prof)
    captcha_mode = os.environ.get("RYNIX_AUTH_CAPTCHA", "auto").strip().lower()
    use_captcha = captcha_cfg and (
        captcha_mode in ("1", "true", "yes", "on")
        or (captcha_mode == "auto" and not _is_local(base_url))
    )
    if use_captcha:
        try:
            data.update(fetch_captcha_fields(base_url, captcha_cfg, session_id=session_id))
        except Exception as exc:
            logger.warning("Failed to fetch captcha fields for %s: %s", base_url, exc)

    _rate_limit(base_url)
    try:
        headers = {"Content-Type": auth["content_type"]}
        if auth["content_type"] == "application/x-www-form-urlencoded":
            resp = session_request(
                base_url,
                "POST",
                url,
                session_id=session_id,
                data=data,
                headers=headers,
                follow_redirects=True,
                profile=prof,
                repo_path=repo_path,
            )
        else:
            resp = session_request(
                base_url,
                "POST",
                url,
                session_id=session_id,
                json_body=data,
                headers=headers,
                follow_redirects=True,
                profile=prof,
                repo_path=repo_path,
            )
        if resp.status_code >= 400 and response_needs_captcha(
            resp.status_code, resp.text, captcha_cfg
        ):
            data.update(fetch_captcha_fields(base_url, captcha_cfg, session_id=session_id))
            _rate_limit(base_url)
            if auth["content_type"] == "application/x-www-form-urlencoded":
                resp = session_request(
                    base_url,
                    "POST",
                    url,
                    session_id=session_id,
                    data=data,
                    headers=headers,
                    follow_redirects=True,
                    profile=profile,
                    repo_path=repo_path,
                )
            else:
                resp = session_request(
                    base_url,
                    "POST",
                    url,
                    session_id=session_id,
                    json_body=data,
                    headers=headers,
                    follow_redirects=True,
                    profile=profile,
                    repo_path=repo_path,
                )
        if resp.status_code >= 400:
            return _err("AUTH_FAILED", f"status {resp.status_code}: {resp.text[:200]}")
        payload = resp.json()
        token = payload.get(auth["token_field"]) or payload.get("access_token")
        if not token:
            return _err("AUTH_FAILED", "token field missing in response")

        session = STORE.get(session_id)
        label = role_label or username
        session.tokens[label] = str(token)
        session.audit_log("auth_login", {"role_label": label, "status": resp.status_code})

        return {
            "token_preview": f"...{str(token)[-4:]}",
            "expires_hint": payload.get("expires_in"),
            "role_label": label,
        }
    except Exception as exc:
        return _err("AUTH_FAILED", str(exc))


@mcp.tool()
def unlock_stealth_gate(
    base_url: str,
    profile: str | None = None,
    session_id: str | None = None,
    repo_path: str | None = None,
    allow_live: bool = False,
) -> dict[str, Any]:
    """Unlock profile stealth gate; stores cookie in session for later probes."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    if not allowed:
        return _err("SCOPE_DENIED", reason)

    live_ok, live_reason = _require_live_probe(repo_path, allow_live)
    if not live_ok:
        return _err("LIVE_PROBE_DENIED", live_reason)

    from rynix_mcp.http_session import ensure_stealth_gate
    from rynix_mcp.stealth_gate import gate_audit_entry, load_gate_secret

    prof_data = (
        load_profile(profile, PROFILES_DIR, Path(repo_path) if repo_path else None)
        if (profile or repo_path)
        else None
    )
    ok = ensure_stealth_gate(base_url, session_id, profile=prof_data, repo_path=repo_path)
    if not ok:
        return _err("GATE_UNLOCK_FAILED", "RYNIX_STEALTH_GATE_SECRET missing or unlock rejected")

    secret = load_gate_secret(prof_data, repo_path)
    if secret:
        session = STORE.get(session_id)
        session.audit_log("stealth_gate_unlocked", gate_audit_entry(secret))

    return {"unlocked": True, "base_url": base_url, "session_id": session_id or "default"}


@mcp.tool()
def check_access(
    base_url: str,
    path: str,
    method: str,
    token: str,
    profile: str | None = None,
    allow_write: bool = False,
    allow_live: bool = False,
    repo_path: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Call endpoint with bearer token (E4: status, body_hash, snippet)."""
    result = http_probe(
        base_url,
        path,
        method=method,
        profile=profile,
        allow_write=allow_write,
        allow_live=allow_live,
        repo_path=repo_path,
        token=token,
        session_id=session_id,
    )
    if "error" in result:
        return result
    preview = result.get("body_preview") or ""
    return {
        "status": result.get("status"),
        "body_hash": result.get("hash"),
        "snippet": preview[:500],
    }


def _substantive_response_body(text: str) -> bool:
    """Ignore empty/trivial JSON bodies that produce list-endpoint false positives."""
    stripped = text.strip()
    if not stripped or stripped in ("[]", "{}", "null"):
        return False
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return len(stripped) >= 16
    if isinstance(parsed, list):
        return len(parsed) > 0
    if isinstance(parsed, dict):
        for key in ("items", "results", "data", "cases", "clients"):
            val = parsed.get(key)
            if isinstance(val, list):
                return len(val) > 0
        if len(parsed) == 1 and "detail" in parsed:
            return False
        return len(parsed) > 0
    return True


@mcp.tool()
def compare_role_response(
    base_url: str,
    path: str,
    method: str,
    token_a: str,
    token_b: str,
    profile: str | None = None,
    role_a: str | None = None,
    role_b: str | None = None,
    allow_live: bool = False,
    allow_write: bool = False,
    repo_path: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Dual-token IDOR/BOLA comparison per OWASP API1 evidence class."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    if not allowed:
        return _err("SCOPE_DENIED", reason)

    live_ok, live_reason = _require_live_probe(repo_path, allow_live)
    if not live_ok:
        return _err("LIVE_PROBE_DENIED", live_reason)

    method = method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"} and not allow_write:
        return _err("METHOD_BLOCKED", f"{method} requires allow_write=true")

    repo: Path | None = None
    if repo_path:
        try:
            repo = validate_repo_path(repo_path)
        except ValueError:
            repo = None
    prof = load_profile(profile, PROFILES_DIR, repo)
    risk = load_risk_profile(prof)

    _rate_limit(base_url)
    url = base_url.rstrip("/") + "/" + path.lstrip("/")

    try:
        from rynix_mcp.http_session import request as session_request

        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}
        resp_a = session_request(
            base_url,
            method,
            url,
            session_id=session_id,
            headers=headers_a,
            follow_redirects=False,
            profile=prof,
            repo_path=repo_path,
        )
        _rate_limit(base_url)
        resp_b = session_request(
            base_url,
            method,
            url,
            session_id=session_id,
            headers=headers_b,
            follow_redirects=False,
            profile=prof,
            repo_path=repo_path,
        )

        hash_a = body_hash(resp_a.text)
        hash_b = body_hash(resp_b.text)
        overlap = json_field_overlap(resp_a.text, resp_b.text)

        idor_likely = False
        verdict = "no_signal"

        # Horizontal BOLA: both identities receive 200 with identical body on same resource.
        # Same JSON keys with different values (e.g. role-scoped dashboard) is NOT IDOR.
        if (
            resp_a.status_code == 200
            and resp_b.status_code == 200
            and hash_a == hash_b
            and _substantive_response_body(resp_a.text)
            and _substantive_response_body(resp_b.text)
        ):
            if risk.expected_assignment_scoped_rbac(path, role_a, role_b):
                verdict = "expected_rbac_scope"
            else:
                idor_likely = True
                verdict = "idor_likely"
        # Privilege inversion: lower-trust token succeeds where higher-trust is denied.
        elif resp_a.status_code == 200 and resp_b.status_code in (401, 403, 404):
            if risk.expected_assignment_scoped_rbac(path, role_a, role_b) or (
                role_a and role_b and risk.role_trust_level(role_a) >= risk.role_trust_level(role_b)
            ):
                verdict = "expected_rbac_scope"
            else:
                idor_likely = True
                verdict = "privilege_inversion_suspect"
        # Note: 403 vs 200 (a denied, b allowed) is usually expected RBAC — not flagged.

        result = {
            "verdict": verdict,
            "idor_likely": idor_likely,
            "diff": {
                "status_a": resp_a.status_code,
                "status_b": resp_b.status_code,
                "hash_a": hash_a,
                "hash_b": hash_b,
                "field_overlap": round(overlap, 3),
                "role_a": role_a,
                "role_b": role_b,
            },
        }
        if session_id:
            session = STORE.get(session_id)
            session.add_evidence(
                f"compare-{method}-{path.strip('/').replace('/', '_')}.txt",
                json.dumps(result, indent=2),
            )
            session.audit_log("compare_role_response", {"path": path, "verdict": verdict})
        return result
    except Exception as exc:
        return _err("COMPARE_FAILED", str(exc), retryable=True)


@mcp.tool()
def record_finding(
    severity: str,
    title: str,
    endpoint: str,
    evidence: str,
    session_id: str | None = None,
    verified: bool = False,
    source_plugin: str = "core",
) -> dict[str, Any]:
    """Append structured finding to in-memory session."""
    sev = severity.lower().strip()
    if sev not in _VALID_SEVERITIES:
        return _err(
            "INVALID_SEVERITY",
            f"severity must be one of: {', '.join(sorted(_VALID_SEVERITIES))}",
        )
    session = STORE.get(session_id)
    if verified and session.scopes:
        evidence_lower = evidence.lower()
        probe_markers = (
            "http_probe",
            "compare_role_response",
            "run_idor_matrix",
            "status_code",
            '"method"',
        )
        if not any(m in evidence_lower for m in probe_markers):
            return _err(
                "VERIFIER_REJECT",
                "verified finding in scoped engagement requires http_probe or compare_role_response evidence",
            )
    fid = new_finding_id()
    new_f = Finding(
        id=fid,
        severity=sev,
        title=title,
        endpoint=endpoint,
        evidence=evidence,
        verified=verified,
        source_plugin=source_plugin,
    )
    if not session.add_finding(new_f):
        return _err(
            "FINDINGS_CAP_REACHED",
            f"maximum findings cap of {MAX_FINDINGS_ENTRIES} reached for session",
        )
    session.audit_log("record_finding", {"finding_id": fid, "severity": sev})
    return {"finding_id": fid}


@mcp.tool()
def export_report(
    output_dir: str,
    session_id: str | None = None,
    formats: str = "markdown,json,sarif",
    include_unverified: bool = False,
) -> dict[str, Any]:
    """Write pentest_report.md, findings.json, findings.sarif to output_dir."""
    session = STORE.get(session_id)
    out = resolve_export_output_dir(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    findings = session.findings
    if not include_unverified:
        findings = [f for f in findings if f.verified]

    fmt = {f.strip() for f in formats.split(",")}
    paths: dict[str, str] = {}

    if "json" in fmt:
        json_path = out / "findings.json"
        payload = {
            "findings": [f.to_dict() for f in findings],
            "engagement": {
                "scopes": session.scopes,
                "wstg_coverage": session.wstg_coverage,
                "probe_steps": session.probe_steps,
                "context": session.context,
                "progress": _list_engagement_progress(session.session_id),
            },
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        paths["json_path"] = str(json_path)

    if "markdown" in fmt:
        md_lines = ["# Rynix Pentest Report", "", f"Session: {session.session_id}", ""]
        for f in findings:
            md_lines.extend(
                [
                    f"## {_md_safe(f.title)} ({_md_safe(f.severity)})",
                    f"- Endpoint: {_md_safe(f.endpoint)}",
                    f"- Evidence: {_md_safe(f.evidence)}",
                    f"- Verified: {_md_safe(f.verified)}",
                    "",
                ]
            )
        md_path = out / "pentest_report.md"
        md_path.write_text("\n".join(md_lines), encoding="utf-8")
        paths["markdown_path"] = str(md_path)

    if "sarif" in fmt:
        sarif_path = out / "findings.sarif"
        sarif_path.write_text(
            json.dumps(export_sarif(findings, session.session_id), indent=2),
            encoding="utf-8",
        )
        paths["sarif_path"] = str(sarif_path)

    if "html" in fmt:
        html_lines = [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            "<title>Rynix Pentest Report</title></head><body>",
            f"<h1>Rynix Pentest Report</h1><p>Session: {_html_safe(session.session_id)}</p>",
        ]
        for f in findings:
            html_lines.extend(
                [
                    f"<h2>{_html_safe(f.title)} <small>({_html_safe(f.severity)})</small></h2>",
                    f"<p><strong>Endpoint:</strong> {_html_safe(f.endpoint)}</p>",
                    f"<p><strong>Evidence:</strong> {_html_safe(f.evidence)}</p>",
                    f"<p><strong>Verified:</strong> {_html_safe(f.verified)}</p>",
                ]
            )
        html_lines.append("</body></html>")
        html_path = out / "pentest_report.html"
        html_path.write_text("\n".join(html_lines), encoding="utf-8")
        paths["html_path"] = str(html_path)

    audit_path = out / "audit.jsonl"
    audit_path.write_text(
        "\n".join(json.dumps(line) for line in session.audit),
        encoding="utf-8",
    )
    paths["audit_path"] = str(audit_path)

    if session.evidence:
        evidence_dir = out / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for i, item in enumerate(session.evidence):
            name = item.get("name") or f"req-{i:03d}.txt"
            ev_path = resolve_evidence_path(evidence_dir, name)
            ev_path.write_text(item.get("content", ""), encoding="utf-8")
        paths["evidence_dir"] = str(evidence_dir)

    return paths


@mcp.tool()
def export_openapi_stub(repo_path: str, profile: str | None = None) -> dict[str, Any]:
    """Minimal OpenAPI 3.1 stub from route inventory."""
    try:
        scan = run_scan(validate_repo_path(repo_path), profile)
        paths: dict[str, Any] = {}
        for route in scan.get("routes", []):
            p = route.get("path", "/")
            if p not in paths:
                paths[p] = {}
            method = route.get("method", "get").lower()
            paths[p][method] = {
                "summary": route.get("handler") or "auto",
                "responses": {"200": {"description": "OK"}},
            }
        return {
            "openapi": "3.1.0",
            "info": {"title": "Rynix Stub", "version": "0.1.0"},
            "paths": paths,
        }
    except Exception as exc:
        return _err("OPENAPI_FAILED", str(exc))


@mcp.tool()
def get_technique_guide(vuln_class: str, heading: str | None = None) -> dict[str, Any]:
    """Load vuln-class testing guide from bundled knowledge (e.g. idor, xss)."""
    if heading:
        return load_guide_section(vuln_class, heading)
    return load_technique_guide(vuln_class)


@mcp.tool()
def agent_engagement_playbook(
    scan_mode: str = "standard",
    target_url: str | None = None,
    repo_path: str | None = None,
    profile: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Agent-native engagement plan — host agent (Cursor) executes steps; no external LLM API key."""
    from rynix_mcp.agent_playbook import build_agent_playbook

    return build_agent_playbook(
        scan_mode=scan_mode,
        target_url=target_url,
        repo_path=repo_path,
        profile=profile,
        session_id=session_id,
    )


@mcp.tool()
def get_wstg_test(test_id: str) -> dict[str, Any]:
    """Load OWASP WSTG test guidance by ID (e.g. WSTG-APIT-01)."""
    return load_wstg_test(test_id)


@mcp.tool()
def list_plugins() -> dict[str, Any]:
    """List Phase 6 plugin manifests from plugins/*.toml."""
    return {"plugins": list_plugin_manifests()}


@mcp.tool()
def plugin_health_check(plugin_id: str) -> dict[str, Any]:
    """Verify plugin binary/manifest health before subprocess run."""
    return _plugin_health_check(plugin_id)


@mcp.tool()
def register_scope(
    host: str, scope_type: str = "host", session_id: str | None = None
) -> dict[str, Any]:
    """Register an in-scope host or asset for the engagement session."""
    return _register_scope(host, scope_type, session_id)


@mcp.tool()
def track_wstg_test(
    test_id: str,
    status: str,
    notes: str = "",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Track WSTG test execution status in the engagement session."""
    return _track_wstg_test(test_id, status, notes, session_id)


@mcp.tool()
def track_probe_step(
    name: str,
    status: str,
    detail: str = "",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Log a probe step (tool invocation or manual check) in the session."""
    return _track_probe_step(name, status, detail, session_id)


@mcp.tool()
def save_engagement_context(
    key: str, content: str, session_id: str | None = None
) -> dict[str, Any]:
    """Save engagement notes or threat-model content keyed by name."""
    return _save_engagement_context(key, content, session_id)


@mcp.tool()
def get_engagement_context(session_id: str | None = None) -> dict[str, Any]:
    """Read saved engagement context (threat model, notes) from the session."""
    return _get_engagement_context(session_id)


@mcp.tool()
def list_engagement_progress(session_id: str | None = None) -> dict[str, Any]:
    """Aggregate WSTG coverage, scopes, and probe step counts for the session."""
    return _list_engagement_progress(session_id)


@mcp.tool()
def run_idor_matrix(
    base_url: str,
    profile: str | None = None,
    repo_path: str | None = None,
    session_id: str = "idor-matrix",
    allow_live: bool = False,
    export_dir: str | None = None,
) -> dict[str, Any]:
    """Live dual-token IDOR/RBAC matrix on mirror or staging — credentials via RYNIX_PROBE_PASSWORD env."""
    allowed, reason = _require_scope(base_url, profile, repo_path)
    if not allowed:
        return _err("SCOPE_DENIED", reason)
    live_ok, live_reason = _require_live_probe(repo_path, allow_live)
    if not live_ok:
        return _err("LIVE_PROBE_DENIED", live_reason)
    return _run_idor_matrix(
        base_url=base_url,
        profile=profile,
        repo_path=repo_path,
        session_id=session_id,
        allow_live=allow_live,
        export_dir=export_dir,
    )


@mcp.tool()
def rynix_plugin_run(
    plugin_id: str,
    target_url: str | None = None,
    options: Any = None,
    session_id: str | None = None,
    allow_live: bool = False,
    repo_path: str | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Run an enabled Rynix plugin (template-scan, wstg, engagement, etc.). Requires scope on live targets."""
    probe_urls = extract_probe_urls(target_url, options)
    if probe_urls:
        allowed, reason = require_all_in_scope(probe_urls, profile, repo_path)
        if not allowed:
            return _err("SCOPE_DENIED", reason)
        live_ok, live_reason = _require_live_probe(repo_path, allow_live)
        if not live_ok:
            return _err("LIVE_PROBE_DENIED", live_reason)
    return _execute_plugin(plugin_id, target_url, options, session_id)


def main() -> None:
    tool_names = sorted(t.name for t in mcp._tool_manager.list_tools())
    logger.info(
        "Starting Rynix MCP v%s (root=%s, tools=%d: %s)",
        __version__,
        ROOT,
        len(tool_names),
        ", ".join(tool_names),
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
