"""Live IDOR/RBAC matrix — dual-token compare with session evidence export."""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx

from rynix_mcp.config import PROFILES_DIR
from rynix_mcp.path_safety import resolve_export_output_dir
from rynix_mcp.probe_accounts import (
    accounts_have_passwords,
    load_probe_accounts,
    missing_credentials_message,
    password_for,
)
from rynix_mcp.profile_risk import load_idor_role_pairs, load_risk_profile
from rynix_mcp.profiles import load_profile, resolve_profile_name
from rynix_mcp.scanner import validate_repo_path
from rynix_mcp.target_repo import set_target_repo_env, target_repo_env

logger = logging.getLogger(__name__)


def _role_pairs_for_profile(profile_name: str) -> list[tuple[str, str]]:
    prof = load_profile(profile_name, PROFILES_DIR)
    return load_idor_role_pairs(prof)


def _discover_object_ids(
    base_url: str, token: str, list_path: str, profile: str, session_id: str | None = None
) -> list[str]:
    from rynix_mcp.http_session import request as session_request

    try:
        resp = session_request(
            base_url,
            "GET",
            list_path,
            session_id=session_id,
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []
        rows: list[Any] = []
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            for key in ("items", "results", "data", "cases", "clients"):
                val = data.get(key)
                if isinstance(val, list):
                    rows = val
                    break
        if not rows:
            return []
        ids: list[str] = []
        for row in rows[:5]:
            if isinstance(row, dict):
                for key in ("id", "case_id", "client_id"):
                    if key in row and row[key] is not None:
                        ids.append(str(row[key]))
                        break
        return ids
    except (
        httpx.HTTPError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        AttributeError,
        OSError,
    ) as exc:
        logger.debug("Failed extracting seed IDs from response: %s", exc)
        return []


def _run_comparison(
    *,
    base_url: str,
    method: str,
    path: str,
    ra: str,
    rb: str,
    tokens: dict[str, str],
    profile: str,
    allow_live: bool,
    repo: str | None,
    session_id: str,
) -> dict[str, Any]:
    from rynix_mcp.server import compare_role_response

    cmp = compare_role_response(
        base_url=base_url,
        path=path,
        method=method,
        token_a=tokens[ra],
        token_b=tokens[rb],
        profile=profile,
        role_a=ra,
        role_b=rb,
        allow_live=allow_live,
        repo_path=repo,
        session_id=session_id,
    )
    return {
        "method": method,
        "path": path,
        "role_a": ra,
        "role_b": rb,
        **cmp,
    }


def run_idor_matrix(
    base_url: str,
    profile: str | None = None,
    repo_path: str | None = None,
    session_id: str = "idor-matrix",
    allow_live: bool = False,
    export_dir: str | None = None,
    roles: list[str] | None = None,
    parallel: bool | None = None,
) -> dict[str, Any]:
    """Login roles, run compare_role_response matrix, optional export_report with evidence."""
    from rynix_mcp.http_session import ensure_stealth_gate
    from rynix_mcp.server import auth_login, export_report, scope_check

    default_pwd = os.environ.get("RYNIX_PROBE_PASSWORD", "")
    ceo_pwd = os.environ.get("RYNIX_PROBE_PASSWORD_CEO", default_pwd)
    accounts = load_probe_accounts(session_id=session_id)
    if not accounts_have_passwords(accounts):
        return {
            "error": {
                "code": "MISSING_CREDENTIALS",
                "message": missing_credentials_message(accounts),
                "retryable": False,
            }
        }

    repo = repo_path or target_repo_env() or None
    repo_path_obj: Path | None = None
    if repo:
        try:
            repo_path_obj = validate_repo_path(repo)
        except ValueError:
            repo_path_obj = None
    profile = resolve_profile_name(profile, repo_path_obj)
    prof = load_profile(profile, PROFILES_DIR, repo_path_obj)
    risk = load_risk_profile(prof)

    scope = scope_check(base_url, profile, repo_path=repo)
    if not scope.get("allowed"):
        return {"error": {"code": "SCOPE_DENIED", "message": str(scope), "retryable": False}}

    if not ensure_stealth_gate(base_url, session_id, profile=prof, repo_path=repo):
        return {
            "error": {
                "code": "GATE_FAILED",
                "message": "Stealth gate unlock failed — set gate secret env from profile [stealth.gate]",
                "retryable": True,
            }
        }

    role_list = roles or list(accounts.keys())
    tokens: dict[str, str] = {}
    login_errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    ephemeral_ids: list[int] = []
    from rynix_mcp.session import STORE

    login_gap = float(os.environ.get("RYNIX_MATRIX_LOGIN_GAP_SEC", "1.0"))
    login_retries = int(os.environ.get("RYNIX_MATRIX_LOGIN_RETRIES", "3"))
    retry_429_wait = float(os.environ.get("RYNIX_MATRIX_429_WAIT_SEC", "62"))

    for role in role_list:
        if role not in accounts:
            continue
        session = STORE.get(session_id)
        if role in session.tokens:
            tokens[role] = session.tokens[role]
            continue
        username, env_key = accounts[role]
        pwd = password_for(env_key, default_pwd, ceo_pwd)
        result: dict[str, Any] = {}
        for attempt in range(login_retries):
            result = auth_login(
                base_url,
                username,
                pwd,
                profile=profile,
                role_label=role,
                session_id=session_id,
                allow_live=allow_live,
                repo_path=repo,
            )
            if "error" not in result:
                break
            message = str(result.get("error", {}).get("message", ""))
            if "429" in message and attempt + 1 < login_retries:
                time.sleep(retry_429_wait)
                continue
            break
        if "error" in result:
            login_errors.append({"role": role, "error": result["error"]})
        else:
            tok = session.tokens.get(role)
            if tok:
                tokens[role] = tok
        if login_gap > 0:
            time.sleep(login_gap)

    missing_privileged = [r for r in risk.discovery_roles if r in role_list and r not in tokens]
    if missing_privileged and repo:
        set_target_repo_env(repo)
        try:
            from rynix_mcp.mirror_ephemeral_roles import mint_missing_mirror_tokens

            minted = mint_missing_mirror_tokens(missing_privileged)
            for role, tok in minted.get("tokens", {}).items():
                tokens[role] = tok
                STORE.get(session_id).tokens[role] = tok
            ephemeral_ids.extend(minted.get("created_ids", []))
            if minted.get("minted_roles"):
                warnings.append(f"ephemeral_minted:{','.join(minted['minted_roles'])}")
        except Exception as exc:
            warnings.append(f"ephemeral_mint_failed:{exc}")

    probe_paths = list(risk.list_probe_paths)
    discover_token = next((tokens[r] for r in risk.discovery_roles if r in tokens), None)
    case_ids: list[str] = []
    client_ids: list[str] = []
    if discover_token:
        case_ids = _discover_object_ids(
            base_url, discover_token, "/api/v1/cases/", profile, session_id
        )
        client_ids = _discover_object_ids(
            base_url, discover_token, "/api/v1/clients/", profile, session_id
        )
        if not case_ids:
            warnings.append("case_object_discovery_empty")
        if not client_ids:
            warnings.append("client_object_discovery_empty")
        for cid in case_ids[:2]:
            probe_paths.append(("GET", f"/api/v1/cases/{cid}"))
        for cid in client_ids[:2]:
            probe_paths.append(("GET", f"/api/v1/clients/{cid}"))
    else:
        warnings.append("object_discovery_skipped_no_privileged_token")
        for method, template in risk.object_templates:
            probe_paths.append((method, template.format(id="1")))

    if not any(
        p for _, p in probe_paths if "{" not in p and p.rstrip("/").split("/")[-1].isdigit()
    ):
        warnings.append("using_placeholder_object_ids")

    role_pairs = _role_pairs_for_profile(profile)
    active_pairs = [(ra, rb) for ra, rb in role_pairs if ra in tokens and rb in tokens]
    if roles is not None and len(tokens) >= 2 and not active_pairs:
        ordered = sorted(tokens.keys(), key=lambda r: risk.role_trust_level(r))
        active_pairs = [
            (ordered[i], ordered[j])
            for i in range(len(ordered))
            for j in range(i + 1, len(ordered))
        ]
    if not active_pairs:
        warnings.append(
            "NO_ACTIVE_ROLE_PAIRS: no privileged tokens resolved; IDOR cross-role checks were NOT executed"
        )
    if not probe_paths:
        warnings.append("NO_PROBE_PATHS: no probe paths resolved for IDOR testing")

    jobs: list[tuple[str, str, str, str]] = []
    for method, path in probe_paths:
        for ra, rb in active_pairs:
            jobs.append((method, path, ra, rb))

    use_parallel = parallel
    if use_parallel is None:
        use_parallel = os.environ.get("RYNIX_IDOR_PARALLEL", "").lower() in ("1", "true", "yes")

    results: list[dict[str, Any]] = []
    idor_signals = 0

    if use_parallel and jobs:
        with ThreadPoolExecutor(max_workers=min(4, len(jobs))) as pool:
            futures = {
                pool.submit(
                    _run_comparison,
                    base_url=base_url,
                    method=method,
                    path=path,
                    ra=ra,
                    rb=rb,
                    tokens=tokens,
                    profile=profile,
                    allow_live=allow_live,
                    repo=repo,
                    session_id=session_id,
                ): (method, path, ra, rb)
                for method, path, ra, rb in jobs
            }
            for future in as_completed(futures):
                row = future.result()
                results.append(row)
                if row.get("idor_likely"):
                    idor_signals += 1
    else:
        for method, path, ra, rb in jobs:
            row = _run_comparison(
                base_url=base_url,
                method=method,
                path=path,
                ra=ra,
                rb=rb,
                tokens=tokens,
                profile=profile,
                allow_live=allow_live,
                repo=repo,
                session_id=session_id,
            )
            results.append(row)
            if row.get("idor_likely"):
                idor_signals += 1

    out_paths: dict[str, str] = {}
    out_root = resolve_export_output_dir(export_dir or "live-idor-matrix")
    out_root.mkdir(parents=True, exist_ok=True)
    matrix_path = out_root / "matrix.json"
    if not results:
        matrix_payload: Any = {
            "coverage_warning": "NO_ACTIVE_ROLE_PAIRS" if not active_pairs else "NO_PROBE_PATHS",
            "message": (
                "no privileged tokens resolved; IDOR cross-role checks were NOT executed"
                if not active_pairs
                else "no probe paths resolved for IDOR checks"
            ),
            "executed": False,
            "jobs": len(jobs),
            "results": [],
        }
    else:
        matrix_payload = results
    matrix_path.write_text(json.dumps(matrix_payload, indent=2), encoding="utf-8")
    out_paths["matrix_json"] = str(matrix_path)

    report_paths = export_report(
        str(out_root), session_id=session_id, formats="markdown,json,sarif"
    )
    out_paths.update(report_paths)

    if ephemeral_ids:
        try:
            import asyncio

            from rynix_mcp.mirror_ephemeral_roles import cleanup_ephemeral_users

            asyncio.run(cleanup_ephemeral_users(ephemeral_ids))
        except Exception as exc:
            warnings.append(f"ephemeral_cleanup_failed:{exc}")

    coverage_note = "full" if case_ids or client_ids else "list_paths_and_placeholders_only"

    return {
        "base_url": base_url,
        "profile": profile,
        "session_id": session_id,
        "roles_logged_in": list(tokens.keys()),
        "login_errors": login_errors,
        "warnings": warnings,
        "coverage_note": coverage_note,
        "parallel": use_parallel,
        "comparisons": len(results),
        "idor_signals": idor_signals,
        "results": results,
        "output": out_paths,
    }
