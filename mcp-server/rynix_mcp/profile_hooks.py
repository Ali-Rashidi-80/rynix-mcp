"""Optional profile-driven auth captcha and stealth gate hooks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def captcha_settings(profile: dict[str, Any]) -> dict[str, Any] | None:
    auth = profile.get("auth")
    if not isinstance(auth, dict):
        return None
    cap = auth.get("captcha")
    if not isinstance(cap, dict):
        return None
    if cap.get("enabled") is False:
        return None
    path = str(cap.get("path", "")).strip()
    if not path:
        return None
    markers = cap.get("markers") or cap.get("required_markers") or []
    return {
        "path": path,
        "markers": [str(m) for m in markers] if isinstance(markers, list) else [],
        "required_status": int(cap.get("required_status", 400)),
    }


def gate_settings(profile: dict[str, Any]) -> dict[str, Any] | None:
    stealth = profile.get("stealth")
    if isinstance(stealth, dict) and isinstance(stealth.get("gate"), dict):
        gate = stealth["gate"]
    else:
        block = profile.get("profile")
        if isinstance(block, dict) and isinstance(block.get("stealth"), dict):
            gate = block["stealth"].get("gate")
        else:
            gate = None
    if not isinstance(gate, dict):
        return None
    query = str(gate.get("query_param", "")).strip()
    cookie = str(gate.get("cookie_name", "")).strip()
    if not query or not cookie:
        return None
    secret_env = gate.get("secret_env") or []
    secret_files = gate.get("secret_repo_files") or gate.get("secret_repo_paths") or []
    secret_key = str(gate.get("secret_key", "RYNIX_STEALTH_GATE_SECRET")).strip()
    transport = str(gate.get("transport", "header")).strip().lower()
    header_name = str(gate.get("header_name", "X-Gate-Secret")).strip()
    return {
        "query_param": query,
        "cookie_name": cookie,
        "transport": transport,
        "header_name": header_name,
        "secret_env": [str(x) for x in secret_env] if isinstance(secret_env, list) else [],
        "secret_repo_files": [str(x) for x in secret_files]
        if isinstance(secret_files, list)
        else [],
        "secret_key": secret_key or "RYNIX_STEALTH_GATE_SECRET",
    }


def load_gate_secret_from_profile(
    profile: dict[str, Any],
    repo_path: Path | str | None = None,
) -> str:
    gate = gate_settings(profile)
    if not gate:
        return ""
    for env_name in gate["secret_env"]:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    repo = Path(repo_path).resolve() if repo_path else None
    if repo and repo.is_dir():
        for rel in gate["secret_repo_files"]:
            rel_path = str(rel).lstrip("/\\")
            path = (repo / rel_path).resolve()
            try:
                path.relative_to(repo)
            except ValueError:
                continue
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                prefix = f"{gate['secret_key']}="
                if stripped.startswith(prefix):
                    value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    if value:
                        return value
    return ""
