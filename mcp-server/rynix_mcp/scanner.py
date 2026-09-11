from __future__ import annotations

import fnmatch
import ipaddress
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rynix_mcp.config import PROFILES_DIR, resolve_scanner_bin
from rynix_mcp.profiles import load_profile
from rynix_mcp.scan_config import scan_config_from_profile

_SCAN_CACHE: dict[tuple[str, str | None], tuple[float, dict[str, Any]]] = {}

SCAN_CACHE_TTL_SEC = 60.0


def validate_repo_path(repo_path: str) -> Path:

    path = Path(repo_path).resolve()

    if not path.is_dir():
        raise ValueError(f"repo_path not found: {path}")

    return path


def run_scan(repo_path: Path, profile: str | None = None) -> dict[str, Any]:

    cache_key = (str(repo_path), profile)

    now = time.monotonic()

    cached = _SCAN_CACHE.get(cache_key)

    if cached is not None:
        ts, payload = cached

        if now - ts < SCAN_CACHE_TTL_SEC:
            return payload

    bin_path = resolve_scanner_bin()

    if not bin_path.is_file():
        raise RuntimeError(f"rynix-scan binary not found at {bin_path}")

    prof = load_profile(profile, PROFILES_DIR, repo_path)

    config = scan_config_from_profile(prof)

    cmd = [
        str(bin_path),
        "analyze",
        "--repo",
        str(repo_path),
        "--format",
        "json",
    ]

    if profile:
        cmd.extend(["--profile", profile])

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(config, tmp)

        config_path = tmp.name

    cmd.extend(["--config", config_path])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("rynix-scan timed out after 300s") from None

    finally:
        Path(config_path).unlink(missing_ok=True)

    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "rynix-scan failed")

    stdout = (proc.stdout or "").strip()

    if not stdout:
        raise RuntimeError("rynix-scan returned empty output")

    try:
        result = json.loads(stdout)

    except json.JSONDecodeError as exc:
        raise RuntimeError(f"rynix-scan returned invalid JSON: {exc}") from exc

    from rynix_mcp.stack_detect import detect_stack

    result["detected_stack"] = detect_stack(repo_path)

    _SCAN_CACHE[cache_key] = (now, result)

    return result


def _normalize_scope_host(host: str) -> str:
    cleaned = host.lower().strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned


def scope_allowed(base_url: str, profile: dict[str, Any], env_allowlist: str) -> tuple[bool, str]:

    parsed = urlparse(base_url)

    if parsed.scheme not in ("http", "https"):
        return False, "invalid scheme"

    host = _normalize_scope_host(parsed.hostname or "")

    if not host:
        return False, "missing host"

    allow_hosts: list[str] = []

    scope = profile.get("scope", {})

    if isinstance(scope, dict):
        allow_hosts.extend(scope.get("allow_hosts", []))

    if env_allowlist:
        allow_hosts.extend([h.strip() for h in env_allowlist.split(",") if h.strip()])

    deny_loopback = False
    if isinstance(scope, dict):
        deny_loopback = bool(scope.get("deny_loopback"))
    if not deny_loopback:
        allow_hosts.extend(["localhost", "127.0.0.1", "::1"])

    for pattern in allow_hosts:
        pattern = pattern.lower().strip()

        if pattern == "*":
            continue

        if pattern.startswith("*."):
            zone = pattern[2:]

            if host == zone or host.endswith("." + zone):
                return True, f"matched {pattern}"

        elif fnmatch.fnmatch(host, pattern) or host == _normalize_scope_host(pattern):
            return True, f"matched {pattern}"

    for cidr in scope.get("allow_cidrs", []) if isinstance(scope, dict) else []:
        try:
            net = ipaddress.ip_network(cidr, strict=False)

            if ipaddress.ip_address(host) in net:
                return True, f"matched cidr {cidr}"

        except ValueError:
            return False, f"invalid cidr {cidr!r} in profile — fail-closed"

    return False, f"host {host} not in allowlist"


def profile_auth(profile: dict[str, Any]) -> dict[str, Any]:

    auth = profile.get("auth", {})

    if not isinstance(auth, dict):
        auth = {}

    return {
        "login_path": auth.get("login_path", "/api/v1/auth/login"),
        "content_type": auth.get("content_type", "application/x-www-form-urlencoded"),
        "username_field": auth.get("username_field", "username"),
        "password_field": auth.get("password_field", "password"),
        "token_field": auth.get("token_field", "access_token"),
    }
