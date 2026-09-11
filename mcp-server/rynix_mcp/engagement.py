"""Rynix engagement YAML validation (scope guard patterns, no subprocess)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REQUIRED_TOP = ("name", "target", "scope")
REQUIRED_TARGET = ("base_url",)
REQUIRED_SCOPE = ("allow",)


def validate_engagement_yaml(engagement_path: str) -> dict[str, Any]:
    path = Path(engagement_path)
    if not path.is_file():
        return {
            "error": {
                "code": "NOT_FOUND",
                "message": f"Engagement file not found: {engagement_path}",
                "retryable": False,
            }
        }

    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return {
            "valid": False,
            "error": {"code": "ENCODING_ERROR", "message": str(exc), "retryable": False},
            "issues": [f"engagement file is not valid UTF-8: {exc}"],
            "source": str(path),
        }
    except OSError as exc:
        return {
            "valid": False,
            "error": {"code": "READ_FAILED", "message": str(exc), "retryable": True},
            "issues": [f"cannot read engagement file: {exc}"],
            "source": str(path),
        }

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return {
            "valid": False,
            "error": {"code": "YAML_PARSE", "message": str(exc), "retryable": False},
            "issues": [str(exc)],
            "source": str(path),
        }

    if not isinstance(data, dict):
        return {
            "error": {
                "code": "INVALID_SHAPE",
                "message": "Engagement root must be a mapping",
                "retryable": False,
            }
        }

    issues: list[str] = []
    for key in REQUIRED_TOP:
        if key not in data:
            issues.append(f"missing required key: {key}")

    target = data.get("target", {})
    if isinstance(target, dict):
        for key in REQUIRED_TARGET:
            if key not in target:
                issues.append(f"target.{key} required")
    else:
        issues.append("target must be a mapping")

    scope = data.get("scope", {})
    if isinstance(scope, dict):
        allow = scope.get("allow", {})
        if not isinstance(allow, dict):
            issues.append("scope.allow must be a mapping")
        elif not allow.get("hosts"):
            issues.append("scope.allow.hosts must list at least one host")
    else:
        issues.append("scope must be a mapping")

    deny_paths = []
    if isinstance(scope, dict):
        deny = scope.get("deny", {})
        if isinstance(deny, dict):
            deny_paths = deny.get("paths", []) or []

    base_url = ""
    if isinstance(target, dict):
        base_url = str(target.get("base_url", ""))

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "name": data.get("name"),
        "base_url": base_url,
        "allowed_hosts": (scope.get("allow", {}) or {}).get("hosts", [])
        if isinstance(scope, dict)
        else [],
        "deny_paths": deny_paths,
        "scopes_to_run": data.get("scopes_to_run", []),
        "source": str(path),
    }
