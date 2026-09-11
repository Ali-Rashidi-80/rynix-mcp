"""Profile-driven math captcha helper for auth_login probes."""

from __future__ import annotations

import re
from typing import Any


def solve_math_prompt(prompt: str) -> str:
    """Solve prompts like '5 + 3 = ?' or Persian-digit variants."""
    normalized = prompt.replace("−", "-").replace("؟", "?")
    match = re.search(r"(\d+)\s*([+\-])\s*(\d+)", normalized)
    if not match:
        raise ValueError(f"cannot parse captcha prompt: {prompt!r}")
    left, op, right = int(match.group(1)), match.group(2), int(match.group(3))
    return str(left + right if op == "+" else left - right)


def response_needs_captcha(status_code: int, body: str, settings: dict[str, Any] | None) -> bool:
    if not settings:
        return False
    markers = settings.get("markers") or []
    required_status = int(settings.get("required_status", 400))
    return status_code == required_status and any(marker in body for marker in markers)


def fetch_captcha_fields(
    base_url: str,
    settings: dict[str, Any],
    session_id: str | None = None,
) -> dict[str, str]:
    from rynix_mcp.http_session import request as session_request

    path = str(settings["path"])
    resp = session_request(base_url, "GET", path, session_id=session_id)
    if resp.status_code >= 400:
        raise RuntimeError(f"captcha fetch failed: {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict):
        return {}
    if str(data.get("disabled", "")).lower() == "true" or not data.get("captcha_id"):
        return {}
    prompt = str(data.get("prompt_en") or data.get("prompt") or "")
    answer = solve_math_prompt(prompt)
    return {"captcha_id": str(data["captcha_id"]), "captcha_answer": answer}
