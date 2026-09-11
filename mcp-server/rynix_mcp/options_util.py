"""Parse plugin/MCP options from JSON string or dict."""

from __future__ import annotations

import json
from typing import Any


def parse_options(options: str | dict[str, Any] | None) -> dict[str, Any]:
    if options is None:
        return {}
    if isinstance(options, dict):
        return dict(options)
    text = str(options).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except json.JSONDecodeError:
        return {"raw": text}
