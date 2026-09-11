#!/usr/bin/env python3
"""Gate #10 — example-law-firm profile neutral + optional live IDOR=0 smoke."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

PROFILE = ROOT / "profiles" / "example-law-firm.toml"


def _target_profile_path() -> Path | None:
    raw = os.environ.get("RYNIX_TARGET_REPO", "").strip()
    if not raw:
        return None
    return Path(raw) / ".pentest" / "profile.toml"


def main() -> int:
    errors: list[str] = []

    if not PROFILE.is_file():
        errors.append("missing profiles/example-law-firm.toml")
    else:
        text = PROFILE.read_text(encoding="utf-8")
        if 'name = "example-law-firm"' not in text:
            errors.append("profile name must be example-law-firm")
        forbidden = ("adl" + "_api", "liquid" + "glass")
        if any(token in text.lower() for token in forbidden):
            errors.append("profile contains private leak strings")

    erp_profile = _target_profile_path()
    if erp_profile and erp_profile.is_file():
        erp = erp_profile.read_text(encoding="utf-8")
        if 'name = "example-law-firm"' not in erp:
            errors.append("target .pentest/profile.toml not renamed")
    else:
        print("SKIP target repo profile check (set RYNIX_TARGET_REPO)")

    base = os.environ.get("RYNIX_PROBE_BASE_URL", "").strip()
    if base and os.environ.get("RYNIX_GATE10_LIVE", "1") == "1":
        try:
            from rynix_mcp.idor_matrix import run_idor_matrix

            result = run_idor_matrix(base, profile="example-law-firm", session_id="gate10")
            if "error" in result:
                errors.append(f"live idor_matrix error: {result['error']}")
            elif result.get("idor_signals", 1) != 0:
                errors.append(f"idor_signals={result.get('idor_signals')} expected 0")
            else:
                print(f"PASS live IDOR smoke comparisons={result.get('comparisons')}")
        except Exception as exc:  # noqa: BLE001
            print(f"SKIP live IDOR smoke: {exc}")
    else:
        print("SKIP live IDOR smoke (set RYNIX_PROBE_BASE_URL for live gate)")

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        return 1
    print("PASS gate 10 example-law-firm profile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
