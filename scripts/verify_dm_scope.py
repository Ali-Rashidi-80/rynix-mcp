#!/usr/bin/env python3
"""Phase D-M — verify deferred scope documented and Tier-1 frontends present."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFERRED = ROOT / "docs" / "DM_SCOPE_DEFERRED.md"
FRONTEND = ROOT / "rynix-core" / "src" / "frontend"
TIER1_FRONT = {"react.rs", "nextjs.rs", "vue.rs", "nuxt.rs", "angular.rs", "sveltekit.rs"}


def main() -> int:
    errors: list[str] = []
    if not DEFERRED.is_file():
        errors.append("missing docs/DM_SCOPE_DEFERRED.md")
    else:
        text = DEFERRED.read_text(encoding="utf-8")
        if "Flutter" not in text or "deferred" not in text.lower():
            errors.append("DM_SCOPE_DEFERRED.md must document Flutter deferral")

    if (ROOT / "rynix-core" / "src" / "frontend" / "flutter.rs").is_file():
        errors.append("flutter.rs should not exist in v1 (deferred)")

    for name in TIER1_FRONT:
        if not (FRONTEND / name).is_file():
            errors.append(f"missing frontend/{name}")

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        return 1
    print("PASS D-M scope (Flutter deferred, Tier-1 frontends OK)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
