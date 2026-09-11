#!/usr/bin/env python3
"""Gate #12 — multi-stack manifest coverage with real extractor files."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "stacks" / "manifest.toml"
CORE_ROUTES = ROOT / "rynix-core" / "src" / "routes"
CORE_FRONTEND = ROOT / "rynix-core" / "src" / "frontend"
CORE_API = ROOT / "rynix-core" / "src" / "api_styles"
PROFILES = ROOT / "profiles"

BACKEND_TIER1 = {
    "fastapi",
    "django",
    "flask",
    "express",
    "nestjs",
    "fastify",
    "gin",
    "spring",
    "aspnet",
    "laravel",
    "rails",
}
FRONTEND_TIER1 = {"react", "nextjs", "vue", "nuxt", "angular", "sveltekit"}
API_STYLES = {"graphql", "trpc", "openapi"}
TIER2 = {
    "echo",
    "fiber",
    "chi",
    "axum",
    "actix",
    "koa",
    "hono",
    "adonisjs",
    "symfony",
    "quarkus",
    "ktor",
    "sinatra",
    "phoenix",
}


def main() -> int:
    import tomllib

    if not MANIFEST.is_file():
        print(f"FAIL missing {MANIFEST}", file=sys.stderr)
        return 1

    data = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    stacks = data.get("stack", [])
    tier1 = [s for s in stacks if s.get("tier") == 1]
    tier2 = [s for s in stacks if s.get("tier") == 2]
    tier3 = [s for s in stacks if s.get("tier") == 3]

    errors: list[str] = []

    if len(tier1) < 20:
        errors.append(f"Tier1 count {len(tier1)} < 20")
    if len(tier2) < 12:
        errors.append(f"Tier2 count {len(tier2)} < 12")
    if len(tier3) < 80:
        errors.append(f"Tier3 count {len(tier3)} < 80 (multi-stack parity)")

    for stack_id in BACKEND_TIER1:
        path = CORE_ROUTES / f"{stack_id}.rs"
        if not path.is_file():
            errors.append(f"missing dedicated extractor routes/{stack_id}.rs")

    for stack_id in TIER2:
        path = CORE_ROUTES / f"{stack_id}.rs"
        if not path.is_file():
            errors.append(f"missing Tier2 extractor routes/{stack_id}.rs")

    for name in (
        "mod.rs",
        "react.rs",
        "nextjs.rs",
        "vue.rs",
        "nuxt.rs",
        "angular.rs",
        "sveltekit.rs",
    ):
        if not (CORE_FRONTEND / name).is_file():
            errors.append(f"missing frontend/{name}")

    for name in ("mod.rs", "graphql.rs", "trpc.rs", "openapi.rs"):
        if not (CORE_API / name).is_file():
            errors.append(f"missing api_styles/{name}")

    profile_count = len(list(PROFILES.glob("*.toml")))
    if profile_count < 20:
        errors.append(f"profiles count {profile_count} < 20")

    for s in tier1:
        if s.get("extractor") != "dedicated":
            errors.append(f"Tier1 {s['id']} must be dedicated")
        sid = s["id"]
        golden = ROOT / s.get("golden", "")
        if golden and not golden.is_file():
            errors.append(f"missing golden {golden}")
        if sid in BACKEND_TIER1 | FRONTEND_TIER1 | API_STYLES | TIER2:
            cargo_test = s.get("cargo_test", "")
            if not cargo_test:
                errors.append(f"Tier1 {sid} missing cargo_test")

    for s in tier2:
        if s.get("extractor") != "dedicated":
            errors.append(f"Tier2 {s['id']} must be dedicated")

    stub_goldens = 0
    for s in tier1 + tier2:
        golden = ROOT / s.get("golden", "")
        if golden.is_file():
            try:
                payload = json.loads(golden.read_text(encoding="utf-8"))
                routes = payload.get("routes", [])
                if len(routes) == 1 and routes[0].get("path") == "/api/health":
                    stub_goldens += 1
            except json.JSONDecodeError:
                errors.append(f"invalid golden json {golden}")

    if stub_goldens > len(tier1) + len(tier2):
        errors.append(f"too many stub goldens ({stub_goldens}) — refresh golden fixtures")

    proc = subprocess.run(
        ["cargo", "test", "-q", "--manifest-path", str(ROOT / "rynix-core" / "Cargo.toml")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    if proc.returncode != 0:
        errors.append(f"cargo test failed: {(proc.stderr or proc.stdout)[:400]}")

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        return 1

    print(f"Tier1: {len(tier1)}/{len(tier1)} dedicated — OK")
    print(f"Tier2: {len(tier2)}/{len(tier2)} dedicated — OK")
    print(f"Tier3: {len(tier3)}/{len(tier3)} listed — OK")
    print(f"multi-stack parity: {len(stacks)}/{len(stacks)} — OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
