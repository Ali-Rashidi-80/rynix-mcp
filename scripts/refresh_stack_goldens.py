#!/usr/bin/env python3
"""Refresh stack golden JSON from canonical route expectations."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "stacks"

FIXTURES: dict[str, dict] = {
    "express-routes.json": {
        "stack": "express",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/:id"},
        ],
    },
    "gin-routes.json": {
        "stack": "gin",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/:id"},
        ],
    },
    "echo-routes.json": {
        "stack": "echo",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/items/:id"},
        ],
    },
    "fiber-routes.json": {
        "stack": "fiber",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/:id"},
        ],
    },
    "chi-routes.json": {
        "stack": "chi",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "PUT", "path": "/api/items/{id}"},
        ],
    },
    "axum-routes.json": {
        "stack": "axum",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/{id}"},
        ],
    },
    "actix-routes.json": {
        "stack": "actix",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/{id}"},
        ],
    },
    "koa-routes.json": {
        "stack": "koa",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/:id"},
        ],
    },
    "hono-routes.json": {
        "stack": "hono",
        "routes": [
            {"method": "GET", "path": "/api/health"},
            {"method": "POST", "path": "/api/users/:id"},
        ],
    },
    "react-routes.json": {
        "stack": "react",
        "frontend_routes": [
            {"path": "/dashboard", "file": "src/App.tsx"},
            {"path": "/cases", "file": "src/App.tsx"},
        ],
    },
    "nextjs-routes.json": {
        "stack": "nextjs",
        "frontend_routes": [{"path": "/dashboard", "file": "app/dashboard/page.tsx"}],
    },
    "generic-routes.json": {
        "stack": "generic",
        "routes": [{"method": "GET", "path": "/api/health"}],
        "warnings": ["generic_extractor_used"],
    },
}


def main() -> int:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for name, payload in FIXTURES.items():
        path = GOLDEN / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
