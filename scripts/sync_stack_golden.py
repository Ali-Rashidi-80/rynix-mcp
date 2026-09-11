#!/usr/bin/env python3
"""Sync stack golden JSON files with minimal realistic route fixtures."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "stacks"

FIXTURES: dict[str, list[dict[str, str]]] = {
    "fastapi": [
        {"method": "GET", "path": "/items/{item_id}"},
        {"method": "POST", "path": "/finance/case-fee-receipts/{event_id}/purge"},
    ],
    "django": [{"method": "GET", "path": "users/"}, {"method": "GET", "path": "users/<int:pk>/"}],
    "flask": [{"method": "GET", "path": "/api/users"}, {"method": "POST", "path": "/api/login"}],
    "express": [
        {"method": "GET", "path": "/api/health"},
        {"method": "POST", "path": "/api/users/:id"},
    ],
    "nestjs": [{"method": "GET", "path": ":id"}, {"method": "POST", "path": "/"}],
    "fastify": [{"method": "GET", "path": "/health"}, {"method": "POST", "path": "/users"}],
    "gin": [{"method": "GET", "path": "/api/health"}, {"method": "POST", "path": "/api/users/:id"}],
    "spring": [{"method": "GET", "path": "/api/users"}, {"method": "POST", "path": "/api/admin"}],
    "aspnet": [
        {"method": "GET", "path": "/api/values"},
        {"method": "POST", "path": "/api/values/{id}"},
    ],
    "laravel": [{"method": "GET", "path": "/api/users"}, {"method": "POST", "path": "/api/login"}],
    "rails": [{"method": "GET", "path": "/users"}, {"method": "POST", "path": "/users/:id"}],
    "react": [{"method": "GET", "path": "/dashboard"}, {"method": "GET", "path": "/cases"}],
    "nextjs": [{"method": "GET", "path": "/dashboard"}, {"method": "GET", "path": "/api/users"}],
    "vue": [{"method": "GET", "path": "/home"}, {"method": "GET", "path": "/settings"}],
    "nuxt": [{"method": "GET", "path": "/"}, {"method": "GET", "path": "/users"}],
    "angular": [{"method": "GET", "path": "/admin"}, {"method": "GET", "path": "/reports"}],
    "sveltekit": [{"method": "GET", "path": "/dashboard"}, {"method": "GET", "path": "/account"}],
    "graphql": [
        {"method": "POST", "path": "/graphql"},
        {"method": "POST", "path": "/graphql#users"},
    ],
    "trpc": [{"method": "POST", "path": "/trpc/users.query"}],
    "openapi": [
        {"method": "GET", "path": "/api/v1/users"},
        {"method": "POST", "path": "/api/v1/items"},
    ],
    "echo": [
        {"method": "GET", "path": "/api/health"},
        {"method": "POST", "path": "/api/users/:id"},
    ],
    "fiber": [{"method": "GET", "path": "/api/health"}, {"method": "POST", "path": "/api/items"}],
    "chi": [{"method": "GET", "path": "/api/health"}],
    "axum": [{"method": "GET", "path": "/api/health"}],
    "actix": [{"method": "GET", "path": "/api/health"}],
    "koa": [{"method": "GET", "path": "/api/health"}],
    "hono": [{"method": "GET", "path": "/api/health"}],
    "adonisjs": [{"method": "GET", "path": "/api/users"}],
    "symfony": [{"method": "GET", "path": "/api/users"}],
    "quarkus": [{"method": "GET", "path": "/api/users"}],
    "ktor": [{"method": "GET", "path": "/api/users"}],
    "sinatra": [{"method": "GET", "path": "/users"}],
    "phoenix": [{"method": "GET", "path": "/api/users"}],
    "generic": [{"method": "GET", "path": "/api/health"}],
}


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for stack_id, routes in FIXTURES.items():
        path = GOLDEN / f"{stack_id}-routes.json"
        payload = {"stack": stack_id, "routes": routes}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.name} ({len(routes)} routes)")


if __name__ == "__main__":
    main()
