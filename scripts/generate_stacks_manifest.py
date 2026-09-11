#!/usr/bin/env python3
"""Generate stacks/manifest.toml with Tier 1+2+3 framework entries."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACKS = ROOT / "stacks" / "manifest.toml"
PROFILES = ROOT / "profiles"

TIER1 = [
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
    "react",
    "nextjs",
    "vue",
    "nuxt",
    "angular",
    "sveltekit",
    "graphql",
    "trpc",
    "openapi",
]
TIER2 = [
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
]
TIER3 = [
    "crystal",
    "dart",
    "haskell",
    "perl",
    "scala",
    "swift",
    "zig",
    "elixir-generic",
    "php-generic",
    "ruby-generic",
    "python-generic",
    "node-generic",
    "go-generic",
    "rust-generic",
    "java-generic",
    "csharp-generic",
    "kotlin-generic",
    "cpp-generic",
    # multi-stack parity — language/framework generics (Tier 3)
    "amber",
    "lucky",
    "aqueduct",
    "shelf",
    "angel",
    "plug",
    "grape",
    "padrino",
    "micronaut",
    "dropwizard",
    "spark-java",
    "play-framework",
    "yesod",
    "scotty",
    "servant",
    "slim",
    "codeigniter",
    "cakephp",
    "yii",
    "tornado",
    "pyramid",
    "bottle",
    "starlette",
    "rocket",
    "warp",
    "actix-generic",
    "akka-http",
    "play-scala",
    "vapor",
    "perfect",
    "catalyst",
    "mojolicious",
    "dancer",
    "crow",
    "pistache",
    "drogon",
    "jester",
    "lapis",
    "plumber",
    "compojure",
    "reitit",
    "pedestal",
    "luminus",
    "nitrogen",
    "n2o",
    "beego",
    "buffalo",
    "iris",
    "martini",
    "revel",
    "sanic",
    "cherrypy",
    "web2py",
    "feathers",
    "loopback",
    "meteor",
    "sails",
    "strapi",
    "keystone",
    "redwood",
    "blazor",
    "minimal-api",
    "nancy",
    "servicestack",
    "cowboy",
    "nerves",
    "opencart",
    "magento",
    "drupal",
    "wordpress-api",
    "joomla",
    "typo3",
    "openapi-generic",
    "grpc-generic",
    "soap-generic",
    "websocket-generic",
]


def profile_template(stack_id: str) -> str:
    return f'''name = "{stack_id}"
display_name = "Rynix Profile: {stack_id}"
stack = ["{stack_id}"]

[paths]
api_endpoints = "backend/app/api"
frontend_src = "src"

[scope]
allow_hosts = ["localhost", "127.0.0.1"]

[auth]
login_path = "/api/auth/login"
auth_markers = ["authenticate", "authorize", "auth"]

[brief]
concerns = ["IDOR", "auth bypass", "injection"]
focus = ["API routes", "role matrix"]
context = ["Auto-generated Tier-1 stack profile for {stack_id}"]

[risk]
object_paths_pattern = "/{{id}}"
discovery_roles = ["user", "admin"]

[[risk.idor_role_pairs]]
low = "user"
high = "admin"
'''


def main() -> None:
    lines = ["# Multi-stack manifest — multi-stack parity coverage", ""]
    for stack_id in TIER1:
        lines += [
            "[[stack]]",
            f'id = "{stack_id}"',
            "tier = 1",
            'extractor = "dedicated"',
            f'golden = "tests/golden/stacks/{stack_id}-routes.json"',
            f'cargo_test = "{stack_id}_extracts_routes"',
            f'knowledge = "knowledge/frameworks/{stack_id}.md"',
            f'profile = "profiles/{stack_id}.toml"',
            "",
        ]
        prof = PROFILES / f"{stack_id}.toml"
        if not prof.is_file() and stack_id not in ("example-law-firm", "generic-fastapi-react"):
            prof.write_text(profile_template(stack_id), encoding="utf-8")

    for stack_id in TIER2:
        lines += [
            "[[stack]]",
            f'id = "{stack_id}"',
            "tier = 2",
            'extractor = "dedicated"',
            f'golden = "tests/golden/stacks/{stack_id}-routes.json"',
            f'cargo_test = "{stack_id}_extracts_routes"',
            f'knowledge = "knowledge/frameworks/{stack_id}.md"',
            f'profile = "profiles/{stack_id}.toml"',
            "",
        ]
        prof = PROFILES / f"{stack_id}.toml"
        if not prof.is_file():
            prof.write_text(profile_template(stack_id), encoding="utf-8")

    for stack_id in TIER3:
        lines += [
            "[[stack]]",
            f'id = "{stack_id}"',
            "tier = 3",
            'extractor = "generic"',
            'golden = "tests/golden/stacks/generic-routes.json"',
            'cargo_test = "generic_extracts_routes"',
            "",
        ]

    STACKS.parent.mkdir(parents=True, exist_ok=True)
    STACKS.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {STACKS} with {len(TIER1) + len(TIER2) + len(TIER3)} stacks")


if __name__ == "__main__":
    main()
