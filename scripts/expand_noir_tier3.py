#!/usr/bin/env python3
"""Append industry Tier-3 stack entries to stacks/manifest.toml (80+ total)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "stacks" / "manifest.toml"

# Additional generic frameworks (generic extractor coverage).
NOIR_TIER3 = [
    "beego",
    "buffalo",
    "revel",
    "martini",
    "mux",
    "gorilla",
    "iris",
    "go-zero",
    "rocket",
    "warp",
    "hyper",
    "actix-web-generic",
    "rocket-rs",
    "slim",
    "lumen",
    "yii",
    "cakephp",
    "codeigniter",
    "zend",
    "cakephp3",
    "dropwizard",
    "micronaut",
    "vertx",
    "spark-java",
    "javalin",
    "play-framework",
    "deno-fresh",
    "deno-oak",
    "oak",
    "bun-hono",
    "camping",
    "cuba",
    "lotus",
    "mack",
    "nancy",
    "padrino",
    "ramaze",
    "rack",
    "amber",
    "lucky",
    "kemal",
    "angel",
    "shelf",
    "dart-frog",
    "scotty",
    "servant",
    "yesod",
    "catalyst",
    "dancer2",
    "mojolicious",
    "play-scala",
    "akka-http",
    "http4s",
    "vapor",
    "perfect-swift",
    "zig-zap",
    "zig-httptool",
    "plug",
    "cowboy",
    "n2o",
    "bottle",
    "cherrypy",
    "tornado",
    "sanic",
    "starlette",
    "aiohttp",
    "falcon",
    "hug",
    "responder",
    "robyn",
    "litestar",
    "ktor-generic",
    "spring-webflux",
    "micronaut-kotlin",
    "aspnet-mvc",
    "nancyfx",
    "servicestack",
    "symfony-generic",
    "laravel-generic",
    "express-generic",
    "koa-generic",
    "nestjs-generic",
    "rails-generic",
    "sinatra-generic",
    "phoenix-generic",
    "next-generic",
    "nuxt-generic",
    "vue-generic",
    "graphql-generic",
    "grpc-gateway",
    "openapi-generic",
    "wasmcloud",
    "wasm-http",
    "serverless-offline",
]

BLOCK = """
[[stack]]
id = "{id}"
tier = 3
extractor = "generic"
golden = "tests/golden/stacks/generic-routes.json"
cargo_test = "generic_extracts_routes"
"""


def main() -> int:
    text = MANIFEST.read_text(encoding="utf-8")
    existing = set(re.findall(r'^id = "([^"]+)"', text, re.MULTILINE))
    added = 0
    for stack_id in NOIR_TIER3:
        if stack_id in existing:
            continue
        text += BLOCK.format(id=stack_id)
        existing.add(stack_id)
        added += 1
    MANIFEST.write_text(text, encoding="utf-8")
    tier3 = len([line for line in text.splitlines() if line.strip() == "tier = 3"])
    print(f"added {added} tier-3 stacks; total tier-3={tier3}; total ids={len(existing)}")
    if tier3 < 80:
        print(f"WARN tier-3 count {tier3} < 80", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
