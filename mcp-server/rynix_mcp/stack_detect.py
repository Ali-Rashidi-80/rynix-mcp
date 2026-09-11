"""Detect application stack from repository manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def detect_stack(repo_path: str | Path) -> list[dict[str, Any]]:
    repo = Path(repo_path).resolve()
    detected: list[dict[str, Any]] = []

    pkg = repo / "package.json"
    if pkg.is_file():
        data = _read_json(pkg) or {}
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if "next" in deps:
            detected.append(
                {"name": "nextjs", "confidence": "high", "signals": ["package.json:next"]}
            )
        elif "react" in deps:
            detected.append(
                {"name": "react", "confidence": "high", "signals": ["package.json:react"]}
            )
        if "@nestjs/core" in deps:
            detected.append(
                {"name": "nestjs", "confidence": "high", "signals": ["package.json:@nestjs/core"]}
            )
        if "express" in deps:
            detected.append(
                {"name": "express", "confidence": "high", "signals": ["package.json:express"]}
            )
        if "fastify" in deps:
            detected.append(
                {"name": "fastify", "confidence": "high", "signals": ["package.json:fastify"]}
            )
        if "vue" in deps:
            detected.append(
                {"name": "vue", "confidence": "medium", "signals": ["package.json:vue"]}
            )
        if "nuxt" in deps or "nuxt3" in deps:
            detected.append(
                {"name": "nuxt", "confidence": "high", "signals": ["package.json:nuxt"]}
            )
        if "@angular/core" in deps:
            detected.append(
                {"name": "angular", "confidence": "high", "signals": ["package.json:@angular/core"]}
            )
        if "@sveltejs/kit" in deps:
            detected.append(
                {
                    "name": "sveltekit",
                    "confidence": "high",
                    "signals": ["package.json:@sveltejs/kit"],
                }
            )

    if (repo / "go.mod").is_file():
        text = (repo / "go.mod").read_text(encoding="utf-8", errors="ignore")
        if "gin-gonic/gin" in text:
            detected.append({"name": "gin", "confidence": "high", "signals": ["go.mod:gin"]})
        elif "labstack/echo" in text:
            detected.append({"name": "echo", "confidence": "high", "signals": ["go.mod:echo"]})
        elif "gofiber/fiber" in text:
            detected.append({"name": "fiber", "confidence": "high", "signals": ["go.mod:fiber"]})
        elif "go-chi/chi" in text:
            detected.append({"name": "chi", "confidence": "high", "signals": ["go.mod:chi"]})

    if (repo / "pyproject.toml").is_file() or (repo / "requirements.txt").is_file():
        py_text = ""
        if (repo / "pyproject.toml").is_file():
            py_text += (repo / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
        if (repo / "requirements.txt").is_file():
            py_text += (repo / "requirements.txt").read_text(encoding="utf-8", errors="ignore")
        if "fastapi" in py_text.lower():
            detected.append(
                {"name": "fastapi", "confidence": "high", "signals": ["python:fastapi"]}
            )
        if "django" in py_text.lower():
            detected.append({"name": "django", "confidence": "high", "signals": ["python:django"]})
        if "flask" in py_text.lower():
            detected.append({"name": "flask", "confidence": "medium", "signals": ["python:flask"]})

    if (repo / "composer.json").is_file():
        data = _read_json(repo / "composer.json") or {}
        req = data.get("require", {})
        if "laravel/framework" in req:
            detected.append(
                {"name": "laravel", "confidence": "high", "signals": ["composer.json:laravel"]}
            )
        if "symfony/framework-bundle" in req:
            detected.append(
                {"name": "symfony", "confidence": "high", "signals": ["composer.json:symfony"]}
            )

    if (repo / "Gemfile").is_file():
        text = (repo / "Gemfile").read_text(encoding="utf-8", errors="ignore")
        if "rails" in text:
            detected.append({"name": "rails", "confidence": "high", "signals": ["Gemfile:rails"]})
        if "sinatra" in text:
            detected.append(
                {"name": "sinatra", "confidence": "medium", "signals": ["Gemfile:sinatra"]}
            )

    if (repo / "pom.xml").is_file() or list(repo.glob("**/build.gradle*")):
        detected.append(
            {"name": "spring", "confidence": "medium", "signals": ["jvm:spring-or-gradle"]}
        )

    if list(repo.glob("**/*.csproj")):
        detected.append({"name": "aspnet", "confidence": "medium", "signals": ["csproj"]})

    if (repo / "Cargo.toml").is_file():
        text = (repo / "Cargo.toml").read_text(encoding="utf-8", errors="ignore")
        if "axum" in text:
            detected.append({"name": "axum", "confidence": "high", "signals": ["Cargo.toml:axum"]})
        if "actix-web" in text:
            detected.append(
                {"name": "actix", "confidence": "high", "signals": ["Cargo.toml:actix"]}
            )

    if not detected:
        detected.append({"name": "generic", "confidence": "low", "signals": ["no_manifest_match"]})

    return detected
