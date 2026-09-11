#!/usr/bin/env python3
"""Phase I — enrich techniques and stub framework guides with Rynix sections."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"
TECHNIQUES = KNOWLEDGE / "techniques"
FRAMEWORKS = KNOWLEDGE / "frameworks"
WSTG = KNOWLEDGE / "wstg"

TOOL_MAP: dict[str, list[str]] = {
    "access-control": ["run_idor_matrix", "compare_role_response", "rbac_matrix", "check_access"],
    "api-testing": ["list_api_routes", "export_openapi_stub", "http_probe"],
    "authentication": ["auth_login", "compare_role_response", "http_probe"],
    "business-logic": ["http_probe", "compare_role_response", "record_finding"],
    "clickjacking": ["http_probe", "list_frontend_routes"],
    "cors": ["http_probe", "compare_role_response"],
    "cross-site-scripting": ["http_probe", "browser-debug plugin"],
    "csrf": ["http_probe", "compare_role_response"],
    "dom-based": ["list_frontend_routes", "browser-debug plugin"],
    "essential-skills": ["http_probe", "analyze_repo", "get_technique_guide"],
    "file-upload": ["http_probe", "record_finding"],
    "graphql": ["analyze_repo", "http_probe", "export_openapi_stub"],
    "host-header": ["http_probe", "compare_role_response"],
    "http-request-smuggling": ["http_probe"],
    "information-disclosure": ["http_probe", "analyze_repo"],
    "insecure-deserialization": ["http_probe", "record_finding"],
    "jwt": ["auth_login", "compare_role_response", "http_probe"],
    "nosql-injection": ["http_probe", "sql-injection-cli plugin"],
    "oauth": ["auth_login", "compare_role_response"],
    "os-command-injection": ["http_probe", "record_finding"],
    "path-traversal": ["http_probe", "record_finding"],
    "prototype-pollution": ["http_probe", "browser-debug plugin"],
    "race-conditions": ["http_probe", "compare_role_response"],
    "sql-injection": ["http_probe", "sql-injection-cli plugin"],
    "ssrf": ["http_probe", "record_finding"],
    "ssti": ["http_probe", "record_finding"],
    "web-cache-deception": ["http_probe", "compare_role_response"],
    "web-cache-poisoning": ["http_probe", "compare_role_response"],
    "web-llm-attacks": ["http_probe", "record_finding"],
    "websockets": ["http_probe", "list_api_routes"],
    "xxe": ["http_probe", "record_finding"],
}

FRAMEWORK_SECTIONS = """\
## Attack surface

- Route handlers, middleware, and global error handlers
- Auth/session plugins and dependency injection
- Static assets, uploads, and admin mounts
- Background jobs and websocket channels

## High-value targets

- Admin and internal APIs not in public docs
- Object IDs in paths (`/users/:id`, `/orders/{{id}}`)
- File import/export and report endpoints
- Health/debug/metrics routes in production

## Key vulnerabilities

- Missing per-route authorization (IDOR, privilege escalation)
- Mass assignment / extra JSON fields changing ownership
- CORS and CSRF gaps on cookie or token auth
- SSRF in webhook, preview, or import URLs
- Template injection in server-side rendering

## Rynix workflow

1. `analyze_repo` with stack hint `__STACK__` — map routes and auth decorators.
2. `rbac_matrix` + `high_risk_surfaces` for IDOR candidates.
3. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
4. `record_finding` only after verified cross-role or cross-tenant diff.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
"""


def _slug(path: Path) -> str:
    return path.stem


def technique_block(slug: str) -> str:
    tools = TOOL_MAP.get(slug, ["http_probe", "record_finding"])
    tools_inline = ", ".join(f"`{t}`" for t in tools)
    tools_list = "\n".join(f"- `{t}`" for t in tools)
    return f"""
## Rynix workflow

1. `get_technique_guide` for `{slug}` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: {tools_inline}.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

{tools_list}

## Evidence requirements

- Reproducible request/response or role-comparison diff.
- Session ID on all live tool calls.
- Link findings to endpoint + parameter, not generic claims.

## ASVS mapping

- V4 Access Control — role-appropriate responses for protected resources.
- V5 Validation — input handling for injection and parser differentials.

## CWE references

- CWE-284: Improper Access Control
- CWE-20: Improper Input Validation
"""


def enrich_techniques() -> int:
    updated = 0
    for path in TECHNIQUES.glob("*.md"):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        if "## Rynix workflow" in text:
            continue
        slug = _slug(path)
        path.write_text(text.rstrip() + technique_block(slug) + "\n", encoding="utf-8")
        updated += 1
    return updated


def enrich_frameworks(min_lines: int = 40) -> int:
    updated = 0
    for path in FRAMEWORKS.glob("*.md"):
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) >= min_lines:
            continue
        stack = _slug(path)
        title = stack.replace("-", " ").title()
        body = (
            f"---\nname: {stack}\n"
            f"description: Security testing playbook for {title} applications\n---\n\n"
            f"# {title}\n\n"
            f"Security testing notes for {title}. Use static analysis plus live probes; "
            f"do not rely on framework defaults for authorization.\n\n"
        )
        body += FRAMEWORK_SECTIONS.replace("__STACK__", stack)
        path.write_text(body + "\n", encoding="utf-8")
        updated += 1
    return updated


def enrich_wstg_evidence() -> int:
    updated = 0
    block = """
## Evidence requirements

- Request/response snippet or `compare_role_response` diff.
- Session ID on all tool calls.
- No unverified claims in `export_report`.
"""
    for path in WSTG.rglob("WSTG-*.md"):
        text = path.read_text(encoding="utf-8")
        if "## Evidence requirements" in text:
            continue
        if "## Rynix workflow" not in text:
            continue
        text = text.rstrip() + block + "\n"
        path.write_text(text, encoding="utf-8")
        updated += 1
    return updated


def enrich_technique_tooling() -> int:
    updated = 0
    for path in TECHNIQUES.glob("*.md"):
        if path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        if "## Rynix tooling" in text:
            continue
        if "## Rynix workflow" not in text:
            continue
        slug = _slug(path)
        tools = TOOL_MAP.get(slug, ["http_probe", "record_finding"])
        block = "## Rynix tooling\n\n" + "\n".join(f"- `{t}`" for t in tools) + "\n"
        text = text.replace("## Evidence requirements", block + "\n## Evidence requirements", 1)
        path.write_text(text, encoding="utf-8")
        updated += 1
    return updated


def main() -> int:
    t = enrich_techniques()
    tooling = enrich_technique_tooling()
    f = enrich_frameworks()
    w = enrich_wstg_evidence()
    print(f"enriched techniques={t} tooling={tooling} frameworks={f} wstg_evidence={w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
