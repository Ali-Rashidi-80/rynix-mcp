#!/usr/bin/env python3
"""Append industrial deep-dive sections to Tier-1 generated framework guides."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORKS = ROOT / "mcp-server" / "rynix_mcp" / "knowledge" / "frameworks"
PRESERVE = {"django.md", "fastapi.md", "nestjs.md", "nextjs.md"}
MARKER = "## Industrial deep dive"
MIN_LINES = 120

DEEP: dict[str, str] = {
    "express": """
### Middleware ordering attacks
Map `app.use` registration order in `analyze_repo`. Routes attached to `app` before `passport.session()` may be reachable without session. Test nested routers mounted at `/api` vs `/api/v1` for inconsistent JWT middleware.

### NoSQL and prototype pollution
When Mongoose is present, probe `{"$gt":""}` and `__proto__` keys in JSON bodies. Express `extended` urlencoded parser may accept nested objects that bypass shallow validators.

### Production hardening checklist
- Disable `X-Powered-By`
- Ensure `trust proxy` matches deployment (Host/X-Forwarded-For)
- Rate-limit auth routes independently of public static assets
""",
    "flask": """
### Blueprint isolation
Each `Blueprint` can define `@bp.before_request`. Compare auth on `api_bp` vs `admin_bp` — interns sometimes get API access while admin HTML routes stay protected (false sense of safety).

### Session forgery
If `SECRET_KEY` is weak or committed, forge `session` cookie. Test `SESSION_COOKIE_SECURE` and `HTTPONLY` on HTTPS deployments.

### SSTI confirmation chain
`{{7*7}}` → config leak payloads → only on authorized staging. Document exact template file from `analyze_repo`.
""",
    "gin": """
### Group middleware gaps
`r.Group("/api")` with `authMiddleware` does not protect routes registered on root `r`. Grep for `r.GET` outside groups after static analysis.

### Binding differentials
Send duplicate JSON keys and wrong `Content-Type` to skip `ShouldBindJSON`. Test path param overflow on `{id}` segments.

### Concurrency on balances
Parallel POSTs to finance-like endpoints — pair with example law-firm application `compare_role_response` patterns.
""",
    "spring": """
### Actuator exposure
`/actuator/env`, `/actuator/heapdump` must return 404 in prod. If exposed, treat as critical — do not download heap to shared storage.

### `@PreAuthorize` drift
Controller-level annotation missing on new methods in large PRs. Diff OpenAPI vs code for orphan endpoints.

### SpEL and mass assignment
Over-posting to entities via JSON — fields like `isAdmin` not in DTO whitelist.
""",
    "laravel": """
### Policy vs gate
`Gate::allows` in controller but missing on Livewire/Filament parallel routes. Scan `routes/api.php` vs `routes/web.php`.

### Debug tools
`/_ignition`, `/telescope` must be disabled. `.env` `APP_DEBUG=false` on staging mirrors.

### Mass assignment
`$guarded = []` on User model — classic privilege escalation via registration.
""",
    "rails": """
### Strong parameters
`params.permit!` in legacy controllers. API-only mode skipping CSRF — ensure token auth still enforced.

### Sidekiq Web
Mount at `/sidekiq` without Devise — vertical escalation to job queue.

### IDOR scoping
`current_user.cases.find(params[:id])` vs `Case.find(params[:id])` — static grep both patterns.
""",
    "aspnet": """
### Minimal APIs
`.MapGet` without `.RequireAuthorization()` beside secured controllers — common in refactors.

### SignalR
Hub methods without `[Authorize]` while HTTP equivalent requires role.

### Deserialization legacy
`TypeNameHandling.All` in Newtonsoft configs — hunt in `appsettings*.json`.
""",
    "fastify": """
### Schema strictness
`additionalProperties: true` allows injecting `role` or `ownerId`. Fuzz nested objects in `schema.body`.

### Plugin encapsulation
Routes registered on parent instance bypass child plugin `preHandler` — verify encapsulation boundaries.

### Swagger in prod
`/documentation` exposes full attack map — gate with auth or disable.
""",
    "react": """
### Client-only guards
`PrivateRoute` does not protect API. Every hidden button must have `compare_role_response` proof on backing endpoint.

### Token storage
`localStorage` JWT + any XSS = account takeover. Prefer httpOnly cookie architecture review.

### Build-time secrets
`VITE_*` and `REACT_APP_*` leak in bundle — grep production JS for API keys.
""",
    "vue": """
### Router meta drift
Child routes missing `meta.requiresAuth` when parent has it. Test deep links `/settings/billing`.

### Pinia persistence
Serialized auth state in localStorage — tamper `role` field and replay API calls.

### SSR hydration
Nuxt overlap — see also `nuxt.md` for server route parity.
""",
    "nuxt": """
### server/api parity
`server/api/**/*.ts` often skips middleware used in `pages/`. Priority fuzz list.

### Payload leak
Inspect `__NUXT__` / `__NUXT_DATA__` in HTML for PII returned from `useFetch`.

### Nitro route rules
`routeRules` auth misconfiguration on hybrid static pages.
""",
    "angular": """
### Lazy module guards
`CanLoad` vs `CanActivate` — chunks may load before guard completes. Test direct chunk URLs.

### DomSanitizer bypass
`bypassSecurityTrustHtml` on user content — document sink file:line.

### Interceptor gaps
Requests bypassing `HttpInterceptor` via raw `fetch` in legacy code.
""",
    "sveltekit": """
### +server.ts exposure
API routes without `locals.user` check while `+page.server.ts` enforces session.

### Form actions CSRF
Double-submit and missing SameSite on session cookies.

### Prerender leaks
Dynamic routes accidentally prerendered with user-specific data.
""",
    "graphql": """
### Introspection
Disable in production. Batch privileged introspection query with user token in single HTTP request.

### Field-level auth
Parent resolver authorized but child field leaks cross-tenant data — test nested selections.

### DoS limits
Depth/complexity limits — safe bounded queries only.
""",
    "trpc": """
### Procedure leakage
`adminProcedure` accidentally merged into `publicRouter` export.

### Input Zod passthrough
`.passthrough()` on update schemas — inject ownership fields.

### Batching
Mix privileged and unprivileged procedures in one batch call.
""",
    "openapi": """
### Spec drift fuzz
Operations in spec vs 404/405 on live server — both directions.

### Security scheme gaps
`bearerAuth` in spec but not enforced on subset of paths.

### Undocumented admin paths
Fuzz from `analyze_repo` not present in OpenAPI.
""",
}


def main() -> int:
    updated = 0
    for name, body in DEEP.items():
        path = FRAMEWORKS / f"{name}.md"
        if not path.is_file() or name in {p.replace(".md", "") for p in PRESERVE}:
            continue
        text = path.read_text(encoding="utf-8")
        if MARKER in text:
            continue
        block = f"\n{MARKER}\n{body.strip()}\n"
        # Insert before Rynix workflow
        anchor = "## Rynix workflow"
        if anchor in text:
            text = text.replace(anchor, block + "\n" + anchor, 1)
        else:
            text = text.rstrip() + block + "\n"
        path.write_text(text, encoding="utf-8")
        updated += 1
        lines = len(text.splitlines())
        print(f"expanded {name}.md ({lines} lines)")

    thin = [
        p.name
        for p in FRAMEWORKS.glob("*.md")
        if p.name not in PRESERVE and len(p.read_text(encoding="utf-8").splitlines()) < MIN_LINES
    ]
    if thin:
        print(f"WARN still <{MIN_LINES} lines: {thin}", file=__import__("sys").stderr)
    print(f"deep-dive updated {updated} guides")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
