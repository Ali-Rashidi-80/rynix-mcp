---
name: nuxt
description: Security testing for Nuxt 3 — server routes, middleware, auth module, and SSR data leaks
---

# Nuxt

Security testing for Nuxt 3 — server routes, middleware, auth module, and SSR data leaks. Map routes with `analyze_repo` (stack hint `nuxt`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `definePageMeta({ middleware: 'auth' })`
- Server routes `server/api/*.ts` — often weaker than pages
- `useFetch`, `useAsyncData` exposing secrets in HTML payload
- Nitro server handlers

**Auth**
- `@sidebase/nuxt-auth`, custom `auth` middleware
- Route rules in `nuxt.config`

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `definePageMeta`, `middleware:`, `server/api`, `useAuth`, `navigateTo`.

## High-Value Targets

- `/api/_nuxt` build manifest revealing all routes
- Server API routes without mirroring page middleware
- `runtimeConfig` public vs private key confusion

## Reconnaissance

```
GET /api/health
GET /dashboard
# Inspect __NUXT_DATA__ in HTML source
```

## Key Vulnerabilities

### SSR data leakage
- Sensitive fields serialized into `__NUXT__` payload
- Server route returns internal fields not filtered for client

### Auth middleware gaps
- `middleware/auth.ts` not applied to `/api/*` server routes

## Stack-specific probe matrix

| Layer | middleware | server/api |
|-------|------------|------------|
| pages | auth | same rules |
| server/api | often missing | priority target |
| __NUXT__ payload | no secrets | grep HTML |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `nuxt`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["nuxt"]` in profile `[scanner]` for dedicated extractor routing.
- Review `analyze_repo` warnings for `generic_extractor_used` — expand `api_roots` if triggered.
- Cross-check routes from `list_api_routes` against auth markers listed above.

## Bypass techniques

- Content-Type and method override (`X-HTTP-Method-Override`, `_method` parameter).
- Path normalization (`/api/users/1/`, `/api/users/1%2f`, case variants).
- Duplicate parameters and JSON key precedence in binding layers.
- Race parallel requests on state-changing endpoints (limits, balances, invites).

## Validation requirements

- Side-by-side `compare_role_response` for owner vs non-owner on object IDs.
- Static `rbac_matrix` citation (file:line) for routes missing auth markers.
- Minimal safe payloads only — document exact request that proves the flaw.
- Session ID on every live tool call; findings via `record_finding` with probe hash.


## Industrial deep dive
### server/api parity
`server/api/**/*.ts` often skips middleware used in `pages/`. Priority fuzz list.

### Payload leak
Inspect `__NUXT__` / `__NUXT_DATA__` in HTML for PII returned from `useFetch`.

### Nitro route rules
`routeRules` auth misconfiguration on hybrid static pages.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["nuxt"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
