---
name: vue
description: Security testing for Vue 3 — router guards, Pinia auth state, and template injection
---

# Vue

Security testing for Vue 3 — router guards, Pinia auth state, and template injection. Map routes with `analyze_repo` (stack hint `vue`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- Vue Router `beforeEach` navigation guards
- Composition API `ref`/`reactive` storing tokens
- `v-html` directive XSS sink
- Nuxt overlap — see nuxt.md for SSR

**Auth**
- `meta: { requiresAuth: true }` on routes
- Axios interceptors attaching JWT

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `beforeEach`, `requiresAuth`, `meta.roles`, `router.beforeEach`, `useAuthStore`.

## High-Value Targets

- Lazy-loaded admin chunks still downloadable
- `/api` proxy misconfiguration in dev server deployed to prod
- WebSocket channels keyed by user ID in query string

## Reconnaissance

```
# router.ts paths from analyze_repo
GET /settings
GET /api/profile
```

## Key Vulnerabilities

### Guard bypass
- Direct API calls skipping router guards
- `requiresAuth` only on parent route — child routes open

### XSS
- `v-html` with user content
- Server-side template injection if using Vue SSR without escaping

## Stack-specific probe matrix

| Route meta | beforeEach | Pinia token |
|------------|------------|-------------|
| requiresAuth | block | API still test |
| roles: admin | redirect | horizontal IDOR |
| /api/* | axios interceptor | revoke on 401 |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `vue`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["vue"]` in profile `[scanner]` for dedicated extractor routing.
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
### Router meta drift
Child routes missing `meta.requiresAuth` when parent has it. Test deep links `/settings/billing`.

### Pinia persistence
Serialized auth state in localStorage — tamper `role` field and replay API calls.

### SSR hydration
Nuxt overlap — see also `nuxt.md` for server route parity.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["vue"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
