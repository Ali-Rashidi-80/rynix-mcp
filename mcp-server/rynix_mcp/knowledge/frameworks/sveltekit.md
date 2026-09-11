---
name: sveltekit
description: Security testing for SvelteKit — server hooks, form actions, and `+server.ts` endpoints
---

# SvelteKit

Security testing for SvelteKit — server hooks, form actions, and `+server.ts` endpoints. Map routes with `analyze_repo` (stack hint `sveltekit`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `+page.server.ts`, `+layout.server.ts` load functions
- `hooks.server.ts` `handle` sequence auth
- Form actions `+page.server.ts` `actions`
- `+server.ts` API routes parallel to pages

**Auth**
- `event.locals.user` populated in hooks
- Session cookies via `cookies.set`

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `handle`, `event.locals`, `hooks.server`, `getSession`, `protect`.

## High-Value Targets

- `+server.ts` endpoints missing session check present in `+page.server.ts`
- `prerender` exposing dynamic routes statically
- `PUBLIC_` env vars in client bundle

## Reconnaissance

```
GET /api/health
GET /dashboard
```

## Key Vulnerabilities

### Server/client boundary
- Sensitive data in `load` returned to client unnecessarily
- CSRF on form actions when SameSite misconfigured

### IDOR
- `params.id` in load function without ownership validation

## Stack-specific probe matrix

| File | auth check | risk |
|------|------------|------|
| +page.server.ts | session | data leak in load |
| +server.ts | often open | IDOR |
| hooks.server.ts | set locals | single source |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `sveltekit`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["sveltekit"]` in profile `[scanner]` for dedicated extractor routing.
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
### +server.ts exposure
API routes without `locals.user` check while `+page.server.ts` enforces session.

### Form actions CSRF
Double-submit and missing SameSite on session cookies.

### Prerender leaks
Dynamic routes accidentally prerendered with user-specific data.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["sveltekit"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
