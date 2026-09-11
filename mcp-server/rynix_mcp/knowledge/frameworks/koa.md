---
name: koa
description: Security testing for Koa — async middleware onion, ctx.state, and JWT
---

# Koa

Security testing for Koa — async middleware onion, ctx.state, and JWT. Map routes with `analyze_repo` (stack hint `koa`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `app.use` middleware onion — first registered = outermost
- `ctx.state`, `ctx.request.body`
- `@koa/router` route-level middleware
- Error event listener stack traces

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `ctx.state.user`, `jwt`, `koa-jwt`, `session`, `isAuthenticated`.

## High-Value Targets

- Router middleware not applied when mounting with `prefix` mismatch
- `koa-static` serving `.env` if misconfigured
- GraphQL koa mount

## Reconnaissance

```
GET /api/health
GET /api/users/1
```

## Key Vulnerabilities

### Middleware onion
- Auth middleware after router — never runs for matched routes
- `ctx.throw` leaking internal messages

### Session
- `koa-session` without `secure` on HTTPS

## Stack-specific probe matrix

| Middleware order | ctx.state | onion |
|------------------|-----------|-------|
| auth before router | user | gap if after |
| session | secure cookie | fixation |
| body parser | limits | DoS safe |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `koa`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["koa"]` in profile `[scanner]` for dedicated extractor routing.
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

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["koa"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
