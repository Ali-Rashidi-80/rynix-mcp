---
name: fastify
description: Security testing for Fastify — JSON schema validation, hooks lifecycle, and plugin encapsulation
---

# Fastify

Security testing for Fastify — JSON schema validation, hooks lifecycle, and plugin encapsulation. Map routes with `analyze_repo` (stack hint `fastify`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- Route schemas (`schema.body`, `response`) — validation bypass via extra keys
- `onRequest`, `preHandler`, `preValidation` hooks
- Plugin encapsulation — auth plugin not applied to nested plugins
- `@fastify/multipart`, `@fastify/static`

**Auth**
- `@fastify/jwt`, custom `preHandler` auth
- Role decorators in TypeScript routes

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `preHandler`, `@fastify/jwt`, `request.user`, `authenticate`, `onRequest`.

## High-Value Targets

- Routes registered outside authenticated plugin scope
- `/documentation` Swagger in production
- WebSocket `@fastify/websocket` without JWT repeat check

## Reconnaissance

```
GET /health
GET /api/users/1
```

## Key Vulnerabilities

### Schema bypass
- `additionalProperties: true` allowing privilege fields
- Content-Type switching to skip JSON schema validation

### Hook ordering
- `preValidation` skipped when `attachValidation: false`

### IDOR
- Handler trusts `request.params.id` without tenant scoping

## Stack-specific probe matrix

| Route | preHandler | schema.strict |
|-------|------------|---------------|
| /api/* | jwtVerify | additionalProperties false |
| /docs | public | disable prod |
| upload | multipart | filename traversal |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `fastify`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["fastify"]` in profile `[scanner]` for dedicated extractor routing.
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
### Schema strictness
`additionalProperties: true` allows injecting `role` or `ownerId`. Fuzz nested objects in `schema.body`.

### Plugin encapsulation
Routes registered on parent instance bypass child plugin `preHandler` — verify encapsulation boundaries.

### Swagger in prod
`/documentation` exposes full attack map — gate with auth or disable.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["fastify"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
