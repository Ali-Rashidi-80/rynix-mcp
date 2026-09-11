---
name: axum
description: Security testing for Axum (Rust) — extractors, layers, Tower middleware, and typed routes
---

# Axum

Security testing for Axum (Rust) — extractors, layers, Tower middleware, and typed routes. Map routes with `analyze_repo` (stack hint `axum`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `Router::new()`, `route`, `nest`
- Tower layers: `Extension`, `AuthLayer`, rate limit
- Extractors: `Path`, `Query`, `Json`, `TypedHeader`
- `State` shared application state races

**Auth**
- Custom `FromRequestParts` for JWT/session
- `tower_http::auth` patterns

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `FromRequestParts`, `Extension<User>`, `AuthLayer`, `require_auth`, `Claims`.

## High-Value Targets

- `nest("/api", public_router)` leaking admin routes
- `Debug` error responses in production
- WebSocket upgrade handlers

## Reconnaissance

```
GET /api/health
GET /api/users/{id}
```

## Key Vulnerabilities

### Extractor failures
- `Option<Json<T>>` silently accepting empty body
- Auth extension missing returns 500 vs 401 — info leak

### IDOR
- `Path(uuid)>` without row-level check in handler

## Stack-specific probe matrix

| Router | layer | extractor |
|--------|-------|-----------|
| nest /api | AuthLayer | Path UUID |
| Extension | User | missing 500 |
| ws | handshake | per-msg |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `axum`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["axum"]` in profile `[scanner]` for dedicated extractor routing.
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
2. `analyze_repo` with `stack_hints=["axum"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
