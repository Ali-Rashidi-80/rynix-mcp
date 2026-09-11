---
name: gin
description: Security testing for Gin (Go) — middleware chains, JWT groups, binding validation, and goroutine race windows
---

# Gin

Security testing for Gin (Go) — middleware chains, JWT groups, binding validation, and goroutine race windows. Map routes with `analyze_repo` (stack hint `gin`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `gin.Engine`, route groups `r.Group("/api")`
- Middleware: `Use()`, group-level vs route-level
- `ShouldBindJSON`, `BindJSON`, validator tags
- `gin.H` map responses — avoid leaking internal errors

**Auth**
- JWT middleware (`jwt-go`, custom `AuthMiddleware`)
- API key headers, basic auth on admin routes

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `jwt`, `AuthMiddleware`, `middleware.Auth`, `c.Get("user")`, `Authorize`, `RequireRole`.

## High-Value Targets

- `r.Group("/api/v1")` with mixed protected/unprotected routes
- Admin group `/admin` behind weak shared secret header
- File handlers `c.File`, `c.FileAttachment`
- WebSocket upgrade handlers without repeating HTTP auth

## Reconnaissance

```
GET /api/health
GET /api/users/1
Authorization: Bearer <jwt>
```

## Key Vulnerabilities

### Middleware ordering
- Public routes registered on root engine bypassing group middleware
- CORS middleware allowing credentials from reflected Origin

### Binding bypass
- Duplicate JSON keys, wrong Content-Type to skip `ShouldBind`
- Integer overflow on path params (`/users/-1`)

### Concurrency
- Race on balance/quantity updates — parallel `http_probe` batch

## Stack-specific probe matrix

| Group | Middleware | Probe |
|-------|------------|-------|
| /api/v1 | JWT | missing on POST |
| /admin | API key header | brute rotation |
| /ws | none | auth at handshake |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `gin`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["gin"]` in profile `[scanner]` for dedicated extractor routing.
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
### Group middleware gaps
`r.Group("/api")` with `authMiddleware` does not protect routes registered on root `r`. Grep for `r.GET` outside groups after static analysis.

### Binding differentials
Send duplicate JSON keys and wrong `Content-Type` to skip `ShouldBindJSON`. Test path param overflow on `{id}` segments.

### Concurrency on balances
Parallel POSTs to finance-like endpoints — pair with example law-firm application `compare_role_response` patterns.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["gin"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
