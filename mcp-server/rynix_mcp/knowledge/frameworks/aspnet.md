---
name: aspnet
description: Security testing for ASP.NET Core — `[Authorize]`, policy handlers, antiforgery, and minimal APIs
---

# ASP.NET Core

Security testing for ASP.NET Core — `[Authorize]`, policy handlers, antiforgery, and minimal APIs. Map routes with `analyze_repo` (stack hint `aspnet`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- Controllers, Minimal APIs (`MapGet`, `MapPost`)
- Middleware pipeline order — auth before endpoints
- `IAuthorizationService`, policy-based auth
- Razor Pages, tag helpers

**Auth**
- `[Authorize(Roles = "Admin")]`, `[AllowAnonymous]`
- JWT Bearer, cookie auth, OpenID Connect
- Claims-based authorization

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `[Authorize]`, `[AllowAnonymous]`, `RequireAuthorization`, `AddAuthorization`, `IAuthorizationHandler`.

## High-Value Targets

- Swagger `/swagger`, health checks exposing dependencies
- SignalR hubs without `[Authorize]` on hub methods
- Blazor Server circuit authorization gaps
- `IFormFile` upload path traversal

## Reconnaissance

```
GET /health
GET /swagger/v1/swagger.json
GET /api/users/1
Authorization: Bearer <token>
```

## Key Vulnerabilities

### Policy bypass
- Minimal API endpoint missing `.RequireAuthorization()`
- `[AllowAnonymous]` on nested controller action only

### Mass assignment
- Model binding over-posting to entity with sensitive properties
- `JsonSerializer` missing `[JsonIgnore]` on admin flags

### Deserialization
- `TypeNameHandling` in Newtonsoft.Json (legacy configs)

## Stack-specific probe matrix

| Surface | [Authorize] | Minimal API |
|---------|-------------|-------------|
| Controllers | per-action | .RequireAuthorization() |
| SignalR hubs | hub method | per-invoke |
| Blazor | circuit | server auth |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `aspnet`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["aspnet"]` in profile `[scanner]` for dedicated extractor routing.
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
### Minimal APIs
`.MapGet` without `.RequireAuthorization()` beside secured controllers — common in refactors.

### SignalR
Hub methods without `[Authorize]` while HTTP equivalent requires role.

### Deserialization legacy
`TypeNameHandling.All` in Newtonsoft configs — hunt in `appsettings*.json`.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["aspnet"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
