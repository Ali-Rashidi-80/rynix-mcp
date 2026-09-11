---
name: spring
description: Security testing for Spring Boot — SecurityFilterChain, `@PreAuthorize`, SpEL, Actuator, and JPA injection
---

# Spring Boot

Security testing for Spring Boot — SecurityFilterChain, `@PreAuthorize`, SpEL, Actuator, and JPA injection. Map routes with `analyze_repo` (stack hint `spring`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `@RestController`, `@RequestMapping`, path variables
- Spring Security filter chain order, `permitAll` vs `authenticated`
- Actuator endpoints (`/actuator/*`), env, heapdump
- Thymeleaf / Freemarker if present

**Auth**
- `@PreAuthorize`, `@Secured`, `@RolesAllowed`
- OAuth2 Resource Server, JWT decoder configuration
- Method security vs URL security mismatch

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `@PreAuthorize`, `@Secured`, `SecurityFilterChain`, `hasRole`, `hasAuthority`, `@EnableMethodSecurity`.

## High-Value Targets

- `/actuator/env`, `/actuator/heapdump`, `/actuator/gateway/routes`
- Swagger UI `/swagger-ui.html`, `/v3/api-docs`
- Admin `@PreAuthorize("hasRole('ADMIN')")` — test horizontal escalation
- File upload `MultipartFile`, path traversal in storage

## Reconnaissance

```
GET /actuator/health
GET /v3/api-docs
GET /api/users/1
```

## Key Vulnerabilities

### SpEL injection
- `@Value` or custom expressions in `@PreAuthorize` with user input
- Spring Data `sort` parameter injection

### Mass assignment
- `@RequestBody` entity binding extra fields (`isAdmin=true`)
- Jackson `JsonIgnoreProperties` misconfiguration

### IDOR
- Repository `findById` without ownership check in service layer

## Stack-specific probe matrix

| Path | @PreAuthorize | Actuator |
|------|---------------|----------|
| /api/** | authenticated | off in prod |
| /actuator/env | denyAll | must 404 |
| /api/users/{id} | hasRole USER | IDOR |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `spring`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["spring"]` in profile `[scanner]` for dedicated extractor routing.
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
### Actuator exposure
`/actuator/env`, `/actuator/heapdump` must return 404 in prod. If exposed, treat as critical — do not download heap to shared storage.

### `@PreAuthorize` drift
Controller-level annotation missing on new methods in large PRs. Diff OpenAPI vs code for orphan endpoints.

### SpEL and mass assignment
Over-posting to entities via JSON — fields like `isAdmin` not in DTO whitelist.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["spring"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
