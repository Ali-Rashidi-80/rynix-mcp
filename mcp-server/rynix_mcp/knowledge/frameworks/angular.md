---
name: angular
description: Security testing for Angular — route guards, interceptors, and template sanitization bypass
---

# Angular

Security testing for Angular — route guards, interceptors, and template sanitization bypass. Map routes with `analyze_repo` (stack hint `angular`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `CanActivate`, `CanActivateChild`, `CanLoad` guards
- HTTP interceptors adding `Authorization`
- DomSanitizer bypass research (bypassSecurityTrust*)
- Lazy modules with separate guard registration

**Auth**
- `AuthGuard` service, role-based `*ngIf` only in template

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `CanActivate`, `AuthGuard`, `HttpInterceptor`, `router.navigate`, `hasRole`.

## High-Value Targets

- Admin lazy modules — test loading `/admin` module chunks
- Environment.ts API URLs and feature flags in bundle
- GraphQL Apollo client with stored tokens

## Reconnaissance

```
GET /admin
GET /api/users/1
```

## Key Vulnerabilities

### Guard bypass
- Resolver fetches data before guard completes (race)
- API not validating roles that UI hides

### XSS
- `bypassSecurityTrustHtml` misuse
- Custom elements shadow DOM escaping sanitizer

## Stack-specific probe matrix

| Guard | CanActivate | lazy module |
|-------|-------------|-------------|
| AuthGuard | route | chunk still loads |
| RoleGuard | data.roles | API enforcement |
| HttpInterceptor | Bearer | refresh race |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `angular`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["angular"]` in profile `[scanner]` for dedicated extractor routing.
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
### Lazy module guards
`CanLoad` vs `CanActivate` — chunks may load before guard completes. Test direct chunk URLs.

### DomSanitizer bypass
`bypassSecurityTrustHtml` on user content — document sink file:line.

### Interceptor gaps
Requests bypassing `HttpInterceptor` via raw `fetch` in legacy code.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["angular"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
