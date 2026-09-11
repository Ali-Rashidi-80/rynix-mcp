---
name: rails
description: Security testing for Ruby on Rails — strong parameters, CSRF, ActiveRecord SQLi, and Devise auth
---

# Rails

Security testing for Ruby on Rails — strong parameters, CSRF, ActiveRecord SQLi, and Devise auth. Map routes with `analyze_repo` (stack hint `rails`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `config/routes.rb`, RESTful resources, namespaces
- `before_action :authenticate_user!`
- ActiveRecord, `find_by_sql`, scopes
- ERB templates, `html_safe` abuse

**Auth**
- Devise, `current_user`, `authorize!` (CanCanCan)
- Doorkeeper OAuth, API-only mode without CSRF

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `before_action :authenticate`, `current_user`, `authorize!`, `doorkeeper_authorize!`, `protect_from_forgery`.

## High-Value Targets

- `/rails/info/properties`, `/rails/mailers` in development mis-deployed
- ActiveStorage direct upload URLs
- Sidekiq Web UI `/sidekiq`
- GraphQL mount without per-field authorization

## Reconnaissance

```
GET /users/sign_in
GET /api/v1/users/1
X-CSRF-Token: ... (for cookie auth)
```

## Key Vulnerabilities

### Mass assignment
- `permit!` or missing strong parameters on `params.require`
- `attr_accessible` legacy apps

### SQL injection
- `where("name = '#{params[:q]}'")` string interpolation
- `order(params[:sort])` without allowlist

### IDOR
- `User.find(params[:id])` without scoping to `current_user`

## Stack-specific probe matrix

| Resource | before_action | CanCan |
|----------|---------------|--------|
| UsersController | authenticate | authorize |
| Admin:: | admin role | separate namespace |
| ActiveStorage | signed URLs | expiry |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `rails`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["rails"]` in profile `[scanner]` for dedicated extractor routing.
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
### Strong parameters
`params.permit!` in legacy controllers. API-only mode skipping CSRF — ensure token auth still enforced.

### Sidekiq Web
Mount at `/sidekiq` without Devise — vertical escalation to job queue.

### IDOR scoping
`current_user.cases.find(params[:id])` vs `Case.find(params[:id])` — static grep both patterns.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["rails"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
