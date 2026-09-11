---
name: laravel
description: Security testing for Laravel — gates, policies, mass assignment, debug mode, and route middleware
---

# Laravel

Security testing for Laravel — gates, policies, mass assignment, debug mode, and route middleware. Map routes with `analyze_repo` (stack hint `laravel`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `routes/web.php`, `routes/api.php`, `Route::` groups
- Middleware `auth`, `can`, `throttle`
- Eloquent ORM, raw `DB::select`
- Blade templates, `{!! !!}` unescaped output

**Auth**
- `Gate::`, `Policy` classes, `@can` directives
- Sanctum, Passport API tokens
- `Auth::user()`, middleware `auth:sanctum`

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `middleware('auth'`, `->middleware(`, `Gate::`, `authorize(`, `auth:sanctum`, `@can`.

## High-Value Targets

- `/telescope`, `/horizon`, `/_ignition` when debug enabled
- `APP_DEBUG=true` exposing `.env` via error pages
- API resources returning hidden attributes leak via `append`
- Storage symlink `public/storage` path traversal

## Reconnaissance

```
GET /api/user
GET /sanctum/csrf-cookie
php artisan route:list  (whitebox via analyze_repo)
```

## Key Vulnerabilities

### Mass assignment
- `$fillable` / `$guarded` misconfiguration on User model
- `create($request->all())` on sensitive models

### Policy gaps
- `view` authorized but `update`/`delete` missing policy checks
- API routes without `auth` middleware in `api.php`

### SQL injection
- `whereRaw`, `orderByRaw` with concatenated user input

## Stack-specific probe matrix

| Route file | middleware | Policy |
|------------|------------|--------|
| api.php | auth:sanctum | per-model |
| web.php | auth | CSRF |
| /telescope | auth | disable prod |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `laravel`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["laravel"]` in profile `[scanner]` for dedicated extractor routing.
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
### Policy vs gate
`Gate::allows` in controller but missing on Livewire/Filament parallel routes. Scan `routes/api.php` vs `routes/web.php`.

### Debug tools
`/_ignition`, `/telescope` must be disabled. `.env` `APP_DEBUG=false` on staging mirrors.

### Mass assignment
`$guarded = []` on User model — classic privilege escalation via registration.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["laravel"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
