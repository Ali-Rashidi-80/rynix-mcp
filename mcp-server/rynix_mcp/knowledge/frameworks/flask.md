---
name: flask
description: Security testing for Flask/Werkzeug apps — decorators, Jinja2 SSTI, session signing, and blueprint auth drift
---

# Flask

Security testing for Flask/Werkzeug apps — decorators, Jinja2 SSTI, session signing, and blueprint auth drift. Map routes with `analyze_repo` (stack hint `flask`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- Blueprints (`Blueprint`, `register_blueprint`) with independent before_request hooks
- `@app.route` decorators, method lists, `strict_slashes`
- Jinja2 templates, `render_template`, `|safe` filter abuse
- Werkzeug debugger PIN bypass when `debug=True`

**Auth**
- Flask-Login (`@login_required`, `current_user`)
- Flask-JWT-Extended, Flask-HTTPAuth
- `@roles_required`, custom decorators inconsistently applied

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `@login_required`, `login_required`, `current_user`, `@jwt_required`, `roles_required`, `permission_required`.

## High-Value Targets

- `/admin`, Flask-Admin panel
- Debug toolbar, Werkzeug interactive debugger
- Secret key dependent endpoints (itsdangerous signed URLs)
- File download `send_file` with user-controlled paths
- Celery/RQ task enqueue with object IDs

## Reconnaissance

```
curl -I https://target/
GET /login  /admin  /api/v1/
# Check Set-Cookie: session=...
```

## Key Vulnerabilities

### Session / crypto
- Weak or default `SECRET_KEY` — forge session cookies
- `SESSION_COOKIE_SECURE=False` on HTTPS deployment

### SSTI (Jinja2)
```
{{7*7}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### IDOR
- Blueprint without `before_request` auth on subset of routes
- API returning 404 vs 403 — information leak on object existence

## Stack-specific probe matrix

| Blueprint | @login_required | Anonymous |
|-----------|-----------------|-----------|
| /api/v1/* | required | 401 |
| /admin/* | staff only | redirect |
| /static/uploads/* | N/A | path traversal |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `flask`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["flask"]` in profile `[scanner]` for dedicated extractor routing.
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
### Blueprint isolation
Each `Blueprint` can define `@bp.before_request`. Compare auth on `api_bp` vs `admin_bp` — interns sometimes get API access while admin HTML routes stay protected (false sense of safety).

### Session forgery
If `SECRET_KEY` is weak or committed, forge `session` cookie. Test `SESSION_COOKIE_SECURE` and `HTTPONLY` on HTTPS deployments.

### SSTI confirmation chain
`{{7*7}}` → config leak payloads → only on authorized staging. Document exact template file from `analyze_repo`.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["flask"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
