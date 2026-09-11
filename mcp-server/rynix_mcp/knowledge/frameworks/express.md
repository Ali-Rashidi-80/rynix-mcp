---
name: express
description: Security testing for Express.js applications covering middleware chains, session/JWT auth, and prototype pollution in Node
---

# Express

Security testing for Express.js applications covering middleware chains, session/JWT auth, and prototype pollution in Node. Map routes with `analyze_repo` (stack hint `express`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- `app.use()` middleware order — auth applied after route registration leaks access
- Routers (`express.Router`), nested mounts at `/api`, `/admin`
- Body parsers: `express.json`, `urlencoded`, `multer` for uploads
- Error handlers and `next(err)` — stack trace leakage

**Auth**
- Passport.js strategies (local, JWT, OAuth), `req.user` population
- `express-session` + `connect-redis`, cookie flags
- Custom middleware: `ensureAuthenticated`, role checks on `req.user.role`

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `passport.authenticate`, `req.isAuthenticated`, `req.user`, `jwt.verify`, `ensureLoggedIn`, `authorize(`.

## High-Value Targets

- `/api/*` routes mounted without global auth middleware
- Admin routers under `/admin` or `/internal`
- File upload (`multer`) + static `express.static` misconfig
- Webhook/callback URLs accepting user-supplied targets (SSRF)
- GraphQL mounted via `express-graphql` with introspection enabled

## Reconnaissance

```
GET /api/health
GET /api/users/1  (IDOR matrix)
curl -H "Authorization: Bearer <token>" /api/admin/users
# Fingerprint: X-Powered-By: Express (disable in prod)
```

## Key Vulnerabilities

### Authentication gaps
- Route registered before `passport.session()` middleware
- JWT in header verified but `req.user` never bound — handlers trust client-sent `userId`
- Role check only in UI, not in API route

### Prototype pollution / mass assignment
- `Object.assign(req.body, defaults)` without schema validation
- Lodash `merge` on user input — test `__proto__`, `constructor.prototype`

### Injection
- `eval`, `vm`, template engines (EJS, Pug, Handlebars) with user input
- NoSQL (`$gt`, `$where`) when using Mongoose without sanitization
- Raw SQL via `mysql2`/`pg` string concatenation bypassing ORM

### CORS / CSRF
- `cors({ origin: true })` reflecting arbitrary Origin with credentials
- Cookie auth without `SameSite` + missing CSRF token on state-changing routes

## Stack-specific probe matrix

| Endpoint pattern | Role A | Role B | IDOR? |
|------------------|--------|--------|-------|
| GET /api/users/:id | 200 own | 403 other | test |
| POST /api/admin/* | 403 user | 200 admin | vertical |
| GET /api/internal/health | 401 | 401 | no leak |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `express`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["express"]` in profile `[scanner]` for dedicated extractor routing.
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
### Middleware ordering attacks
Map `app.use` registration order in `analyze_repo`. Routes attached to `app` before `passport.session()` may be reachable without session. Test nested routers mounted at `/api` vs `/api/v1` for inconsistent JWT middleware.

### NoSQL and prototype pollution
When Mongoose is present, probe `{"$gt":""}` and `__proto__` keys in JSON bodies. Express `extended` urlencoded parser may accept nested objects that bypass shallow validators.

### Production hardening checklist
- Disable `X-Powered-By`
- Ensure `trust proxy` matches deployment (Host/X-Forwarded-For)
- Rate-limit auth routes independently of public static assets

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["express"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
