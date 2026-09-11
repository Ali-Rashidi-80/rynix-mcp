---
name: react
description: Security testing for React SPAs — client-side routes, token storage, API coupling, and XSS sinks
---

# React

Security testing for React SPAs — client-side routes, token storage, API coupling, and XSS sinks. Map routes with `analyze_repo` (stack hint `react`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- React Router (`Route`, `Navigate`, protected route wrappers)
- State management exposing secrets in bundle
- `dangerouslySetInnerHTML`, DOMPurify misconfig
- Environment variables baked into `VITE_*` / `REACT_APP_*`

**API coupling**
- Bearer tokens in `localStorage` vs `httpOnly` cookies
- CORS preflight differences per API path

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `PrivateRoute`, `useAuth`, `Navigate to="/login"`, `Authorization: Bearer`.

## High-Value Targets

- `/admin`, `/dashboard` routes — test direct URL access (client-only guard)
- API base URL in bundle pointing to staging with weaker auth
- WebSocket subscriptions keyed by predictable IDs

## Reconnaissance

```
# list_frontend_routes from analyze_repo
GET /dashboard  (without auth cookie)
GET /api/users/1  (compare_role_response)
```

## Key Vulnerabilities

### Client-side auth bypass
- Route guard only in React — API must enforce server-side
- JWT in localStorage — XSS steals token

### XSS
- `dangerouslySetInnerHTML` with partial sanitization
- Third-party script tags in CMS-driven React pages

### IDOR
- Frontend hides buttons but API returns other users' data

## Stack-specific probe matrix

| Client route | Guard | API must enforce |
|--------------|-------|------------------|
| /dashboard | PrivateRoute | 401 without token |
| /admin | role check | 403 non-admin |
| /api/* | N/A | compare_role_response |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `react`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["react"]` in profile `[scanner]` for dedicated extractor routing.
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
### Client-only guards
`PrivateRoute` does not protect API. Every hidden button must have `compare_role_response` proof on backing endpoint.

### Token storage
`localStorage` JWT + any XSS = account takeover. Prefer httpOnly cookie architecture review.

### Build-time secrets
`VITE_*` and `REACT_APP_*` leak in bundle — grep production JS for API keys.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["react"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
