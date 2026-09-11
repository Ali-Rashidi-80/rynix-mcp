---
name: graphql
description: Security testing for GraphQL APIs — introspection, batching, depth limits, and resolver auth
---

# GraphQL

Security testing for GraphQL APIs — introspection, batching, depth limits, and resolver auth. Map routes with `analyze_repo` (stack hint `graphql`), then validate authorization with live probes — never trust framework defaults.

## Attack Surface

**Core**
- Schema introspection `__schema`, `__type`
- Queries, mutations, subscriptions
- Field-level auth vs object-level
- DataLoader batching IDOR windows

**Stacks**
- Apollo Server, Yoga, Strawberry, Graphene — resolver patterns differ

## Auth markers (static analysis)

Rynix `analyze_repo` flags routes containing: `@auth`, `@permission`, `shield`, `rule`, `isAuthenticated`, `context.user`.

## High-Value Targets

- Introspection enabled in production
- GraphiQL/Playground exposed
- `users { id email passwordHash }` over-fetching
- Batching attack combining privileged + unprivileged queries

## Reconnaissance

```
POST /graphql
{"query":"{ __schema { types { name } } }"}
```

## Key Vulnerabilities

### Authorization
- Resolver checks parent auth but field resolvers skip check
- Global ID enumeration across types

### DoS
- Deep nested queries without cost analysis
- Alias overload batching

## Stack-specific probe matrix

| Operation | auth directive | batch |
|-----------|----------------|-------|
| Query.users | @auth | field IDOR |
| Mutation.* | role | introspection off |
| subscription | ws auth | topic IDOR |

## Testing Methodology

1. **Enumerate** — `analyze_repo` + `list_api_routes` / `list_frontend_routes` for stack `graphql`.
2. **RBAC matrix** — `rbac_matrix` and `high_risk_surfaces` for IDOR candidates.
3. **Cross-role probes** — `compare_role_response` and `run_idor_matrix` on object IDs in paths.
4. **Config & debug** — `http_probe` admin, actuator, swagger, and debug paths from recon section.
5. **Record evidence** — `record_finding` only after reproducible probe output.

## Stack detection signals

- Set `stack_hints=["graphql"]` in profile `[scanner]` for dedicated extractor routing.
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
### Introspection
Disable in production. Batch privileged introspection query with user token in single HTTP request.

### Field-level auth
Parent resolver authorized but child field leaks cross-tenant data — test nested selections.

### DoS limits
Depth/complexity limits — safe bounded queries only.

## Rynix workflow

1. `scope_check` + `register_scope` for target host.
2. `analyze_repo` with `stack_hints=["graphql"]` — review `detected_stack` confidence.
3. `rbac_matrix` + `high_risk_surfaces` — prioritize endpoints lacking auth markers.
4. `http_probe` / `compare_role_response` / `run_idor_matrix` for evidence.
5. `track_wstg_test` + `export_report` with session ID on every call.

## Evidence requirements

- Request/response diff or status/body hash from `compare_role_response`.
- Repo citation (file:line) when static analysis informed the probe.
- No severity without reproducible probe output.
