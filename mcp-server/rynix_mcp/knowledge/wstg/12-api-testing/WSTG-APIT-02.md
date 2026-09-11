---
id: WSTG-APIT-02
title: Testing REST APIs
category: API Testing
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/02-Testing_REST_API
---

# WSTG-APIT-02: Testing REST APIs

## Summary

REST APIs expose application functionality via HTTP endpoints using standard methods (GET, POST, PUT, DELETE, PATCH). Common security issues include Broken Object-Level Authorization (BOLA/IDOR) where users access other users' resources by manipulating IDs, mass assignment where extra properties in requests modify unintended fields, improper content type negotiation, missing rate limiting, verbose error messages exposing internal details, and lack of proper input validation on API parameters.

## Test Objectives

- Test for Broken Object-Level Authorization (BOLA/IDOR) across API endpoints
- Test for mass assignment by adding unexpected properties to requests
- Assess content type handling and error responses
- Verify rate limiting on API endpoints
- Test authentication and authorization enforcement
- Check for verbose error messages and information disclosure

## Prerequisites

- Target application exposes REST API endpoints
- API documentation (Swagger/OpenAPI) available or endpoints discovered via proxy
- Docker pentest container capturing traffic
- Multiple test accounts with different privilege levels

## Test Steps

### Step 1: Discover and Map API Endpoints

**CLI Actions:**
Use `curl` to check for API documentation:

```
GET /swagger.json HTTP/1.1
Host: target.com
```

```
GET /api-docs HTTP/1.1
Host: target.com
```

```
GET /openapi.json HTTP/1.1
Host: target.com
```

```
GET /v1/api-docs HTTP/1.1
Host: target.com
```

```
GET /.well-known/openapi.json HTTP/1.1
Host: target.com
```

Use `curl` to collect all API requests observed during application usage. Map endpoints, methods, and parameters.

### Step 2: Test Broken Object-Level Authorization (BOLA/IDOR)

**CLI Actions:**
Use `save to manual-review file` with authenticated API requests. Modify resource IDs to access other users' data:

```
GET /api/v1/users/1001/profile HTTP/1.1
Host: target.com
Authorization: Bearer <user_A_token>
```

Change to another user's ID:
```
GET /api/v1/users/1002/profile HTTP/1.1
Host: target.com
Authorization: Bearer <user_A_token>
```

Use `fuzz-cli` to enumerate IDs:
```
GET /api/v1/users/§1001§/profile HTTP/1.1
Host: target.com
Authorization: Bearer <user_A_token>
```

Test BOLA on all CRUD operations:
```
GET /api/v1/orders/§ORDER_ID§ HTTP/1.1
PUT /api/v1/orders/§ORDER_ID§ HTTP/1.1
DELETE /api/v1/orders/§ORDER_ID§ HTTP/1.1
```

Also test non-numeric IDs (UUIDs, slugs) - use `curl` to collect valid IDs observed in traffic.

### Step 3: Test Mass Assignment

**CLI Actions:**
Use `curl` to add extra properties to API requests:

```
PUT /api/v1/users/me HTTP/1.1
Host: target.com
Authorization: Bearer <token>
Content-Type: application/json

{"name": "Test User", "email": "test@test.com", "role": "admin", "isAdmin": true, "balance": 999999, "verified": true, "tier": "premium"}
```

```
POST /api/v1/users/register HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "newuser", "password": "Pass123!", "email": "new@test.com", "role": "admin", "permissions": ["admin", "super_admin"]}
```

Use the API documentation (if available) to find all model properties and test injecting internal/admin-only fields.

### Step 4: Test HTTP Method Override

**CLI Actions:**
Use `curl` to test if method restrictions can be bypassed:

```
POST /api/v1/users/1001 HTTP/1.1
Host: target.com
Authorization: Bearer <token>
X-HTTP-Method-Override: DELETE
```

```
GET /api/v1/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer <user_token>
X-HTTP-Method: PUT
```

Test override headers:
- `X-HTTP-Method-Override`
- `X-HTTP-Method`
- `X-Method-Override`
- `_method` parameter

### Step 5: Test Content Type Handling

**CLI Actions:**
Use `curl` to send requests with unexpected content types:

```
POST /api/v1/data HTTP/1.1
Host: target.com
Content-Type: application/xml

<root><username>admin</username><role>admin</role></root>
```

```
POST /api/v1/data HTTP/1.1
Host: target.com
Content-Type: text/plain

username=admin&role=admin
```

If the API accepts XML when it expects JSON, XXE may be possible:
```
POST /api/v1/data HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>
```

### Step 6: Test API Versioning and Deprecated Endpoints

**CLI Actions:**
Use `curl` to test older API versions that may lack security controls:

```
GET /api/v1/users/1001 HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

```
GET /api/v2/users/1001 HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

```
GET /api/users/1001 HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

Older versions may have weaker authentication, no rate limiting, or missing authorization checks.

### Step 7: Test Rate Limiting

**CLI Actions:**
Use `fuzz-cli` to test rate limiting on API endpoints:

```
GET /api/v1/users/me HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

Send 100+ requests rapidly and monitor for:
- HTTP 429 Too Many Requests
- `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers
- Throttling or blocking behavior

Test sensitive endpoints specifically:
- Login / authentication
- Password reset
- User enumeration endpoints
- Data export endpoints

### Step 8: Test Verbose Error Responses

**CLI Actions:**
Use `curl` to trigger errors and check for information disclosure:

```
GET /api/v1/users/invalid HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

```
POST /api/v1/data HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{invalid_json}
```

```
GET /api/v1/internal/debug HTTP/1.1
Host: target.com
```

Check for stack traces, database errors, internal paths, or framework details in error responses.

Use `rynix_plugin_run('template-scan')` to check for API-related findings.

## Payloads

### BOLA/IDOR Test Values
```
# Sequential IDs
1, 2, 3, ..., 1000

# Common test IDs
0, -1, 1, 2, admin, root, test

# UUID enumeration (if found in traffic)
<UUID from user A>
<UUID from user B>

# Encoded IDs
Base64-encoded IDs
URL-encoded IDs
```

### Mass Assignment Properties
```
role
admin
is_admin
isAdmin
permissions
privilege
account_type
tier
balance
credits
verified
email_verified
approved
status
internal
debug
```

### HTTP Method Override Headers
```
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PUT
X-HTTP-Method-Override: PATCH
X-HTTP-Method: DELETE
X-Method-Override: PUT
_method=DELETE
```

### Content Types to Test
```
application/json
application/xml
text/xml
application/x-www-form-urlencoded
multipart/form-data
text/plain
application/yaml
```

### API Discovery Paths
```
/swagger.json
/swagger/v1/swagger.json
/api-docs
/openapi.json
/openapi.yaml
/v1/api-docs
/v2/api-docs
/.well-known/openapi.json
/api/swagger
/docs
/redoc
```

## Detection Criteria

A finding should be logged when:
- User A can access User B's resources by changing resource IDs (BOLA)
- Extra properties in requests modify restricted fields (mass assignment)
- HTTP method override bypasses access controls
- API accepts unexpected content types that enable XXE or other attacks
- No rate limiting on sensitive API endpoints
- Deprecated API versions lack security controls
- Error responses reveal internal details (stack traces, DB errors, paths)
- API documentation is publicly accessible and reveals internal endpoints

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| BOLA allows accessing/modifying other users' sensitive data | High |
| Mass assignment enables privilege escalation (role=admin) | High |
| XXE via content type switching (XML accepted) | High |
| Missing authentication on sensitive API endpoints | High |
| Mass assignment modifies non-security fields (name, preferences) | Medium |
| No rate limiting on login API endpoint | Medium |
| Deprecated API version accessible with weaker security | Medium |
| API documentation publicly accessible with internal endpoints | Medium |
| Verbose error messages with stack traces | Low |
| Rate limiting exists but threshold is high | Low |
| Proper BOLA prevention, mass assignment protection, rate limiting | Not a finding |

## Remediation

- Implement object-level authorization checks in every API endpoint
- Use the authenticated user's ID from the session/token, not from request parameters
- Implement allowlisting for accepted request properties (prevent mass assignment)
- Enforce strict content type validation (reject unexpected content types)
- Implement rate limiting on all API endpoints, especially authentication
- Remove or secure deprecated API versions
- Return generic error messages without internal details
- Disable API documentation in production or protect with authentication
- Implement proper authentication (OAuth 2.0, API keys with scopes)
- Use pagination with maximum page size limits
- Log and monitor API access patterns for anomaly detection
- Validate all input parameters against expected schemas

## References

- [OWASP Testing Guide - Testing REST API](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/02-Testing_REST_API)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

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

