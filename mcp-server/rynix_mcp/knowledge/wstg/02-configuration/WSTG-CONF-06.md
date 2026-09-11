---
id: WSTG-CONF-06
title: Test HTTP Methods
category: Configuration and Deployment Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
---

# WSTG-CONF-06: Test HTTP Methods

## Summary

HTTP methods (verbs) define actions on resources. Misconfigured servers may allow dangerous methods like PUT, DELETE, or TRACE, enabling file upload, resource deletion, or Cross-Site Tracing (XST) attacks.

## Test Objectives

- Enumerate supported HTTP methods on each endpoint
- Identify dangerous or unnecessary methods that are enabled
- Test if method-based access controls can be bypassed

## Prerequisites

- Target URL is accessible via `http_probe`

## Test Steps

### Step 1: Send OPTIONS Request

**CLI Actions:**
1. Use `curl` to send an OPTIONS request to the target root and key endpoints:
   ``
   OPTIONS / HTTP/1.1
   Host: target.com
   ``
2. Check the `Allow` header in the response for listed methods
3. Repeat for key application endpoints (login, API, admin)

### Step 2: Test Each HTTP Method

**CLI Actions:**
Test each method using `curl`:

```
GET / HTTP/1.1
Host: target.com
```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 0
```

```
PUT / HTTP/1.1
Host: target.com
Content-Length: 0
```

```
DELETE / HTTP/1.1
Host: target.com
```

```
PATCH / HTTP/1.1
Host: target.com
Content-Length: 0
```

```
TRACE / HTTP/1.1
Host: target.com
```

```
HEAD / HTTP/1.1
Host: target.com
```

```
CONNECT target.com:443 HTTP/1.1
Host: target.com
```

Note the response code for each: 200/204 = allowed, 405 = method not allowed, 501 = not implemented.

### Step 3: Test TRACE for Cross-Site Tracing (XST)

**CLI Actions:**
1. Use `curl` with a TRACE request including custom headers:
   ``
   TRACE / HTTP/1.1
   Host: target.com
   X-Custom-Header: XST-Test
   Cookie: session=test123
   ``
2. If the response body contains the request headers (echoed back), XST is possible

### Step 4: Test Method Override Headers

**CLI Actions:**
Some frameworks allow method override via headers. Test with `curl`:

```
POST /admin/users HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
Content-Length: 0
```

```
POST /admin/users HTTP/1.1
Host: target.com
X-HTTP-Method: PUT
Content-Length: 0
```

```
POST /admin/users HTTP/1.1
Host: target.com
X-Method-Override: PATCH
Content-Length: 0
```

Also test via query parameter:
```
POST /admin/users?_method=DELETE HTTP/1.1
Host: target.com
Content-Length: 0
```

### Step 5: Test Method-Based Access Control Bypass

**CLI Actions:**
1. If an endpoint returns 403 for GET, try other methods with `curl`:
   - POST, PUT, PATCH, DELETE, HEAD, OPTIONS
   - An arbitrary method: `FAKEVERB /restricted-path HTTP/1.1`
2. Compare responses - a different status code may indicate access control bypass

## Payloads

### HTTP Methods to Test
```
GET
POST
PUT
DELETE
PATCH
TRACE
HEAD
OPTIONS
CONNECT
PROPFIND
PROPPATCH
MKCOL
COPY
MOVE
LOCK
UNLOCK
```

### Method Override Headers
```
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
```

## Detection Criteria

A finding should be logged when:
- TRACE method is enabled and echoes request headers (XST vulnerability)
- PUT or DELETE methods are available on endpoints they shouldn't be
- Method override headers bypass access controls
- WebDAV methods (PROPFIND, MKCOL, etc.) are enabled in production
- Arbitrary methods bypass access controls that are only enforced for GET/POST

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| PUT/DELETE allows file modification or resource deletion | High |
| Method override bypasses authentication/authorization | Medium |
| TRACE enabled (XST possible) | Low |
| Unnecessary methods enabled but without exploitable impact | Low |

## Remediation

- Disable TRACE method on the web server
- Only allow necessary HTTP methods per endpoint
- Ensure access controls are enforced regardless of HTTP method
- Disable WebDAV methods if not needed
- Block method override headers at the reverse proxy or WAF level

## References

- [OWASP Testing Guide - Test HTTP Methods](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
- [CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

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

- V14 Configuration — secure defaults for headers, TLS, methods.
- V13 API and Web Service — admin interfaces not exposed.

## CWE references

- CWE-16: Configuration
- CWE-319: Cleartext Transmission

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test HTTP methods, security headers, and TLS cipher suites.
- Verify admin/debug interfaces return 404 or require auth in production.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

