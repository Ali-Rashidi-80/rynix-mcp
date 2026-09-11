---
id: WSTG-INPV-03
title: Testing for HTTP Verb Tampering
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering
---

# WSTG-INPV-03: Testing for HTTP Verb Tampering

## Summary

HTTP Verb Tampering tests whether an application enforces access controls consistently across all HTTP methods. Many web frameworks and servers respond differently to various HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, etc.). If authorization checks are only applied to specific methods (e.g., POST), an attacker may bypass them by reissuing the request with a different method (e.g., GET or an arbitrary verb). Method override headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method) can also be abused to trick the server into treating a request as a different method than what was actually sent.

## Test Objectives

- Determine if access controls differ when the HTTP method is changed
- Identify endpoints that accept unexpected or arbitrary HTTP methods
- Test if method override headers can bypass authentication or authorization
- Verify that security-sensitive actions are restricted to their intended HTTP methods

## Prerequisites

- Target URL is accessible via `http_probe`
- Application entry points and authenticated endpoints have been mapped (WSTG-INFO-06)
- At least one authenticated session for testing protected resources
- Knowledge of which endpoints are restricted and which HTTP methods they should accept

## Test Steps

### Step 1: Enumerate Allowed HTTP Methods

**CLI Actions:**
1. Use `curl` to identify key endpoints, especially those with access controls
2. For each endpoint, use `curl` with an OPTIONS request to discover allowed methods:
   ``
   OPTIONS /admin/dashboard HTTP/1.1
   Host: target.com
   ``
3. Check the `Allow` header in the response for listed methods
4. Use `save to manual-review file` to save each endpoint for further testing

### Step 2: Test Access-Controlled Endpoints with Different Methods

**CLI Actions:**
1. Identify an endpoint that returns 403 Forbidden or redirects for unauthorized users
2. Use `curl` to replay the request with different HTTP methods:
   ``
   GET /admin/users HTTP/1.1
   Host: target.com
   ``
   ``
   POST /admin/users HTTP/1.1
   Host: target.com
   ``
   ``
   PUT /admin/users HTTP/1.1
   Host: target.com
   ``
   ``
   DELETE /admin/users HTTP/1.1
   Host: target.com
   ``
   ``
   PATCH /admin/users HTTP/1.1
   Host: target.com
   ``
   ``
   HEAD /admin/users HTTP/1.1
   Host: target.com
   ``
3. Compare response codes and bodies across methods
4. If any method returns a 200 or different response, it may indicate a bypass

### Step 3: Test Arbitrary HTTP Methods

**CLI Actions:**
Use `curl` with non-standard or arbitrary HTTP verbs:
```
FOOBAR /admin/users HTTP/1.1
Host: target.com
```
```
TEST /admin/users HTTP/1.1
Host: target.com
```
```
JEFF /admin/users HTTP/1.1
Host: target.com
```

Some web servers or frameworks treat unrecognized methods as GET requests, potentially bypassing method-specific access controls.

### Step 4: Test Method Override Headers

**CLI Actions:**
Use `curl` to send a POST request with method override headers to simulate different methods:
```
POST /admin/users HTTP/1.1
Host: target.com
X-HTTP-Method-Override: PUT
Content-Length: 0
```
```
POST /admin/users HTTP/1.1
Host: target.com
X-HTTP-Method: DELETE
Content-Length: 0
```
```
POST /admin/users HTTP/1.1
Host: target.com
X-Method-Override: PATCH
Content-Length: 0
```
```
GET /admin/users HTTP/1.1
Host: target.com
X-HTTP-Method-Override: POST
```

Also test with query string overrides:
```
GET /admin/users?_method=DELETE HTTP/1.1
Host: target.com
```
```
POST /admin/users?_method=PUT HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

_method=PUT
```

### Step 5: Test TRACE Method for Cross-Site Tracing

**CLI Actions:**
Use `curl` to test if TRACE is enabled:
```
TRACE / HTTP/1.1
Host: target.com
X-Custom-Header: TraceTest
```

If the response body echoes back the full request including headers, Cross-Site Tracing (XST) may be possible, allowing cookie theft in combination with XSS.

### Step 6: Test HEAD Method for Information Disclosure

**CLI Actions:**
Use `curl` to send HEAD requests to authenticated endpoints:
```
HEAD /admin/users HTTP/1.1
Host: target.com
```

Check if the HEAD response reveals information (response headers, status codes) that should be restricted. Some applications process HEAD requests fully but only suppress the body.

## Payloads

### HTTP Methods to Test
```
GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
TRACE
CONNECT
PROPFIND
PROPPATCH
MKCOL
COPY
MOVE
LOCK
UNLOCK
```

### Arbitrary Methods
```
FOOBAR
TEST
JEFF
HACK
CATS
BILBO
DEBUG
TRACK
```

### Method Override Headers
```
X-HTTP-Method-Override: PUT
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PATCH
X-HTTP-Method: PUT
X-HTTP-Method: DELETE
X-Method-Override: PUT
X-Method-Override: DELETE
```

### Method Override via Query/Body Parameters
```
?_method=PUT
?_method=DELETE
?_method=PATCH
_method=PUT (in POST body)
_method=DELETE (in POST body)
```

### Content-Type Variations for Method Switching
```
Content-Type: application/x-www-form-urlencoded
Content-Type: application/json
Content-Type: multipart/form-data
Content-Type: text/xml
```

## Detection Criteria

A finding should be logged when:
- An access-controlled endpoint returns a different (more permissive) response for an alternate HTTP method
- Arbitrary or non-standard HTTP methods bypass authentication or authorization
- Method override headers cause the server to process the request as a different method, bypassing controls
- The TRACE method is enabled and echoes back request headers
- HEAD requests to restricted endpoints return 200 OK instead of 403/401

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authentication or authorization fully bypassed via method change | High |
| Administrative functions accessible via method override | High |
| TRACE method enabled, exploitable with XSS for session hijacking | Medium |
| Sensitive data disclosed via HEAD or OPTIONS to unauthorized users | Medium |
| Different methods return different error codes but no data leakage | Low |
| OPTIONS reveals allowed methods without further exploitable impact | Informational |

## Remediation

- Enforce access controls at the application layer regardless of HTTP method
- Configure the web server to reject HTTP methods that are not explicitly required
- Disable TRACE and TRACK methods on the web server
- Ignore or reject method override headers (X-HTTP-Method-Override, etc.) unless explicitly needed
- Implement authorization checks in a centralized middleware that applies to all HTTP methods
- Use allowlists for accepted HTTP methods on each endpoint
- Test access controls with multiple HTTP methods during code review and QA

## References

- [OWASP Testing Guide - HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
- [OWASP HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
- [CWE-650: Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

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

- V5 Validation — input handling and parser differentials.
- V12 Files and Resources — upload and inclusion controls.

## CWE references

- CWE-20: Improper Input Validation
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting

## Rynix tooling

- Primary tools: ``http_probe``, ``rynix_plugin_run` (template-scan)`, ``record_finding``

## Test focus

- Fuzz parameters with encoding variants (URL, Unicode, double-encoding).
- Switch Content-Type to traverse alternate validators.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

