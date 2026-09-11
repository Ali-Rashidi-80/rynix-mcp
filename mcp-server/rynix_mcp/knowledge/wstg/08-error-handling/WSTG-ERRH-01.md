---
id: WSTG-ERRH-01
title: Testing for Improper Error Handling
category: Error Handling
severity_range: Informational-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling
---

# WSTG-ERRH-01: Testing for Improper Error Handling

## Summary

Verbose error messages can reveal sensitive information about the application's internal workings, including technology stack, database structure, file paths, and code logic. Attackers use this information to refine their attacks.

## Test Objectives

- Trigger error conditions in the application
- Analyze error messages for sensitive information disclosure
- Identify inconsistent error handling across the application

## Prerequisites

- Target URL is accessible via `http_probe`
- Basic application functionality has been mapped

## Test Steps

### Step 1: Trigger HTTP Error Codes

**CLI Actions:**
Use `curl` to request resources that trigger standard HTTP errors:

```
GET /nonexistent-page-xyz HTTP/1.1          (404 Not Found)
GET /admin/../../../etc/passwd HTTP/1.1     (400/403)
GET / HTTP/1.0                              (test HTTP/1.0 handling)
```

Send a very long URL (8000+ chars) to trigger 414 URI Too Long.
Send a request with invalid Content-Type to trigger 415.

### Step 2: Trigger Application Errors via Invalid Input

**CLI Actions:**
Use `curl` to submit invalid data:

```
GET /product?id=abc HTTP/1.1         (string where number expected)
GET /product?id=-1 HTTP/1.1          (negative ID)
GET /product?id=99999999 HTTP/1.1    (non-existent ID)
GET /product?id= HTTP/1.1            (empty value)
GET /product?id=null HTTP/1.1        (null string)
GET /product?id[]=1 HTTP/1.1         (array parameter)
```

```
POST /api/data HTTP/1.1
Content-Type: application/json

{invalid json}
```

```
POST /api/data HTTP/1.1
Content-Type: application/json

{"field": null, "number": "not_a_number"}
```

### Step 3: Trigger Database Errors

**CLI Actions:**
Use `curl` with SQL meta-characters (see also WSTG-INPV-05):

```
GET /product?id=1' HTTP/1.1
GET /search?q=' HTTP/1.1
GET /user?name=admin%00 HTTP/1.1
```

Check for database error messages in responses.

### Step 4: Trigger Server-Side Errors

**CLI Actions:**
Use `curl` with malformed requests:

```
GET / HTTP/1.1
Host: target.com
Content-Type: %invalid
```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 999999
Transfer-Encoding: chunked
```

```
GET / HTTP/1.1
Host: target.com
Accept: ../../../etc/passwd
```

### Step 5: Analyze Error Responses

For each error response, check for:
- **Stack traces** - reveal code paths, library versions, file locations
- **SQL queries** - reveal database structure and query logic
- **File paths** - reveal server directory structure (`/var/www/html/`, `C:\inetpub\`)
- **Framework versions** - reveal specific software versions
- **Debug information** - detailed error context intended for developers
- **Internal IP addresses** - reveal network architecture

## Payloads

### Error-Triggering Inputs
```
'
"
\
%00
%0a%0d
{{
${
<>
[]
{}
null
undefined
NaN
Infinity
-1
0
99999999999
(empty string)
a]
```

## Detection Criteria

A finding should be logged when:
- Stack traces are displayed to users
- SQL error messages reveal query structure
- File paths on the server are disclosed
- Framework or library versions are revealed in errors
- Debug mode is enabled in production
- Error messages differ for different conditions (may enable enumeration)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Full stack traces with code snippets in production | Medium |
| SQL queries visible in error messages | Medium |
| Server file paths disclosed | Low |
| Framework/library version numbers in errors | Low |
| Generic error page but with verbose HTTP headers | Informational |
| Custom error pages with no information disclosure | Not a finding |

## Remediation

- Implement custom error pages that reveal no technical details
- Disable debug mode and verbose error output in production
- Log detailed errors server-side, show generic messages to users
- Return consistent error responses to prevent enumeration
- Configure the web server to use custom error pages for all HTTP error codes
- Implement a global exception handler that catches all unhandled errors

## References

- [OWASP Testing Guide - Improper Error Handling](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

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

- V7 Error Handling — no stack traces or internal paths in responses.
- V14 Configuration — custom error pages in production.

## CWE references

- CWE-209: Generation of Error Message Containing Sensitive Information

## Rynix tooling

- Primary tools: ``http_probe``, ``record_finding``

## Test focus

- Trigger edge-case inputs and verify generic error responses only.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

