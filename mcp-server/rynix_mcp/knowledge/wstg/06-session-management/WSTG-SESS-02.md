---
id: WSTG-SESS-02
title: Testing for Cookies Attributes
category: Session Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
---

# WSTG-SESS-02: Testing for Cookies Attributes

## Summary

Cookie attributes control how cookies are stored and transmitted by the browser. Missing or misconfigured attributes can expose session tokens to theft via XSS (missing HttpOnly), network interception (missing Secure), or CSRF (missing SameSite).

## Test Objectives

- Verify that session cookies have appropriate security attributes
- Identify cookies with missing or weak security flags
- Assess cookie scope and path restrictions

## Prerequisites

- Target application sets cookies (especially session cookies)
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Capture Set-Cookie Headers

**CLI Actions:**
1. Use `curl` to authenticate and capture the response:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
2. Examine all `Set-Cookie` headers in the response
3. Use `curl` to find all unique `Set-Cookie` headers across the application

### Step 2: Check Each Cookie Attribute

For each cookie found, verify these attributes:

**Secure Flag:**
- Must be present on all session and sensitive cookies
- Prevents cookie from being sent over HTTP (only HTTPS)

**HttpOnly Flag:**
- Must be present on session cookies
- Prevents JavaScript from accessing the cookie (XSS mitigation)

**SameSite Attribute:**
- Should be `Strict` or `Lax` (not `None` unless truly needed for cross-site)
- `SameSite=None` requires `Secure` flag
- Mitigates CSRF attacks

**Domain Attribute:**
- Should be set to the specific domain, not a wildcard parent domain
- e.g., `Domain=app.target.com` not `Domain=.target.com`

**Path Attribute:**
- Should be restricted to the application path
- e.g., `Path=/app/` not `Path=/`

**Expires/Max-Age:**
- Session cookies should not have long-lived expiration
- Persistent cookies for "remember me" should have reasonable expiration

### Step 3: Test Missing Secure Flag

**CLI Actions:**
1. If a cookie lacks the `Secure` flag, use `curl` to access the application over HTTP:
   ``
   GET / HTTP/1.0
   Host: target.com
   ``
2. Check if the cookie is transmitted in the HTTP (non-encrypted) request

### Step 4: Test Cookie Scope

**CLI Actions:**
1. If `Domain` is set broadly (e.g., `.target.com`), any subdomain can read the cookie
2. Use `curl` to check if other subdomains exist that could be compromised:
   ``
   GET / HTTP/1.1
   Host: blog.target.com
   ``
3. A compromised subdomain could steal session cookies set on the parent domain

### Step 5: Check for Sensitive Data in Non-Session Cookies

**CLI Actions:**
1. Use `curl` to list all cookies being set
2. Use `base64 -d` on cookie values to check for encoded sensitive data
3. Look for cookies containing: usernames, emails, roles, preferences with PII

## Payloads

Not applicable - this is a configuration analysis test.

## Detection Criteria

A finding should be logged when:
- Session cookie is missing `HttpOnly` flag
- Session cookie is missing `Secure` flag
- Session cookie is missing `SameSite` attribute or set to `None` without necessity
- Cookie `Domain` is set too broadly
- Cookie `Path` is set to `/` when it could be more restrictive
- Cookies contain sensitive data in cleartext or easily decodable format
- "Remember me" cookies have excessively long expiration

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Session cookie missing HttpOnly (XSS can steal sessions) | Medium |
| Session cookie missing Secure flag | Medium |
| SameSite=None without Secure flag | Medium |
| Cookie Domain set too broadly | Low |
| Missing SameSite attribute | Low |
| Sensitive data in non-HttpOnly cookies | Medium |
| Persistent session cookie with very long expiry | Low |

## Remediation

- Set `HttpOnly` on all session cookies
- Set `Secure` on all cookies in HTTPS applications
- Set `SameSite=Lax` (or `Strict`) on all cookies
- Restrict `Domain` to the specific application subdomain
- Restrict `Path` to the application directory
- Avoid storing sensitive data in cookies
- Set reasonable `Max-Age` for persistent cookies

**Example secure Set-Cookie header:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800
```

## References

- [OWASP Testing Guide - Cookie Attributes](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

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

- V3 Session Management — fixation, timeout, secure cookie flags.
- V2 Authentication — session binding to client fingerprint where applicable.

## CWE references

- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``auth_login``

## Test focus

- Test cookie flags, rotation on login, and concurrent session limits.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

