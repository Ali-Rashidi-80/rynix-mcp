---
id: WSTG-SESS-04
title: Testing for Exposed Session Variables
category: Session Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables
---

# WSTG-SESS-04: Testing for Exposed Session Variables

## Summary

Session tokens must be treated as sensitive credentials and protected from exposure. When session tokens appear in URLs, are transmitted via insecure channels, or leak through Referer headers, server logs, or browser history, attackers can intercept them to hijack user sessions. This test evaluates whether session variables are exposed through insecure transport or storage mechanisms.

## Test Objectives

- Identify if session tokens appear in URLs (query strings or path parameters)
- Test for session token leakage via Referer headers to third-party sites
- Verify that session tokens are only transmitted over encrypted channels (HTTPS)
- Check for session token exposure in server logs, caches, or error messages

## Prerequisites

- Target application has session management with authentication
- Docker pentest container capturing all application traffic
- An authenticated session for testing

## Test Steps

### Step 1: Check for Session Tokens in URLs

**CLI Actions:**
1. Use `curl` with pattern `\?(.*)(session|sid|token|JSESSIONID|PHPSESSID|ASP\.NET_SessionId)=` to find session tokens in query strings
2. Use `curl` with pattern `;(jsessionid|session)=` to find session tokens in URL path parameters (Java-style)
3. Examine all captured URLs in `curl` for any requests containing session identifiers in the URL
4. If tokens appear in URLs, they will be:
   - Stored in browser history
   - Visible in server access logs
   - Potentially cached by proxy servers
   - Leaked via the Referer header

### Step 2: Test Referer Header Leakage

**CLI Actions:**
1. After authenticating, navigate to a page that contains links to external sites
2. Click an external link and use `curl` to capture the outgoing request
3. Examine the `Referer` header in the outgoing request:
   ``
   Referer: https://target.com/dashboard?session=abc123
   ``
4. Use `curl` with pattern `Referer:.*[?&;](session|sid|token|JSESSIONID|PHPSESSID|access_token)=` to detect any Referer-based leakage
5. If the Referer header contains a session token, the token is exposed to the external site

### Step 3: Test for Insecure Transmission (HTTP vs HTTPS)

**CLI Actions:**
1. Use `curl` to check if any requests containing session cookies are sent over HTTP (not HTTPS)
2. Use `curl` to attempt accessing the application over plain HTTP:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session_token>
   ``
3. Check if the application redirects HTTP to HTTPS or if it serves content over HTTP with the session cookie attached
4. Use `curl` with pattern `^GET http://` to find any plaintext HTTP requests carrying session data

### Step 4: Check for Tokens in Response Bodies and Error Messages

**CLI Actions:**
1. Use `curl` with pattern `(session_id|sessionId|session_token|access_token)\s*[:=]\s*["\']?[a-zA-Z0-9._-]+` in response bodies to find tokens exposed in HTML, JSON, or error messages
2. Trigger error conditions and use `curl` to check if error pages expose session information:
   ``
   GET /nonexistent-page HTTP/1.1
   Host: target.com
   Cookie: session=<valid_token>
   ``
3. Check for debug pages or stack traces that may contain session data

### Step 5: Test for Tokens in Cached Content

**CLI Actions:**
1. Use `curl` to examine response headers for caching directives on authenticated pages
2. Look for missing or permissive cache headers on pages containing session data:
   - `Cache-Control: no-store` should be present
   - `Pragma: no-cache` for HTTP/1.0 compatibility
3. Use `curl` to check if authenticated pages are cacheable:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<valid_token>
   ``
4. Examine response for: `Cache-Control`, `Pragma`, `Expires`, and `ETag` headers

### Step 6: Test for Token Exposure in Cross-Origin Requests

**CLI Actions:**
1. Use `curl` to identify any cross-origin requests that include session cookies
2. Check if `Access-Control-Allow-Credentials: true` is combined with a permissive `Access-Control-Allow-Origin` header
3. Use `curl` to test if session cookies are included in cross-origin AJAX requests:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Origin: https://evil.com
   Cookie: session=<valid_token>
   ``
4. If the response includes `Access-Control-Allow-Origin: https://evil.com` with `Access-Control-Allow-Credentials: true`, session data can be read cross-origin

## Payloads

Not applicable - this is an analysis and observation test focused on examining traffic patterns rather than injecting payloads.

## Detection Criteria

A finding should be logged when:
- Session tokens appear in URL query strings or path parameters
- Session tokens leak via Referer headers to external domains
- Session cookies are transmitted over unencrypted HTTP connections
- Session tokens appear in response bodies, error messages, or debug output
- Authenticated pages lack proper cache-control headers
- CORS configuration allows cross-origin credential access from untrusted origins
- Session tokens are included in client-side JavaScript variables accessible to third-party scripts

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Session token in URL and leaks via Referer to external sites | High |
| Session cookie transmitted over HTTP (no Secure flag, no HSTS) | High |
| Session token exposed in CORS response to untrusted origin with credentials | High |
| Session token visible in URL query string (browser history, logs) | Medium |
| Session token in error messages or debug output | Medium |
| Authenticated pages missing cache-control headers | Low |
| Session token in URL path parameter (less visible than query string) | Medium |
| Referrer-Policy header missing but no external links on sensitive pages | Low |

## Remediation

- Never include session tokens in URLs (query strings or path parameters)
- Use cookie-based session management with `HttpOnly`, `Secure`, and `SameSite` attributes
- Set `Referrer-Policy: no-referrer` or `Referrer-Policy: strict-origin-when-cross-origin` headers
- Enforce HTTPS with HSTS (HTTP Strict Transport Security)
- Set `Cache-Control: no-store` on all authenticated responses
- Avoid exposing session data in error messages or debug output
- Configure CORS restrictively: never reflect arbitrary origins with `Access-Control-Allow-Credentials: true`
- Sanitize server logs to remove or mask session tokens

## References

- [OWASP Testing Guide - Exposed Session Variables](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables)
- [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

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

