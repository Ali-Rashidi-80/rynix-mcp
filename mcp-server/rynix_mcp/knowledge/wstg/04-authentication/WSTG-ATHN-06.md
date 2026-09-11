---
id: WSTG-ATHN-06
title: Testing for Browser Cache Weaknesses
category: Authentication
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses
---

# WSTG-ATHN-06: Testing for Browser Cache Weaknesses

## Summary

Browsers and intermediate proxies cache web content to improve performance. When sensitive pages (login forms, account details, session tokens) are cached, they may be recoverable by other users of the same computer or by anyone with access to the proxy cache. Proper cache-control headers are essential to prevent sensitive data from being stored in browser history, disk cache, or shared proxy caches.

## Test Objectives

- Determine if sensitive pages are cached by the browser or proxies
- Check for proper Cache-Control and Pragma headers on authenticated pages
- Verify that the browser back button does not expose sensitive content after logout
- Test if shared proxy caches store authenticated content

## Prerequisites

- Target application has authentication and serves sensitive content
- Valid user account for testing
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Analyze Cache-Control Headers on Sensitive Pages

**CLI Actions:**
1. Log in and navigate to sensitive pages (account details, profile, dashboard)
2. Use `curl` to capture all responses from authenticated pages
3. Use `curl` with pattern `Cache-Control|Pragma|Expires` to find cache-related headers in responses
4. For each sensitive page, check the response headers using `curl`:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
5. Examine the response for these critical headers:
   - `Cache-Control: no-store, no-cache, must-revalidate`
   - `Pragma: no-cache`
   - `Expires: 0` or a past date

### Step 2: Test Login Page Caching

**CLI Actions:**
1. Use `curl` to fetch the login page and examine cache headers:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
2. Check if the login page response includes appropriate cache-control directives
3. If the login page uses pre-filled credentials from autocomplete, check for `autocomplete="off"` on the form
4. Test the login submission response cache headers:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
5. Verify the POST response and redirect contain no-cache directives

### Step 3: Test Sensitive API Endpoints

**CLI Actions:**
1. Use `curl` with pattern `/api/.*user|/api/.*account|/api/.*profile|/api/.*payment` to identify sensitive API endpoints
2. Use `curl` to request each sensitive API endpoint and examine headers:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
3. Check for `Cache-Control: no-store` on API responses containing personal data
4. Test API responses that return sensitive data like tokens, PII, or financial information:
   ``
   GET /api/user/payment-methods HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
5. Verify that responses with sensitive data include `Cache-Control: private, no-store`

### Step 4: Test Back Button Behavior After Logout

**CLI Actions:**
1. Log in and navigate to a sensitive page
2. Use `curl` to capture the sensitive page response
3. Log out of the application
4. Use `curl` to re-request the sensitive page without session cookies (simulating back button with cached content):
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   ``
5. Check if the response returns the sensitive content or properly redirects to login
6. Test with conditional request headers that browsers use for cached content:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   If-Modified-Since: <date_from_original_response>
   If-None-Match: <etag_from_original_response>
   ``
7. A `304 Not Modified` response for sensitive content indicates a caching issue

### Step 5: Test ETag and Last-Modified Behavior

**CLI Actions:**
1. Use `curl` to request a sensitive page and note any `ETag` or `Last-Modified` headers:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
2. If an ETag is present, test if it leaks information or enables cache-based tracking
3. Check if ETags persist across different authenticated sessions (different users):
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<different_user_session>
   ``
4. Use `rynix_plugin_run('template-scan')` to check for any cacheable response findings from the template-scan plugin

### Step 6: Test HTTPS vs HTTP Cache Differences

**CLI Actions:**
1. Use `curl` to compare cache headers between HTTP and HTTPS responses:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
2. Check if the application sends different cache-control directives for HTTP vs HTTPS
3. Verify that HTTPS responses for sensitive pages include `Cache-Control: no-store` to prevent proxy caching
4. Test if intermediate proxy caching can be triggered by manipulating the request:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Cache-Control: max-age=3600
   ``

## Payloads

Not applicable - this is a configuration and header analysis test.

## Detection Criteria

A finding should be logged when:
- Sensitive pages lack `Cache-Control: no-store` header
- `Pragma: no-cache` is missing from sensitive page responses
- `Expires` header is set to a future date on authenticated pages
- The login page can be cached with pre-filled credentials
- API responses containing PII or tokens are cacheable
- Back button exposes sensitive content after logout (304 Not Modified)
- ETags on sensitive pages enable tracking or information leakage
- Different cache policies exist for HTTP vs HTTPS versions of the same page

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Sensitive data (PII, financial) cached without no-store directive | Medium |
| Authentication tokens or credentials in cacheable responses | Medium |
| Login page cached with autocomplete-enabled password fields | Medium |
| Sensitive API responses missing Cache-Control headers | Medium |
| Back button displays sensitive content after logout | Low |
| ETag tracking across sessions on sensitive pages | Low |
| Static assets on authenticated pages missing cache headers | Low |

## Remediation

- Add `Cache-Control: no-store, no-cache, must-revalidate, private` to all sensitive page responses
- Add `Pragma: no-cache` for HTTP/1.0 compatibility
- Set `Expires: 0` or a past date on sensitive responses
- Use `autocomplete="off"` on login forms and sensitive input fields
- Ensure API responses containing sensitive data include `Cache-Control: no-store`
- Implement proper logout that invalidates server-side sessions (preventing back-button reuse)
- Remove unnecessary ETags from sensitive page responses
- Configure reverse proxies and CDNs to respect no-cache directives for authenticated content
- Consider using `Clear-Site-Data` header on logout responses

## References

- [OWASP Testing Guide - Browser Cache Weaknesses](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses)
- [CWE-525: Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
- [CWE-524: Use of Cache that Contains Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)

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

- V2 Authentication — credential storage, lockout, MFA.
- V3 Session Management — session binding and rotation.

## CWE references

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-798: Use of Hard-coded Credentials

## Rynix tooling

- Primary tools: ``auth_login``, ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test password policy, lockout, and MFA bypass paths.
- Verify tokens/sessions invalidated on logout and password change.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

