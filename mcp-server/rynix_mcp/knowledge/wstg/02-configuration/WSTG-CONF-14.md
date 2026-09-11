---
id: WSTG-CONF-14
title: Test Other HTTP Security Header Misconfigurations
category: Configuration and Deployment Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_for_HTTP_Header_Security
---

# WSTG-CONF-14: Test Other HTTP Security Header Misconfigurations

## Summary

HTTP security headers provide an additional layer of defense by instructing browsers to enable security mechanisms such as clickjacking protection, MIME-type enforcement, referrer control, and feature restrictions. Missing or misconfigured security headers leave users vulnerable to a range of client-side attacks. This test covers security headers beyond HSTS (WSTG-CONF-07) and CSP (WSTG-CONF-12), including X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin headers, and Cache-Control directives.

## Test Objectives

- Identify missing HTTP security headers across application responses
- Assess the correctness of present security header configurations
- Determine if misconfigured headers enable specific attack vectors
- Verify consistent application of security headers across all endpoints

## Prerequisites

- Target URL is accessible via `http_probe`
- Application has been browsed to build a baseline of responses

## Test Steps

### Step 1: Check X-Frame-Options Header

**CLI Actions:**
1. Use `curl` to request the target page and inspect X-Frame-Options:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check for the `X-Frame-Options` header in the response:
   - `DENY` - Page cannot be displayed in a frame (most secure)
   - `SAMEORIGIN` - Page can only be framed by the same origin (acceptable)
   - `ALLOW-FROM uri` - Page can be framed by the specified URI (deprecated in modern browsers)
3. Test multiple pages, especially authentication and sensitive action pages:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
   ``
   GET /account/settings HTTP/1.1
   Host: target.com
   ``
   ``
   GET /transfer HTTP/1.1
   Host: target.com
   ``
4. Missing X-Frame-Options makes the page vulnerable to clickjacking attacks
5. Note: `frame-ancestors` in CSP supersedes X-Frame-Options in modern browsers

### Step 2: Check X-Content-Type-Options Header

**CLI Actions:**
1. Use `curl` to check for the X-Content-Type-Options header:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. The only valid value is `nosniff`:
   ``
   X-Content-Type-Options: nosniff
   ``
3. Without this header, browsers may perform MIME-type sniffing, potentially treating a text file as HTML or JavaScript, enabling XSS attacks
4. Check this header on pages that serve user-uploaded content:
   ``
   GET /uploads/userfile.txt HTTP/1.1
   Host: target.com
   ``
5. Use `curl` to verify the header is consistently present across all responses

### Step 3: Check Referrer-Policy Header

**CLI Actions:**
1. Use `curl` to check for the Referrer-Policy header:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Evaluate the policy value:
   - `no-referrer` - Never send the referrer (most private)
   - `no-referrer-when-downgrade` - Default browser behavior
   - `origin` - Only send the origin, not the full URL
   - `origin-when-cross-origin` - Full URL for same-origin, origin only for cross-origin
   - `same-origin` - Full referrer for same-origin, nothing for cross-origin
   - `strict-origin` - Origin only when protocol stays the same, nothing on downgrade
   - `strict-origin-when-cross-origin` - Recommended policy
   - `unsafe-url` - Always send the full URL (dangerous - leaks sensitive URL parameters)
3. `unsafe-url` is particularly dangerous on pages with sensitive URL parameters (tokens, session IDs)

### Step 4: Check Permissions-Policy (Feature-Policy) Header

**CLI Actions:**
1. Use `curl` to check for the Permissions-Policy header:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Also check for the deprecated `Feature-Policy` header
3. Evaluate which browser features are controlled:
   ``
   Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
   ``
4. Key features to restrict:
   - `camera` - Camera access
   - `microphone` - Microphone access
   - `geolocation` - Location access
   - `payment` - Payment Request API
   - `usb` - USB device access
   - `accelerometer`, `gyroscope`, `magnetometer` - Sensor access
   - `interest-cohort` - FLoC/Topics API (privacy)
5. Missing Permissions-Policy means embedded third-party iframes can potentially access these features

### Step 5: Check Cross-Origin Headers

**CLI Actions:**
1. Use `curl` to check for cross-origin isolation headers:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check for:
   - `Cross-Origin-Opener-Policy` (COOP):
     - `same-origin` - Isolates the browsing context (recommended)
     - `same-origin-allow-popups` - Allows popups from same origin
     - `unsafe-none` - No isolation (default, less secure)
   - `Cross-Origin-Embedder-Policy` (COEP):
     - `require-corp` - Only load resources with CORP headers or CORS
     - `credentialless` - Loads cross-origin resources without credentials
     - `unsafe-none` - Default, no restrictions
   - `Cross-Origin-Resource-Policy` (CORP):
     - `same-origin` - Only same-origin can load the resource
     - `same-site` - Same-site can load the resource
     - `cross-origin` - Any origin can load the resource
3. These headers protect against Spectre-like side-channel attacks and cross-origin information leaks

### Step 6: Check Cache-Control Headers for Sensitive Pages

**CLI Actions:**
1. Use `curl` to request pages that contain sensitive data:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid-session>
   ``
   ``
   GET /api/user/details HTTP/1.1
   Host: target.com
   Authorization: Bearer <token>
   ``
2. Check for appropriate cache control headers:
   - `Cache-Control: no-store` - Response must not be cached (most secure for sensitive data)
   - `Cache-Control: no-cache` - Requires revalidation before use
   - `Cache-Control: private` - Only browser cache, not shared caches
   - `Pragma: no-cache` - HTTP/1.0 backward compatibility
3. Sensitive pages without `no-store` or `no-cache` may be stored in proxy caches, browser caches, or CDN caches, potentially exposing user data

### Step 7: Check X-Permitted-Cross-Domain-Policies Header

**CLI Actions:**
1. Use `curl` to check for the X-Permitted-Cross-Domain-Policies header:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Valid values:
   - `none` - No cross-domain policy files are allowed (most restrictive)
   - `master-only` - Only the master policy file is allowed
   - `all` - All policy files are allowed (least restrictive)
3. This header controls Adobe Flash and PDF cross-domain behavior

### Step 8: Aggregate Header Analysis Across the Application

**CLI Actions:**
1. Use `curl` to review all responses and build a comprehensive view of security header coverage
2. Use `curl` to search for specific headers across all responses:
   - Pattern: `X-Frame-Options:`
   - Pattern: `X-Content-Type-Options:`
   - Pattern: `Referrer-Policy:`
   - Pattern: `Permissions-Policy:|Feature-Policy:`
   - Pattern: `Cross-Origin-Opener-Policy:`
   - Pattern: `Cache-Control:.*no-store`
3. Identify pages that are missing headers compared to others (inconsistent implementation)
4. Use `rynix_plugin_run('template-scan')` to check for any security header findings from the template-scan plugin

## Detection Criteria

A finding should be logged when:
- X-Frame-Options is missing on pages performing sensitive actions (clickjacking risk)
- X-Content-Type-Options: nosniff is missing, especially on pages serving user content
- Referrer-Policy is set to `unsafe-url` or is missing entirely
- Permissions-Policy is absent, allowing unrestricted feature access by embedded content
- Cache-Control headers do not prevent caching of sensitive authenticated responses
- Cross-Origin headers are missing, leaving the application vulnerable to cross-origin attacks
- Security headers are inconsistently applied across endpoints
- Deprecated header values are used (e.g., X-Frame-Options: ALLOW-FROM)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Missing X-Frame-Options on pages with state-changing actions | Medium |
| Sensitive pages cacheable without Cache-Control restrictions | Medium |
| Referrer-Policy set to unsafe-url on pages with sensitive URL parameters | Medium |
| Missing X-Content-Type-Options on pages serving user-uploaded content | Medium |
| Missing Permissions-Policy when third-party iframes are embedded | Low |
| Missing Cross-Origin isolation headers (COOP/COEP) | Low |
| Security headers present on some pages but missing on others | Low |
| Missing X-Permitted-Cross-Domain-Policies header | Low |

## Remediation

- Add the following security headers to all HTTP responses:
  ``
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Cross-Origin-Opener-Policy: same-origin
  X-Permitted-Cross-Domain-Policies: none
  ``
- Add cache control headers to all authenticated/sensitive responses:
  ``
  Cache-Control: no-store, no-cache, must-revalidate, private
  Pragma: no-cache
  ``
- Implement security headers at the reverse proxy or web server level to ensure consistent application
- Use CSP `frame-ancestors` directive as a modern replacement for X-Frame-Options
- Regularly audit security headers using automated scanning tools
- Test security headers across all content types and endpoints, not just HTML pages
- Consider using the `Cross-Origin-Embedder-Policy: require-corp` header if cross-origin isolation is needed

## References

- [OWASP Testing Guide - Test for HTTP Security Headers](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_for_HTTP_Header_Security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
- [CWE-524: Use of Cache that Contains Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)
- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
- [Mozilla Observatory](https://observatory.mozilla.org/)

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

