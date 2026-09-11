---
id: WSTG-CRYP-03
title: Testing for Sensitive Information Sent via Unencrypted Channels
category: Cryptography
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels
---

# WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels

## Summary

Sensitive information such as credentials, session tokens, personal data, financial details, and API keys must be transmitted over encrypted channels (HTTPS/TLS). When data is sent over unencrypted HTTP, it can be intercepted by attackers on the network path through packet sniffing, man-in-the-middle attacks, or compromised network infrastructure. Mixed content scenarios (HTTPS pages loading HTTP resources) also weaken the security posture.

## Test Objectives

- Identify sensitive data transmitted over unencrypted HTTP
- Detect mixed content issues on HTTPS pages
- Verify that login forms and authentication endpoints use HTTPS
- Check that cookies with sensitive data have the Secure flag set
- Identify API endpoints accepting or returning sensitive data over HTTP

## Prerequisites

- Target application is accessible through Docker pentest container
- Application functionality has been mapped, including login flows and data submission forms
- Both HTTP and HTTPS endpoints should be tested

## Test Steps

### Step 1: Check for HTTP Login and Authentication Pages

**CLI Actions:**
Use `curl` to test if authentication endpoints are accessible over HTTP:

```
POST http://target.com/login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=testuser&password=testpassword
```

```
POST http://target.com/api/auth HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "testuser", "password": "testpassword"}
```

Check if the application accepts credentials over HTTP without redirecting to HTTPS.

### Step 2: Scan Proxy History for HTTP Traffic with Sensitive Data

**CLI Actions:**
Use `curl` to search for sensitive data transmitted over HTTP:

- Pattern: `password=` (credentials in plaintext HTTP requests)
- Pattern: `credit.?card|card.?number|ccnum` (payment data)
- Pattern: `ssn|social.?security` (personal identifiers)
- Pattern: `api[_-]?key|apikey|secret[_-]?key` (API keys)
- Pattern: `token=|auth=|session=` (authentication tokens)

Use `curl` to review all captured traffic and filter for HTTP (non-HTTPS) requests containing form submissions or JSON payloads.

### Step 3: Detect Mixed Content

**CLI Actions:**
Use `curl` to fetch HTTPS pages:

```
GET / HTTP/1.1
Host: target.com
```

Examine the response body for references to HTTP resources:

- `<script src="http://...">` (active mixed content - highest risk)
- `<link href="http://...">` (active mixed content for CSS)
- `<iframe src="http://...">`(active mixed content)
- `<img src="http://...">` (passive mixed content)
- `<video src="http://...">` (passive mixed content)

Use `curl` with pattern `http://` to find HTTP resource loads from HTTPS pages.

### Step 4: Check Cookie Security Flags

**CLI Actions:**
Use `curl` to perform authentication and examine `Set-Cookie` headers:

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=testuser&password=testpassword
```

Check each `Set-Cookie` header for:
- `Secure` flag (cookie only sent over HTTPS)
- `HttpOnly` flag (cookie not accessible via JavaScript)

Cookies containing session IDs or authentication tokens without the `Secure` flag will be sent over HTTP if the user visits an HTTP page.

### Step 5: Test HTTP to HTTPS Redirect Behavior

**CLI Actions:**
Use `curl` to access sensitive pages over HTTP:

```
GET /account/profile HTTP/1.0
Host: target.com
```

```
GET /api/user/details HTTP/1.0
Host: target.com
```

```
GET /checkout HTTP/1.0
Host: target.com
```

Check if:
- A 301/302 redirect to HTTPS occurs
- Any sensitive data is included in the HTTP response before redirect
- The redirect uses 301 (permanent) rather than 302 (temporary)

### Step 6: Check for Sensitive Data in URL Parameters

**CLI Actions:**
Use `curl` to find sensitive data passed in URLs:

- Pattern: `\?.*password=`
- Pattern: `\?.*token=`
- Pattern: `\?.*key=`
- Pattern: `\?.*secret=`

URLs are logged in browser history, server logs, and Referer headers, making URL parameters a dangerous channel for sensitive data even over HTTPS.

### Step 7: Check Email and Password Reset Links

**CLI Actions:**
Use `curl` to trigger password reset flows:

```
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=testuser@example.com
```

Verify that any password reset links generated use HTTPS, not HTTP.

## Payloads

Not applicable - this is a traffic analysis and configuration review test.

## Detection Criteria

A finding should be logged when:
- Login forms or authentication endpoints accept credentials over HTTP
- Session cookies lack the `Secure` flag
- Sensitive personal or financial data is transmitted over HTTP
- HTTPS pages load scripts, stylesheets, or iframes over HTTP (active mixed content)
- Password reset or verification links use HTTP
- API endpoints return sensitive data over HTTP
- Sensitive data appears in URL parameters (even over HTTPS)
- No HTTP to HTTPS redirect exists for sensitive pages

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Login credentials submitted over HTTP | High |
| Session tokens transmitted over HTTP (cookies without Secure flag) | High |
| Payment or financial data sent over HTTP | High |
| Active mixed content (scripts/CSS/iframes loaded over HTTP on HTTPS pages) | Medium |
| Sensitive personal data (PII) sent over HTTP | Medium |
| Password reset links use HTTP | Medium |
| API keys or secrets transmitted over HTTP | Medium |
| Passive mixed content (images/video over HTTP on HTTPS pages) | Low |
| Sensitive data in URL parameters over HTTPS | Low |
| HTTP available but immediately redirects to HTTPS with HSTS | Informational |

## Remediation

- Enforce HTTPS for all pages, especially authentication and sensitive data endpoints
- Set the `Secure` flag on all cookies containing session or authentication data
- Implement HSTS with `max-age >= 31536000`, `includeSubDomains`, and `preload`
- Redirect all HTTP requests to HTTPS with 301 (permanent) redirects
- Eliminate all mixed content by updating resource references to HTTPS or protocol-relative URLs
- Use `Content-Security-Policy: upgrade-insecure-requests` to automatically upgrade HTTP to HTTPS
- Never transmit sensitive data in URL parameters
- Configure web servers to reject HTTP entirely on sensitive endpoints if possible
- Ensure password reset and verification links use HTTPS

## References

- [OWASP Testing Guide - Sensitive Information via Unencrypted Channels](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

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

- V6 Stored Cryptography — algorithms, keys, and randomness.
- V9 Communications — TLS configuration and HSTS.

## CWE references

- CWE-326: Inadequate Encryption Strength
- CWE-327: Broken Crypto Algorithm

## Rynix tooling

- Primary tools: ``http_probe``, ``record_finding``

## Test focus

- Verify TLS versions, cipher suites, and sensitive data not in cleartext.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

