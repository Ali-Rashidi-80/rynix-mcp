---
id: WSTG-ATHN-01
title: Testing for Credentials Transported over an Encrypted Channel
category: Authentication
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel
---

# WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel

## Summary

Credentials (usernames, passwords, tokens) must always be transmitted over encrypted channels (HTTPS/TLS). If credentials are sent over HTTP, they can be intercepted via network sniffing or man-in-the-middle attacks.

## Test Objectives

- Determine if credentials are transmitted over encrypted channels
- Check if the application forces HTTPS for authentication
- Verify that no credential-related traffic falls back to HTTP

## Prerequisites

- Target application has authentication functionality
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Check Login Form Action URL

**CLI Actions:**
1. Use `curl` to fetch the login page over HTTP:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
2. Check if the login form's `action` attribute uses `https://` or a relative URL
3. Use `curl` to fetch the same page over HTTPS and compare

### Step 2: Test Login Submission over HTTP

**CLI Actions:**
1. Use `curl` to submit credentials over HTTP:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=test&password=test123
   ``
2. Check if the server accepts the login attempt or redirects to HTTPS
3. If it accepts credentials over HTTP, this is a finding

### Step 3: Check HTTPS Redirect Behavior

**CLI Actions:**
1. Use `curl` to request the target over HTTP:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check if a 301/302 redirect to HTTPS occurs
3. Check for `Strict-Transport-Security` (HSTS) header in HTTPS responses

### Step 4: Check for Mixed Content

**CLI Actions:**
1. Use `curl` to review all captured requests
2. Look for any HTTP (non-HTTPS) requests made from HTTPS pages
3. Pay special attention to requests that carry authentication tokens or session cookies

### Step 5: Verify Token/Cookie Transmission

**CLI Actions:**
1. Use `curl` to find requests containing `Cookie` or `Authorization` headers
2. Check if any of these are sent over HTTP
3. Verify that session cookies have the `Secure` flag set

## Payloads

Not applicable - this is a configuration and transport security test.

## Detection Criteria

A finding should be logged when:
- Login form submits credentials over HTTP
- The application accepts authentication requests over HTTP
- No HTTP-to-HTTPS redirect exists for authentication pages
- HSTS header is missing from HTTPS responses
- Session cookies lack the `Secure` flag
- Authentication tokens are transmitted in HTTP requests

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Credentials submitted over HTTP (no HTTPS at all) | High |
| Login page served over HTTP, form posts to HTTPS | Medium |
| HSTS header missing (HTTPS exists but not enforced) | Medium |
| Session cookies missing Secure flag | Medium |
| Mixed content on authenticated pages | Low |

## Remediation

- Enforce HTTPS across the entire application
- Implement HSTS with a long max-age (e.g., `max-age=31536000; includeSubDomains`)
- Set the `Secure` flag on all session and authentication cookies
- Use 301 permanent redirects from HTTP to HTTPS
- Consider HSTS preloading for maximum protection
- Eliminate all mixed content

## References

- [OWASP Testing Guide - Credentials over Encrypted Channel](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

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

