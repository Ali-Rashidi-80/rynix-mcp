---
id: WSTG-CONF-07
title: Test HTTP Strict Transport Security
category: Configuration and Deployment Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security
---

# WSTG-CONF-07: Test HTTP Strict Transport Security

## Summary

HTTP Strict Transport Security (HSTS) is a security mechanism that instructs web browsers to only communicate with the server over HTTPS, preventing protocol downgrade attacks and cookie hijacking. When a server sends the `Strict-Transport-Security` header, compliant browsers will automatically convert all HTTP requests to HTTPS for that domain. Without HSTS, users are vulnerable to man-in-the-middle attacks during the initial HTTP-to-HTTPS redirect, SSL stripping attacks, and accidental transmission of sensitive data over unencrypted connections.

## Test Objectives

- Determine if the HSTS header is present in responses
- Validate the HSTS header configuration (max-age, includeSubDomains, preload)
- Check if the HSTS max-age value provides adequate protection
- Assess if the domain is included in the HSTS preload list
- Verify HTTP-to-HTTPS redirection behavior

## Prerequisites

- Target URL is accessible via `http_probe`
- Target uses HTTPS

## Test Steps

### Step 1: Check for HSTS Header on HTTPS Responses

**CLI Actions:**
1. Use `curl` to request the site over HTTPS and check for the HSTS header:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Examine the response for the `Strict-Transport-Security` header
3. Record the full header value including all directives
4. Test multiple pages to confirm HSTS is consistently applied:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
   ``
   GET /api/ HTTP/1.1
   Host: target.com
   ``
5. Use `curl` to review HSTS headers across all previously browsed HTTPS responses

### Step 2: Validate HSTS Header Directives

**CLI Actions:**
1. Parse the `Strict-Transport-Security` header value from Step 1
2. Check the following directives:
   - `max-age` - Should be at least 31536000 (1 year) for production sites
   - `includeSubDomains` - Should be present to protect all subdomains
   - `preload` - Optional but recommended for HSTS preload list inclusion
3. Example of a strong HSTS header:
   ``
   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
   ``
4. Flag weak configurations:
   - `max-age=0` disables HSTS
   - `max-age` less than 15768000 (6 months) is considered weak
   - Missing `includeSubDomains` leaves subdomains vulnerable

### Step 3: Test HTTP-to-HTTPS Redirect Behavior

**CLI Actions:**
1. Use `curl` to request the site over HTTP (port 80) and check redirection:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
   (Send to HTTP, not HTTPS)
2. Verify the response is a 301 (permanent redirect) to the HTTPS version, not a 302 (temporary)
3. Check that the HSTS header is NOT present in the HTTP response (it should only appear in HTTPS responses, as per RFC 6797)
4. Verify the redirect target uses HTTPS:
   - `Location: https://target.com/` (correct)
   - `Location: http://target.com/` (incorrect - redirecting to HTTP again)

### Step 4: Check HSTS on Subdomains

**CLI Actions:**
1. If `includeSubDomains` is set, use `curl` to verify subdomains also use HTTPS:
   ``
   GET / HTTP/1.1
   Host: www.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: api.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: mail.target.com
   ``
2. Check if subdomains also return the HSTS header
3. Check if any subdomains are HTTP-only, which would be broken by `includeSubDomains`

### Step 5: Check HSTS Preload Status

**CLI Actions:**
1. Use `curl` to confirm the HSTS header includes all three directives required for preload:
   - `max-age` of at least 31536000
   - `includeSubDomains`
   - `preload`
2. Note: Actual preload list verification requires checking the HSTS preload list at hstspreload.org (outside Rynix scope), but the header can be validated for preload eligibility

### Step 6: Test for HSTS Header Injection or Override

**CLI Actions:**
1. Use `curl` to check if the HSTS header can be influenced by request parameters:
   ``
   GET /?hsts=0 HTTP/1.1
   Host: target.com
   ``
2. Check for multiple `Strict-Transport-Security` headers in the response (conflicting headers may cause browser confusion)
3. Use `rynix_plugin_run('template-scan')` to check for any HSTS-related findings from the template-scan plugin

## Detection Criteria

A finding should be logged when:
- HSTS header is completely absent from HTTPS responses
- `max-age` value is less than 31536000 (1 year)
- `max-age` is set to 0 (HSTS disabled)
- `includeSubDomains` directive is missing
- HSTS header is sent over HTTP (ineffective and against RFC)
- HTTP-to-HTTPS redirect uses 302 instead of 301
- No redirect from HTTP to HTTPS exists at all
- HSTS is inconsistently applied across different endpoints

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No HSTS header and no HTTP-to-HTTPS redirect | Medium |
| No HSTS header but HTTPS redirect is present | Medium |
| HSTS present but max-age less than 6 months | Low |
| HSTS present but missing includeSubDomains | Low |
| HSTS present with adequate max-age but not preloaded | Low |
| HTTP redirect uses 302 instead of 301 | Low |

## Remediation

- Enable HSTS on all HTTPS responses with a strong `max-age` value:
  ``
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  ``
- Implement a 301 permanent redirect from HTTP to HTTPS
- Ensure all subdomains support HTTPS before adding `includeSubDomains`
- Submit the domain to the HSTS preload list at hstspreload.org for maximum protection
- Only send the HSTS header over HTTPS connections (not HTTP)
- Start with a short `max-age` during initial deployment and increase once confirmed stable
- Ensure all content, resources, and APIs are available over HTTPS

## References

- [OWASP Testing Guide - Test HTTP Strict Transport Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security)
- [RFC 6797: HTTP Strict Transport Security (HSTS)](https://tools.ietf.org/html/rfc6797)
- [HSTS Preload List Submission](https://hstspreload.org/)
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

