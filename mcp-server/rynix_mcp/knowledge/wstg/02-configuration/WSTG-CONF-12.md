---
id: WSTG-CONF-12
title: Test for Content Security Policy
category: Configuration and Deployment Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy
---

# WSTG-CONF-12: Test for Content Security Policy

## Summary

Content Security Policy (CSP) is a security header that helps prevent XSS, clickjacking, and other code injection attacks by specifying which content sources are trusted. A weak or missing CSP significantly increases the risk of client-side attacks.

## Test Objectives

- Determine if a CSP header is present
- Assess the strength and correctness of the CSP policy
- Identify misconfigurations that could be exploited to bypass the CSP

## Prerequisites

- Target URL is accessible via `http_probe`

## Test Steps

### Step 1: Check for CSP Header Presence

**CLI Actions:**
1. Use `curl` to request the target page:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check response headers for:
   - `Content-Security-Policy`
   - `Content-Security-Policy-Report-Only`
   - `X-Content-Security-Policy` (deprecated)
   - `X-WebKit-CSP` (deprecated)
3. Check the HTML source for `<meta http-equiv="Content-Security-Policy">` tags
4. Repeat for multiple pages - CSP may vary across endpoints

### Step 2: Analyze CSP Directives

Review each directive in the CSP header:

**Key Directives to Check:**
- `default-src` - Fallback for other directives
- `script-src` - Controls script sources (most critical)
- `style-src` - Controls stylesheet sources
- `img-src` - Controls image sources
- `connect-src` - Controls XHR/fetch destinations
- `frame-src` / `frame-ancestors` - Controls framing (clickjacking protection)
- `object-src` - Controls plugin sources (Flash, Java)
- `base-uri` - Controls `<base>` tag values
- `form-action` - Controls form submission targets

### Step 3: Check for Common CSP Weaknesses

**CLI Actions:**
1. Use `curl` to test pages and look for these weaknesses in the CSP:

**Dangerous Patterns:**
- `unsafe-inline` in `script-src` - Allows inline scripts, defeating XSS protection
- `unsafe-eval` in `script-src` - Allows `eval()`, `setTimeout('string')`, etc.
- `*` wildcard - Allows any source
- `data:` in `script-src` - Allows `data:` URI scripts
- `https:` as broad source - Any HTTPS source is trusted
- Missing `object-src` - Defaults to `default-src`, plugins may be allowed
- Missing `base-uri` - DOM clobbering via `<base>` tag possible
- Missing `frame-ancestors` - Clickjacking possible

### Step 4: Test CSP Bypass via Allowed Domains

**CLI Actions:**
1. If the CSP allows specific CDN domains, check if they host JSONP endpoints or Angular/Vue libraries that could be abused
2. Use `curl` to verify if whitelisted domains serve user-controllable content
3. Common bypassable domains:
   - `*.googleapis.com` (JSONP endpoints)
   - `*.cloudflare.com`
   - `*.amazonaws.com` (S3 buckets)
   - Any domain serving JSONP callbacks

### Step 5: Check for Report-Only Mode

**CLI Actions:**
1. If only `Content-Security-Policy-Report-Only` is present (no enforcing `Content-Security-Policy`), the CSP is not blocking any attacks - only reporting
2. This means the CSP provides no actual protection

## Payloads

Not directly applicable - this is a configuration review test. However, if CSP weaknesses are found, reference the XSS tests (WSTG-INPV-01, WSTG-INPV-02) for exploitation.

## Detection Criteria

A finding should be logged when:
- No CSP header is present at all
- CSP contains `unsafe-inline` or `unsafe-eval` in `script-src`
- CSP uses overly broad wildcards (`*`, `https:`)
- CSP is in report-only mode without an enforcing policy
- `frame-ancestors` is missing (clickjacking risk)
- CSP allows known bypassable domains (CDNs with JSONP)
- `object-src` is not restricted

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No CSP header at all | Medium |
| `unsafe-inline` + `unsafe-eval` in script-src | Medium |
| CSP in report-only mode only | Medium |
| Missing `frame-ancestors` (clickjacking) | Low |
| Overly broad wildcards but no `unsafe-inline` | Low |
| Strong CSP with minor improvements possible | Informational |

## Remediation

- Implement a strict CSP with `script-src` using nonces or hashes instead of `unsafe-inline`
- Remove `unsafe-eval` and refactor code to avoid `eval()`
- Set `object-src 'none'` to prevent plugin abuse
- Set `base-uri 'self'` to prevent base tag injection
- Set `frame-ancestors 'self'` or `'none'` to prevent clickjacking
- Avoid wildcard domains - whitelist specific needed domains
- Use enforcing mode, not just report-only
- Regularly review and tighten the CSP as the application evolves

## References

- [OWASP Testing Guide - Content Security Policy](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy)
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

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

