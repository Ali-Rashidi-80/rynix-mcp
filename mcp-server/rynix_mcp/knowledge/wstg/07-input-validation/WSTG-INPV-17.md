---
id: WSTG-INPV-17
title: Testing for Host Header Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
---

# WSTG-INPV-17: Testing for Host Header Injection

## Summary

Host Header Injection occurs when an application trusts the value of the HTTP Host header for security-sensitive operations without proper validation. The Host header is user-controllable and can be manipulated to influence application behavior. Common attack scenarios include password reset poisoning (where the reset link contains an attacker-controlled domain), web cache poisoning (where the cached response reflects the injected host), and server-side request routing manipulation. Applications that generate absolute URLs using the Host header value, or that route requests based on virtual hosting, are particularly vulnerable.

## Test Objectives

- Determine if the application uses the Host header to generate URLs or make routing decisions
- Test if the Host header value can be manipulated to inject an attacker-controlled domain
- Identify password reset poisoning, cache poisoning, and SSRF via host header injection
- Assess whether alternative host headers (X-Forwarded-Host, X-Host) are processed

## Prerequisites

- Target application is accessible through Docker pentest container
- Application has features that generate absolute URLs (password reset, email links, canonical URLs)
- Docker pentest container capturing traffic
- Understanding of the application's virtual hosting and reverse proxy configuration

## Test Steps

### Step 1: Identify Host Header Usage

**CLI Actions:**
1. Use `curl` to identify features that generate absolute URLs:
   - Password reset functionality
   - Email notifications with links
   - Canonical URL meta tags
   - Sitemaps
   - OAuth/OpenID Connect redirect URIs
   - API documentation with base URLs
2. Use `save to manual-review file` for each endpoint that generates URLs

### Step 2: Test Basic Host Header Manipulation

**CLI Actions:**
Use `curl` to send requests with a modified Host header:

**Replace Host entirely:**
```
GET / HTTP/1.1
Host: evil.com
```

Check if the response contains `evil.com` in any generated URLs, links, or meta tags.

**Inject into password reset:**
```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

If the password reset email contains a link like `https://evil.com/reset?token=xxx`, the attacker can steal the reset token.

### Step 3: Test with Duplicate Host Headers

**CLI Actions:**
Use `curl` with two Host headers to see which one the application uses:

```
GET / HTTP/1.1
Host: target.com
Host: evil.com
```

Some servers use the first Host header for routing but the second for URL generation, or vice versa.

### Step 4: Test X-Forwarded-Host and Alternative Headers

**CLI Actions:**
Use `curl` to test alternative host headers that may override the Host:

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

```
GET / HTTP/1.1
Host: target.com
X-Host: evil.com
```

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Server: evil.com
```

```
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

```
GET / HTTP/1.1
Host: target.com
Forwarded: host=evil.com
```

Check if any of these headers override the Host value in generated URLs.

### Step 5: Test Password Reset Poisoning

**CLI Actions:**
1. Use `curl` to trigger a password reset with a manipulated host:

```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

2. Check the password reset email (if you control the victim email address) to see if the reset link points to `evil.com`
3. If so, a real attacker would receive the token when the victim clicks the link

### Step 6: Test Web Cache Poisoning via Host Header

**CLI Actions:**
Use `curl` to test if responses with injected host values get cached:

```
GET /static/page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

If the response reflects `evil.com` and includes cache headers (`Cache-Control`, `X-Cache: HIT`), subsequent users visiting the same page will receive the poisoned response.

1. Send the request with the injected host
2. Send a normal request to the same URL:
   ``
   GET /static/page HTTP/1.1
   Host: target.com
   ``
3. Check if the normal request returns the poisoned response (with `evil.com` in the content)

### Step 7: Test Host Header with Port and Special Characters

**CLI Actions:**
Use `curl` to test edge cases in host header parsing:

**Port injection:**
```
GET / HTTP/1.1
Host: target.com:evil.com
```

```
GET / HTTP/1.1
Host: target.com:@evil.com
```

```
GET / HTTP/1.1
Host: target.com:80@evil.com
```

**Absolute URL in request line:**
```
GET https://evil.com/ HTTP/1.1
Host: target.com
```

**Host with trailing dot:**
```
GET / HTTP/1.1
Host: target.com.
```

**Host with space injection:**
```
GET / HTTP/1.1
Host: target.com evil.com
```

### Step 8: Test Server-Side Routing Manipulation

**CLI Actions:**
Use `curl` to test if the Host header affects internal routing:

```
GET / HTTP/1.1
Host: localhost
```

```
GET / HTTP/1.1
Host: 127.0.0.1
```

```
GET / HTTP/1.1
Host: internal-app.local
```

```
GET /admin HTTP/1.1
Host: backend-service
```

If the application returns different content for different Host values, it may be possible to access internal virtual hosts or backend services.

Use `rynix_plugin_run('template-scan')` to check if template-scan has detected any host header injection issues.

## Payloads

### Basic Host Header Injection Payloads
```
Host: evil.com
Host: evil.com
Host: target.com
Host: evil.com
```

### Alternative Host Headers
```
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: host=evil.com
X-Original-URL: https://evil.com
X-Rewrite-URL: https://evil.com
```

### Host with Port Manipulation
```
Host: target.com:evil.com
Host: target.com:@evil.com
Host: target.com:80@evil.com
Host: target.com:443@evil.com
Host: evil.com:80
Host: evil.com:443
```

### Absolute URL in Request Line
```
GET https://evil.com/ HTTP/1.1
GET http://evil.com/ HTTP/1.1
GET @evil.com/ HTTP/1.1
```

### Internal Routing Payloads
```
Host: localhost
Host: 127.0.0.1
Host: 0.0.0.0
Host: [::1]
Host: internal-app
Host: backend
Host: admin.internal
Host: 169.254.169.254
```

### Duplicate Host Header Payloads
```
Host: target.com\r\nHost: evil.com
Host: target.com\r\nX-Forwarded-Host: evil.com
```

### Special Character Payloads
```
Host: target.com.
Host: target.com%00.evil.com
Host: target.com%20evil.com
Host: target.com\tevil.com
Host: target.com evil.com
```

### Password Reset Poisoning Payloads
```
Host: evil.com (on password reset endpoint)
X-Forwarded-Host: evil.com (on password reset endpoint)
Host: target.com\nX-Forwarded-Host: evil.com (on password reset endpoint)
```

## Detection Criteria

A finding should be logged when:
- The Host header value is reflected in generated URLs, links, or page content
- Password reset emails contain attacker-controlled domain in the reset link
- Alternative host headers (X-Forwarded-Host) override the Host value in URL generation
- Web cache poisoning is achievable through host header manipulation
- Internal virtual hosts or services are accessible via host header manipulation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Password reset token theft via host header poisoning | High |
| Web cache poisoning serves malicious content to all users | High |
| Access to internal services via host header routing | High |
| Host header reflected in URLs but no direct exploitation path | Medium |
| X-Forwarded-Host overrides Host but limited to informational | Medium |
| Host header reflected in meta tags only (limited impact) | Low |
| Different Host values return different content without security impact | Informational |

## Remediation

- Do not use the Host header to generate URLs in security-sensitive contexts
- Use a server-side configured base URL for generating absolute URLs (password resets, emails, canonical URLs)
- Validate the Host header against an allowlist of permitted values
- Ignore X-Forwarded-Host and similar headers unless explicitly required by trusted proxies
- Configure the web server to reject requests with unrecognized Host header values
- Use a default virtual host that returns an error for unrecognized Host headers
- For password resets, hardcode the application URL rather than deriving it from the request
- Implement cache key normalization that includes the Host header
- Set `Cache-Control: private` on responses that reflect the Host value

## References

- [OWASP Testing Guide - Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [technique Research - Web Cache Poisoning](https://owasp.org/research/practical-web-cache-poisoning)
- [CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

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

