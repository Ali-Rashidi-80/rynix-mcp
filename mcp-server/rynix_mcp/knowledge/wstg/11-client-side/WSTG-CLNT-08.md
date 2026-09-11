---
id: WSTG-CLNT-08
title: Testing for Clickjacking
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Clickjacking
---

# WSTG-CLNT-08: Testing for Clickjacking

## Summary

Clickjacking (UI redressing) is an attack where a transparent or disguised iframe of a target page is overlaid on a malicious page, tricking users into clicking on hidden elements of the target application. Victims believe they are interacting with the visible page but are actually clicking buttons, links, or form elements on the invisible target page. This can lead to unauthorized actions such as changing account settings, approving transactions, or enabling features.

## Test Objectives

- Check if the application can be framed by external pages
- Verify `X-Frame-Options` header configuration
- Verify `Content-Security-Policy frame-ancestors` directive
- Assess the sensitivity of actions that could be clickjacked
- Test for frame-busting JavaScript bypass

## Prerequisites

- Target application is accessible through Docker pentest container
- Application has state-changing functionality (settings, payments, approvals)

## Test Steps

### Step 1: Check X-Frame-Options Header

**CLI Actions:**
Use `curl` to request the target and check for framing protection headers:

```
GET / HTTP/1.1
Host: target.com
```

Check for `X-Frame-Options` header in the response:
- `DENY` - page cannot be framed at all (strongest protection)
- `SAMEORIGIN` - page can only be framed by same-origin pages
- `ALLOW-FROM uri` - page can be framed only by specified origin (deprecated)

### Step 2: Check Content-Security-Policy frame-ancestors

**CLI Actions:**
Use `curl` and check for CSP header:

```
GET / HTTP/1.1
Host: target.com
```

Look for `Content-Security-Policy` header containing `frame-ancestors` directive:
- `frame-ancestors 'none'` - equivalent to X-Frame-Options: DENY
- `frame-ancestors 'self'` - equivalent to X-Frame-Options: SAMEORIGIN
- `frame-ancestors https://trusted.com` - only specific origin

Note: `frame-ancestors` in CSP supersedes `X-Frame-Options`.

### Step 3: Check Multiple Pages for Consistent Protection

**CLI Actions:**
Use `curl` to check framing protection on different pages, especially sensitive ones:

```
GET /account/settings HTTP/1.1
Host: target.com
Cookie: session=<valid_session>
```

```
GET /transfer HTTP/1.1
Host: target.com
Cookie: session=<valid_session>
```

```
GET /admin/panel HTTP/1.1
Host: target.com
Cookie: session=<valid_session>
```

Use `curl` with pattern `X-Frame-Options|frame-ancestors` to check which pages have protection and which do not. Protection must be consistent across all pages.

### Step 4: Test Frame-Busting JavaScript

**CLI Actions:**
Use `curl` to fetch the target page and look for JavaScript frame-busting code:

```
GET / HTTP/1.1
Host: target.com
```

Search response for frame-busting patterns:
```javascript
if (top !== self) top.location = self.location;
if (top.location != self.location) top.location = self.location;
if (parent.frames.length > 0) top.location = self.location;
```

Frame-busting JavaScript can be bypassed using:
- `sandbox` attribute on iframe: `<iframe sandbox="allow-forms" src="target.com">`
- `X-Frame-Options` header should be used instead of JavaScript-only protection

### Step 5: Test with Sandbox Attribute Bypass

**CLI Actions:**
If the application relies only on JavaScript for frame-busting (no X-Frame-Options or CSP), the iframe `sandbox` attribute disables JavaScript, bypassing the protection.

Document this as a finding if no HTTP header-based protection exists.

### Step 6: Assess Impact on Sensitive Actions

**CLI Actions:**
Use `curl` to identify state-changing actions that could be targeted:

- Account deletion or deactivation
- Password or email change
- Payment or transfer confirmation
- Permission grants (OAuth authorization)
- Two-factor authentication disable
- Admin actions (user management, settings)

For each action, verify that the page serving it has proper framing protection.

Use `rynix_plugin_run('template-scan')` to check for clickjacking-related findings.

## Payloads

### Clickjacking Test Page
```html
<html>
<head><title>Clickjacking Test</title></head>
<body>
<h1>Click the button below to win a prize!</h1>
<iframe src="https://target.com/sensitive-action"
        style="opacity:0.1; position:absolute; top:0; left:0; width:100%; height:100%; z-index:2;"
        sandbox="allow-forms allow-same-origin">
</iframe>
<button style="position:absolute; top:300px; left:200px; z-index:1;">
  Click Here to Win!
</button>
</body>
</html>
```

### iframe Sandbox Bypass Values
```
sandbox=""                               (all restrictions, JS disabled)
sandbox="allow-forms"                    (forms work, JS disabled)
sandbox="allow-forms allow-same-origin"  (forms + same-origin, JS disabled)
sandbox="allow-scripts allow-forms"      (scripts + forms, frame-busting may re-enable)
```

### Double-Framing Test
```html
<iframe src="https://framing-proxy.com/frame?url=https://target.com/action">
</iframe>
```

## Detection Criteria

A finding should be logged when:
- Neither `X-Frame-Options` nor CSP `frame-ancestors` is set on sensitive pages
- `X-Frame-Options` is set inconsistently (present on some pages, missing on others)
- Only JavaScript frame-busting is used without HTTP headers
- `X-Frame-Options: ALLOW-FROM` uses an overly broad allowlist
- CSP `frame-ancestors` allows untrusted domains
- Sensitive state-changing pages can be framed

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Sensitive action page (payment, settings change) frameable, no protection | Medium |
| OAuth authorization page frameable (authorization code theft) | Medium |
| Admin pages frameable, leading to unauthorized admin actions | Medium |
| Non-sensitive pages frameable but no exploitable actions | Low |
| JavaScript frame-busting only (no header protection), bypassable via sandbox | Low |
| X-Frame-Options set on sensitive pages but missing on non-sensitive ones | Low |
| Proper X-Frame-Options/CSP frame-ancestors on all pages | Not a finding |

## Remediation

- Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` on all responses
- Use `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`) on all pages
- Apply framing protection consistently across all pages, not just selected ones
- Do not rely on JavaScript frame-busting as the sole defense
- For OAuth authorization endpoints, always set `X-Frame-Options: DENY`
- Require user interaction confirmations (re-entering password, CAPTCHA) for sensitive actions
- Use SameSite cookie attribute to prevent cookies from being sent in framed contexts
- Test framing protection on every new page or endpoint added to the application

## References

- [OWASP Testing Guide - Clickjacking](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Clickjacking)
- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

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

