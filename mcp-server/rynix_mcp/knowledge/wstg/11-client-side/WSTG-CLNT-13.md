---
id: WSTG-CLNT-13
title: Testing for Reverse Tabnabbing
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Reverse_Tabnabbing
---

# WSTG-CLNT-13: Testing for Reverse Tabnabbing

## Summary

Reverse tabnabbing is an attack exploiting the `window.opener` reference available to pages opened via `target="_blank"` links. When a user clicks a link with `target="_blank"`, the newly opened page gains access to the originating page via `window.opener`. A malicious external page can use `window.opener.location` to redirect the original tab to a phishing page, which the user may not notice when they switch back. This is particularly dangerous for user-generated content with external links.

## Test Objectives

- Identify links with `target="_blank"` that do not include `rel="noopener"`
- Check if external links from user-generated content are sanitized
- Assess `window.opener` accessibility from linked pages
- Verify that the application mitigates reverse tabnabbing across all external links

## Prerequisites

- Target application contains links that open in new tabs/windows
- Application includes user-generated content with external links
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify target="_blank" Links

**CLI Actions:**
Use `curl` to fetch pages and search for `target="_blank"` links:

```
GET / HTTP/1.1
Host: target.com
```

```
GET /forum HTTP/1.1
Host: target.com
```

```
GET /comments HTTP/1.1
Host: target.com
```

Use `curl` to search all captured responses for:
- Pattern: `target=._blank`
- Pattern: `target="_blank"`
- Pattern: `window\.open\(`

### Step 2: Check for rel="noopener" Protection

**CLI Actions:**
For each `target="_blank"` link found, check if it includes `rel="noopener"`:

```html
<!-- Vulnerable (no rel="noopener") -->
<a href="https://external.com" target="_blank">Link</a>

<!-- Protected -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Link</a>
```

Use `curl` to fetch pages with external links:

```
GET /blog/post/1 HTTP/1.1
Host: target.com
```

Check all anchor tags with `target="_blank"` for the presence of `rel="noopener"` and/or `rel="noreferrer"`.

### Step 3: Check window.open() Calls

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for `window.open()` calls:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for patterns:
```javascript
window.open(url)           // Vulnerable - opener is set
window.open(url, '_blank') // Vulnerable - opener is set
```

Safe patterns:
```javascript
var w = window.open(url);
w.opener = null;           // Clears opener reference

// Or using noopener feature
window.open(url, '_blank', 'noopener');
```

### Step 4: Test User-Generated Content Links

**CLI Actions:**
Use `curl` to submit content with external links:

```
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"body": "Check out https://external.com for more info"}
```

Then fetch the page where the comment is displayed:

```
GET /post/1/comments HTTP/1.1
Host: target.com
```

Verify if the automatically generated link includes `target="_blank"` and whether `rel="noopener noreferrer"` is added.

### Step 5: Check Referrer-Policy Header

**CLI Actions:**
Use `curl` and check for `Referrer-Policy` header:

```
GET / HTTP/1.1
Host: target.com
```

The `Referrer-Policy` header can complement reverse tabnabbing protection:
- `no-referrer` - prevents sending referrer to external sites
- `same-origin` - only sends referrer for same-origin requests
- `strict-origin-when-cross-origin` - sends only the origin (not full URL) for cross-origin

### Step 6: Check for Cross-Origin-Opener-Policy

**CLI Actions:**
Use `curl` and check for `Cross-Origin-Opener-Policy` (COOP) header:

```
GET / HTTP/1.1
Host: target.com
```

Look for:
```
Cross-Origin-Opener-Policy: same-origin
```

COOP provides browser-level protection against `window.opener` abuse by isolating the browsing context.

Use `rynix_plugin_run('template-scan')` to check for reverse tabnabbing findings.

## Payloads

### Reverse Tabnabbing Proof of Concept
```html
<!-- Malicious external page that exploits window.opener -->
<html>
<body>
<h1>Interesting Content</h1>
<script>
if (window.opener) {
    // Redirect the original tab to a phishing page
    window.opener.location = 'https://attacker.com/phishing-login';
}
</script>
</body>
</html>
```

### User-Generated Link Payloads
```
# Simple external URL
https://attacker.com/tabnab

# External URL that will be auto-linked
Visit attacker.com for details

# Markdown link (if supported)
[Click here](https://attacker.com/tabnab)

# HTML link (if allowed)
<a href="https://attacker.com/tabnab" target="_blank">Legit link</a>
```

### Link Patterns to Search For
```
target="_blank"
target='_blank'
target=_blank
window.open(
```

### Systematic Open Redirect Testing

**CLI Actions:**
Test all URL parameters that accept URLs or paths for open redirect:

```bash
# Test common redirect parameters
for param in url redirect redirect_url return return_url next dest destination rurl; do
  http_probe -sk -o /dev/null -w '%{http_code} %{redirect_url}' "https://target.com/login?${param}=https://evil.com"
  echo " <- ${param}"
done
```

If any parameter causes a redirect to `https://evil.com`, it's an open redirect vulnerability. Also test with bypass techniques:
- `//evil.com` (protocol-relative)
- `https://evil.com@target.com` (credential-based)
- `https://target.com.evil.com` (subdomain confusion)
- `/\evil.com` (backslash bypass)
- `https://target.com%40evil.com` (encoded @)

## Detection Criteria

A finding should be logged when:
- External links use `target="_blank"` without `rel="noopener"` (or `rel="noopener noreferrer"`)
- `window.open()` calls do not set `opener` to null or use the `noopener` feature
- User-generated external links are rendered without `rel="noopener"` protection
- `Cross-Origin-Opener-Policy` header is not set
- No `Referrer-Policy` is configured

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| User-generated external links without noopener on authentication-related pages | Medium |
| External links without noopener on high-traffic pages (forum, comments) | Medium |
| window.open() without noopener for user-controlled URLs | Medium |
| Internal application links with target="_blank" missing noopener | Low |
| External links without noopener on non-sensitive pages | Low |
| Missing COOP header but rel="noopener" present on all links | Low |
| All external links properly protected with noopener and noreferrer | Not a finding |

## Remediation

- Add `rel="noopener noreferrer"` to all `<a>` tags with `target="_blank"`
- For `window.open()`, use the `noopener` feature: `window.open(url, '_blank', 'noopener')`
- Alternatively, set `window.opener = null` after opening
- Implement `Cross-Origin-Opener-Policy: same-origin` header
- Automatically add `rel="noopener noreferrer"` to all user-generated external links
- Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter
- Consider using a link interstitial page for external links ("You are leaving our site")
- Audit existing codebase for all `target="_blank"` links and `window.open()` calls
- Note: Modern browsers (Chrome 88+, Firefox 79+, Safari 12.1+) implicitly set `rel="noopener"` for `target="_blank"` links, but explicit declaration is still recommended for older browsers

## References

- [OWASP Testing Guide - Reverse Tabnabbing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Reverse_Tabnabbing)
- [CWE-1022: Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
- [MDN - Link types: noopener](https://developer.mozilla.org/en-US/docs/Web/HTML/Link_types/noopener)

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

