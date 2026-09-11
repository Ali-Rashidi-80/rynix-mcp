---
id: WSTG-CLNT-04
title: Testing for Client-side URL Redirect
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
---

# WSTG-CLNT-04: Testing for Client-side URL Redirect

## Summary

Client-side URL redirect vulnerabilities (open redirects) occur when JavaScript code uses user-controllable data to redirect users to a different URL without proper validation. Attackers exploit this to redirect victims from a trusted domain to a malicious site for phishing, credential theft, or malware delivery. Since the initial URL appears legitimate, victims are more likely to trust the redirect destination.

## Test Objectives

- Identify client-side redirect mechanisms in JavaScript code
- Test if redirect destinations can be controlled by user input
- Determine if redirect validation can be bypassed
- Assess the impact of open redirects for phishing and token theft

## Prerequisites

- Target application uses client-side redirects
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify Client-Side Redirect Code

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for redirect patterns:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for redirect sinks in JavaScript:
```javascript
window.location = ...
window.location.href = ...
window.location.assign(...)
window.location.replace(...)
document.location = ...
window.open(...)
window.navigate(...)
```

Search for redirect sources:
```javascript
location.hash
location.search
URLSearchParams
document.referrer
window.name
```

### Step 2: Test URL Parameter-Based Redirects

**CLI Actions:**
Use `curl` to test common redirect parameters:

```
GET /redirect?url=https://attacker.com HTTP/1.1
Host: target.com
```

```
GET /login?return_url=https://attacker.com HTTP/1.1
Host: target.com
```

```
GET /page?next=https://attacker.com HTTP/1.1
Host: target.com
```

Test common redirect parameter names:
- `url`, `redirect`, `return`, `next`, `goto`, `target`, `destination`
- `return_url`, `redirect_url`, `redirect_uri`, `return_to`, `continue`
- `rurl`, `redir`, `dest`, `forward`, `out`, `view`

### Step 3: Test Redirect Validation Bypass

**CLI Actions:**
If basic external URLs are blocked, use `curl` to test bypass techniques:

```
GET /redirect?url=//attacker.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=https://target.com@attacker.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=https://attacker.com%23.target.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=https://target.com.attacker.com HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` for double-encoding bypass attempts:
```
GET /redirect?url=https%3A%2F%2Fattacker.com HTTP/1.1
Host: target.com
```

### Step 4: Test Fragment-Based Redirects

**CLI Actions:**
Use `curl` to fetch the page, then note if JavaScript reads `location.hash` for redirects:

```
GET /page HTTP/1.1
Host: target.com
```

If the JavaScript contains:
```javascript
window.location = location.hash.slice(1);
```

The redirect can be triggered via:
```
https://target.com/page#https://attacker.com
```

Note: Fragment-based redirects do not appear in proxy history as fragments are not sent to the server. Document these for manual browser testing.

### Step 5: Test JavaScript Protocol Redirects

**CLI Actions:**
Use `curl` to test if `javascript:` protocol is accepted as a redirect destination:

```
GET /redirect?url=javascript:alert('XSS') HTTP/1.1
Host: target.com
```

```
GET /redirect?url=data:text/html,<script>alert('XSS')</script> HTTP/1.1
Host: target.com
```

```
GET /redirect?url=vbscript:MsgBox('XSS') HTTP/1.1
Host: target.com
```

If JavaScript protocol URLs are accepted, this escalates from open redirect to XSS.

### Step 6: Test OAuth/SSO Redirect URI Manipulation

**CLI Actions:**
Use `curl` to test redirect URI parameters in OAuth flows:

```
GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.com/callback HTTP/1.1
Host: target.com
```

```
GET /oauth/authorize?client_id=app&redirect_uri=https://target.com.attacker.com/callback HTTP/1.1
Host: target.com
```

If the redirect URI is not strictly validated, OAuth tokens may be leaked to attacker-controlled domains.

Use `rynix_plugin_run('template-scan')` to check for open redirect findings.

## Payloads

### Basic Open Redirect URLs
```
https://attacker.com
http://attacker.com
//attacker.com
/\attacker.com
```

### Validation Bypass Payloads
```
# Using @ symbol
https://target.com@attacker.com
https://target.com%40attacker.com

# Subdomain spoofing
https://target.com.attacker.com
https://attacker.com/target.com

# Protocol-relative
//attacker.com
//attacker.com%2f%2ftarget.com

# URL encoding
https%3A%2F%2Fattacker.com
%2F%2Fattacker.com

# Double URL encoding
%252F%252Fattacker.com

# Tab and newline
https://attacker%09.com
https://attacker%0d%0a.com

# Backslash
https://attacker.com\@target.com
/\/attacker.com

# Fragment
https://target.com#https://attacker.com
https://target.com%23@attacker.com

# NULL byte
https://target.com%00.attacker.com
```

### JavaScript Protocol Payloads
```
javascript:alert('XSS')
javascript://comment%0aalert('XSS')
data:text/html,<script>alert('XSS')</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

### Common Redirect Parameter Names
```
url
redirect
return
next
goto
target
destination
return_url
redirect_url
redirect_uri
return_to
continue
rurl
redir
dest
forward
out
view
link
ref
```

## Detection Criteria

A finding should be logged when:
- Client-side JavaScript redirects to a URL specified in user-controllable input
- Redirect destination validation can be bypassed to reach external domains
- JavaScript protocol URLs are accepted as redirect destinations (escalation to XSS)
- OAuth redirect URIs can be manipulated to leak tokens
- Fragment-based redirects send users to attacker-controlled sites

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Open redirect in OAuth flow leaks access tokens | High |
| Redirect accepts javascript: or data: protocol (XSS) | High (treat as XSS) |
| Client-side redirect to arbitrary external URL | Medium |
| Redirect validation bypass using encoding or URL tricks | Medium |
| Open redirect exists but limited to same-origin paths | Low |
| Redirect to external URL but no sensitive context (no auth tokens) | Low |
| All redirect destinations validated against strict allowlist | Not a finding |

## Remediation

- Validate redirect URLs against a strict allowlist of permitted domains
- Use relative paths for redirects instead of full URLs where possible
- Block `javascript:`, `data:`, and `vbscript:` protocol URLs in redirect parameters
- For OAuth flows, validate redirect URIs exactly (no substring matching)
- Implement a redirect warning page: "You are leaving target.com"
- Do not include sensitive tokens in redirect URLs
- Use server-side redirects with validation instead of client-side redirects
- Sanitize URL input: strip authentication credentials, normalize encoding

## References

- [OWASP Testing Guide - Client-side URL Redirect](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

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

