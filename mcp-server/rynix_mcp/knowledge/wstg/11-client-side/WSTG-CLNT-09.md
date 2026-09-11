---
id: WSTG-CLNT-09
title: Testing WebSockets
category: Client-Side
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_WebSockets
---

# WSTG-CLNT-09: Testing WebSockets

## Summary

WebSockets provide full-duplex communication channels between a client and server over a single TCP connection. Unlike HTTP, WebSocket connections are long-lived and bidirectional. Security concerns include cross-site WebSocket hijacking (CSWSH) when origin validation is missing, injection attacks through WebSocket messages, lack of authentication on WebSocket handshakes, and information disclosure through unencrypted WebSocket traffic (ws:// instead of wss://).

## Test Objectives

- Identify WebSocket endpoints and their purpose
- Test for cross-site WebSocket hijacking (missing origin validation)
- Test for injection vulnerabilities in WebSocket messages
- Verify authentication and authorization on WebSocket connections
- Check for unencrypted WebSocket traffic (ws:// vs. wss://)

## Prerequisites

- Target application uses WebSocket connections
- Docker pentest container capturing WebSocket traffic
- WebSocket endpoints have been identified

## Test Steps

### Step 1: Identify WebSocket Endpoints

**CLI Actions:**
Use `curl` to find WebSocket upgrade requests:

Look for requests with:
```
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <random_key>
Sec-WebSocket-Version: 13
Origin: https://target.com
```

Use `curl` with pattern `Upgrade: websocket` to find all WebSocket handshake requests.

### Step 2: Test Cross-Site WebSocket Hijacking (CSWSH)

**CLI Actions:**
Use `curl` to send a WebSocket handshake request with a malicious Origin:

```
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://attacker.com
Cookie: session=<valid_session>
```

If the server returns `101 Switching Protocols` without rejecting the cross-origin request, the WebSocket is vulnerable to CSWSH. An attacker page can establish a WebSocket connection to the target using the victim's cookies.

### Step 3: Test Origin Validation Bypass

**CLI Actions:**
If basic cross-origin requests are rejected, test bypass techniques:

```
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com.attacker.com
```

```
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: null
```

```
GET /ws/chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
(No Origin header at all)

### Step 4: Test Injection via WebSocket Messages

**CLI Actions:**
Use `save to manual-review file` with a WebSocket connection. Test injection payloads in WebSocket messages:

SQL Injection:
```json
{"action": "search", "query": "test' OR 1=1--"}
```

XSS (if messages are rendered in HTML):
```json
{"action": "chat", "message": "<img src=x onerror=alert('XSS')>"}
```

Command Injection:
```json
{"action": "ping", "host": "127.0.0.1; id"}
```

Test all WebSocket message parameters for standard injection vulnerabilities.

### Step 5: Test Authentication and Authorization

**CLI Actions:**
Use `curl` to establish a WebSocket connection without authentication:

```
GET /ws/admin HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

Test:
1. WebSocket connection without session cookie
2. WebSocket connection with expired session
3. WebSocket connection with low-privilege session to admin endpoint
4. Whether WebSocket authorization is re-checked for each message or only at handshake

### Step 6: Check for Unencrypted WebSocket Traffic

**CLI Actions:**
Use `curl` to check for `ws://` (unencrypted) vs. `wss://` (encrypted) connections:

- Pattern: `ws://` (unencrypted WebSocket)

Unencrypted WebSocket traffic can be intercepted and modified by network attackers.

Use `rynix_plugin_run('template-scan')` to check for WebSocket-related findings.

## Payloads

### Cross-Site WebSocket Hijacking Origins
```
https://attacker.com
https://target.com.attacker.com
https://evil.target.com
null
(empty - no Origin header)
```

### WebSocket Injection Payloads
```
# XSS in chat messages
{"message": "<script>alert('XSS')</script>"}
{"message": "<img src=x onerror=alert('XSS')>"}

# SQL injection
{"query": "' OR 1=1--"}
{"id": "1 UNION SELECT username,password FROM users--"}

# Command injection
{"host": "127.0.0.1; cat /etc/passwd"}
{"cmd": "test && id"}

# Path traversal
{"file": "../../../etc/passwd"}

# JSON injection
{"data": "\",\"admin\":true,\"x\":\""}
```

### Authentication Bypass
```
# No session cookie
# Expired session cookie
# Another user's session cookie
# Modified JWT token
# Empty authorization
```

### Denial of Service
```
# Extremely large message
{"data": "A" * 1000000}

# Rapid message flood
Send 1000 messages per second

# Malformed WebSocket frames
Invalid opcode
Missing mask
```

## Detection Criteria

A finding should be logged when:
- WebSocket handshake accepts connections from arbitrary origins (CSWSH)
- Origin validation can be bypassed using subdomains or null origin
- WebSocket messages are vulnerable to injection (XSS, SQLi, command injection)
- WebSocket connections do not require authentication
- WebSocket authorization is checked only at handshake, not per-message
- Unencrypted WebSocket (ws://) is used instead of wss://
- No rate limiting on WebSocket messages

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CSWSH allows reading sensitive data or performing actions as victim | High |
| XSS via WebSocket messages (stored, displayed to other users) | High |
| SQL or command injection through WebSocket messages | High |
| WebSocket endpoints accessible without authentication | Medium |
| Authorization bypass on admin WebSocket channels | Medium |
| Unencrypted WebSocket (ws://) carrying sensitive data | Medium |
| CSWSH possible but WebSocket carries only non-sensitive data | Low |
| No rate limiting on WebSocket messages | Low |
| Proper origin validation, authentication, and encryption | Not a finding |

## Remediation

- Validate the `Origin` header on WebSocket handshake requests against an allowlist
- Require authentication tokens in the WebSocket handshake (via cookies or URL parameters)
- Implement per-message authorization checks, not just at connection time
- Use `wss://` (WebSocket Secure) for all WebSocket connections
- Sanitize all WebSocket message content before processing or rendering
- Implement rate limiting on WebSocket messages
- Set connection timeouts to prevent resource exhaustion
- Use CSRF tokens in the WebSocket handshake URL if cookies are used for authentication
- Log WebSocket connection attempts and messages for security monitoring
- Validate and sanitize all message fields as with any other input

## References

- [OWASP Testing Guide - WebSockets](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_WebSockets)
- [CWE-1385: Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html)
- [Cross-Site WebSocket Hijacking - Christian Schneider](https://christian-schneider.net/CrossSiteWebSocketHijacking.html)

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

