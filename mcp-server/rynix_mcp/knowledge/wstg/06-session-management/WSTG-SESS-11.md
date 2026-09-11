---
id: WSTG-SESS-11
title: Testing for Session Replay
category: Session Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/11-Testing_for_Session_Replay
---

# WSTG-SESS-11: Testing for Session Replay

## Summary

Session replay attacks occur when an attacker captures a valid session token and reuses it to impersonate the legitimate user. Unlike session hijacking (which focuses on token acquisition), session replay focuses on whether the application detects and prevents the reuse of captured tokens from a different context. This test evaluates whether session tokens can be replayed from different clients, networks, or after specific events, and whether the application implements token binding or replay detection mechanisms.

## Test Objectives

- Test if captured session tokens can be successfully replayed from a different client
- Verify whether the application implements any form of token binding (IP, User-Agent, device fingerprint)
- Determine if one-time tokens or nonces are used for sensitive operations
- Test if the application detects concurrent use of the same session token from different locations

## Prerequisites

- A valid test account for authentication
- Docker pentest container capturing traffic
- Ability to send requests with modified client attributes (User-Agent, IP headers)

## Test Steps

### Step 1: Capture a Valid Session Token

**CLI Actions:**
1. Authenticate to the application and use `curl` to capture the session token
2. Record the full authentication context:
   - Session token value
   - All cookies set during authentication
   - Authorization headers (Bearer tokens, JWTs)
   - Client IP address
   - User-Agent string
3. Use `curl` to confirm the token is valid:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   ``
4. Record the response to establish a baseline of authenticated access

### Step 2: Replay Token with Different User-Agent

**CLI Actions:**
1. Use `curl` to replay the captured session with a completely different User-Agent:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
   ``
2. Test with multiple User-Agent strings to verify binding:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   User-Agent: curl/7.68.0
   ``
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   User-Agent: PostmanRuntime/7.29.0
   ``
3. If all requests return authenticated content, the session is not bound to the User-Agent

### Step 3: Replay Token with Different IP Headers

**CLI Actions:**
1. Use `curl` to replay the token with different IP-related headers:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   X-Forwarded-For: 10.0.0.1
   X-Real-IP: 10.0.0.1
   ``
2. Test with various IP values:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<captured_session_token>
   X-Forwarded-For: 203.0.113.100
   ``
3. If the application relies on IP binding, it should reject requests from a different apparent IP
4. Note: many applications do not bind to IP due to mobile users and NAT, but high-security applications should

### Step 4: Replay Token After Password Change

**CLI Actions:**
1. Authenticate and capture the session token (Session A)
2. Change the account password while authenticated:
   ``
   POST /api/user/change-password HTTP/1.1
   Host: target.com
   Cookie: session=<new_session_token>
   Content-Type: application/json

   {"current_password":"oldpass","new_password":"newpass"}
   ``
3. Use `curl` to replay the original session token (Session A):
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_a_before_password_change>
   ``
4. If Session A still works after a password change, old sessions are not invalidated on credential changes

### Step 5: Replay Token After Privilege Change

**CLI Actions:**
1. Authenticate as a user and capture the session token
2. Have an admin change the user's role or permissions (e.g., downgrade from admin to regular user)
3. Use `curl` to replay the old token that was issued when the user had higher privileges:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<pre_privilege_change_token>
   ``
4. If the old token retains the old privilege level, the application does not re-validate permissions from the session store

### Step 6: Test One-Time Token Usage for Sensitive Operations

**CLI Actions:**
1. Identify sensitive operations (password reset, money transfer, account deletion)
2. Capture a request that performs a sensitive operation, including any one-time tokens or nonces:
   ``
   POST /api/transfer HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   Content-Type: application/json

   {"to":"recipient","amount":100,"nonce":"abc123"}
   ``
3. Use `save to manual-review file` with this request
4. Use `curl` to replay the exact same request:
   ``
   POST /api/transfer HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   Content-Type: application/json

   {"to":"recipient","amount":100,"nonce":"abc123"}
   ``
5. If the transfer executes again with the same nonce, replay protection is missing for sensitive operations

### Step 7: Test Concurrent Session Replay Detection

**CLI Actions:**
1. Capture a valid session token
2. Use `curl` to send rapid concurrent requests with the same token but different client fingerprints:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   User-Agent: Chrome/120.0
   X-Forwarded-For: 1.2.3.4
   ``
   ``
   GET /api/user/settings HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   User-Agent: Firefox/120.0
   X-Forwarded-For: 5.6.7.8
   ``
3. Check if the application detects concurrent usage from different apparent clients and invalidates the session or raises an alert
4. Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any session management issues

### Step 8: Test Token Replay Across Application Instances

**CLI Actions:**
1. If the application has multiple subdomains or services, test if a token from one service works on another:
   ``
   GET /dashboard HTTP/1.1
   Host: app2.target.com
   Cookie: session=<token_from_app1>
   ``
2. Use `curl` to replay tokens across different application paths or API versions:
   ``
   GET /api/v2/user/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <token_from_v1_api>
   ``

## Payloads

### User-Agent Replay Strings
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0
Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36
curl/7.68.0
PostmanRuntime/7.36.0
python-requests/2.31.0
```

### IP Header Replay Values
```
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 203.0.113.50
X-Real-IP: 198.51.100.25
Client-IP: 172.16.0.1
```

## Detection Criteria

A finding should be logged when:
- A captured session token works from a completely different client (different User-Agent, IP)
- Session tokens remain valid after password changes
- Session tokens retain old privilege levels after permission changes
- Sensitive operations can be replayed with the same nonce or without replay protection
- The application does not detect concurrent session use from different apparent locations
- Tokens issued for one service or API version work on others without validation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Session token replay allows full account access from any client | High |
| Session valid after password change (compromised sessions persist) | High |
| Sensitive financial operations replayable (no nonce/idempotency) | High |
| Old privilege level retained after permission downgrade | Medium |
| No concurrent session detection | Medium |
| No User-Agent or IP binding (standard applications) | Medium |
| Token works across unrelated application services | Medium |
| No IP binding but User-Agent binding present | Low |
| Token replay possible but session has short lifetime (<15 min) | Low |

## Remediation

- Implement token binding to client attributes (User-Agent, TLS channel binding) where feasible
- Invalidate all existing sessions when a user changes their password or has their account compromised
- Re-validate user permissions from the server-side store on every request (not cached in the token)
- Use one-time tokens (nonces) or idempotency keys for sensitive operations
- Implement concurrent session detection and alerting
- Set short session lifetimes to minimize the replay window
- Consider using TLS Token Binding (RFC 8471) for strong cryptographic session binding
- Implement device fingerprinting as an additional layer of replay detection
- Log and alert on suspicious session activity (rapid location changes, unusual User-Agent switches)
- Use rotating session tokens that change with each request (token chaining)

## References

- [OWASP Testing Guide - Session Replay](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/11-Testing_for_Session_Replay)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

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

- V3 Session Management — fixation, timeout, secure cookie flags.
- V2 Authentication — session binding to client fingerprint where applicable.

## CWE references

- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``auth_login``

## Test focus

- Test cookie flags, rotation on login, and concurrent session limits.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

