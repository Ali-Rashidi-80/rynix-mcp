---
id: WSTG-SESS-07
title: Testing Session Timeout
category: Session Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout
---

# WSTG-SESS-07: Testing Session Timeout

## Summary

Session timeout controls limit how long a session remains valid, reducing the window of opportunity for session hijacking attacks. Two types of timeout should be implemented: idle timeout (session expires after a period of inactivity) and absolute timeout (session expires after a fixed duration regardless of activity). This test verifies that both timeout mechanisms are properly implemented and that sessions become truly invalid after expiration.

## Test Objectives

- Determine if the application enforces an idle session timeout
- Determine if the application enforces an absolute session timeout
- Verify that expired sessions are properly invalidated server-side
- Test that session tokens cannot be used after the expected expiry period

## Prerequisites

- A valid test account for authentication
- Docker pentest container capturing traffic
- Patience or ability to wait for timeout periods (or knowledge of configured timeout values)

## Test Steps

### Step 1: Establish a Baseline Session

**CLI Actions:**
1. Authenticate to the application and use `curl` to capture the session token
2. Use `curl` to confirm the session is active:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   ``
3. Record the authentication timestamp and the session token
4. Look for any session expiration indicators in the response headers (e.g., `Expires`, `Max-Age` in Set-Cookie)

### Step 2: Test Idle Timeout

**CLI Actions:**
1. After authenticating, wait without making any requests (idle period)
2. Start with a 5-minute wait, then test at 15, 30, and 60 minutes
3. After each wait interval, use `curl` with the original session token:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   ``
4. Record at which interval the session is no longer valid (returns 401/403 or redirects to login)
5. The idle timeout should typically be 15-30 minutes for standard applications, shorter for high-security applications

### Step 3: Test Absolute Timeout

**CLI Actions:**
1. Authenticate and record the session token and timestamp
2. Keep the session active by periodically making requests (every few minutes) to prevent idle timeout
3. Use `curl` to send keep-alive requests at regular intervals:
   ``
   GET /api/heartbeat HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   ``
4. Continue until the session expires despite continuous activity
5. If the session remains valid for more than 24 hours of continuous use, the absolute timeout is likely missing
6. Record the absolute timeout duration

### Step 4: Test Session Validity After Cookie Expiry

**CLI Actions:**
1. Check the `Max-Age` or `Expires` attribute of the session cookie from the `Set-Cookie` header
2. If the cookie has a `Max-Age` of 1800 (30 minutes), wait past this time
3. Use `curl` to manually send the expired cookie value:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<expired_cookie_value>
   ``
4. If the server still accepts the expired cookie value, the server-side session has not been invalidated (the cookie expiry is client-side only)

### Step 5: Test Timeout Consistency Across Endpoints

**CLI Actions:**
1. After the session should have timed out, use `curl` to test multiple endpoint types:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<timed_out_session>
   ``
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<timed_out_session>
   ``
   ``
   POST /api/settings/update HTTP/1.1
   Host: target.com
   Cookie: session=<timed_out_session>
   Content-Type: application/json

   {"theme":"dark"}
   ``
2. Verify that the timeout is enforced consistently across all endpoints (page views, API calls, AJAX requests)
3. Check if any endpoints bypass timeout validation

### Step 6: Test Token Refresh and Sliding Window Behavior

**CLI Actions:**
1. Authenticate and note the session token
2. Make a request just before the expected idle timeout
3. Use `curl` to check if the response contains a new `Set-Cookie` header (sliding window refresh)
4. Use `curl` to make a request and examine the response headers for session renewal:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_token>
   ``
5. Document whether the application uses:
   - Fixed timeout (session expires at a set time regardless of activity)
   - Sliding window (idle timer resets with each request)
   - Token rotation (new token issued with each request)

## Payloads

Not applicable - this test relies on timing and observation rather than payload injection.

## Detection Criteria

A finding should be logged when:
- No idle session timeout is implemented (session lives forever without activity)
- No absolute session timeout is implemented (session lives forever with continuous activity)
- Idle timeout is excessively long (greater than 60 minutes for standard applications)
- Absolute timeout is excessively long (greater than 24 hours)
- Session cookie expires client-side but the server-side session remains valid
- Timeout is not enforced consistently across all endpoints
- High-sensitivity applications (banking, healthcare) have timeouts greater than 15 minutes

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No idle timeout at all (session never expires) | Medium |
| No absolute timeout (active session lives indefinitely) | Medium |
| Idle timeout greater than 60 minutes for standard application | Low |
| Idle timeout greater than 15 minutes for financial/healthcare application | Medium |
| Server session valid after client cookie expiry | Medium |
| Timeout inconsistently enforced (some endpoints bypass it) | Medium |
| Reasonable timeout exists but could be shorter | Informational |

## Remediation

- Implement idle session timeout (15-30 minutes for standard applications, 5-15 minutes for high-security)
- Implement absolute session timeout (8-24 hours maximum, shorter for sensitive applications)
- Invalidate sessions server-side when timeout is reached (do not rely solely on cookie expiry)
- Enforce timeout consistently across all endpoints and request types
- Provide users with a warning before session expiry (e.g., a JavaScript dialog)
- Implement re-authentication for sensitive operations after a period of inactivity
- Use sliding window timeouts that reset the idle timer on each request
- Log session timeout events for audit purposes

## References

- [OWASP Testing Guide - Session Timeout](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
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

