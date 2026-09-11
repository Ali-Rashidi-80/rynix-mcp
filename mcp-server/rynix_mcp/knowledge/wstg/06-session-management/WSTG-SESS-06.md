---
id: WSTG-SESS-06
title: Testing for Logout Functionality
category: Session Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
---

# WSTG-SESS-06: Testing for Logout Functionality

## Summary

Proper logout functionality must fully invalidate the user's session on the server side, clear session cookies on the client side, and prevent access to previously authenticated pages. Incomplete logout implementations may leave sessions active on the server, allow session reuse after logout, or fail to clear cached authenticated content, enabling session hijacking or unauthorized access.

## Test Objectives

- Verify that the session is invalidated on the server side after logout
- Confirm that session cookies are properly cleared on the client side
- Test if the back button can access authenticated content after logout
- Check if all tokens (session, JWT, refresh) are invalidated on logout

## Prerequisites

- A valid test account with authentication capability
- Docker pentest container capturing traffic
- An authenticated session to test logout against

## Test Steps

### Step 1: Capture the Authenticated Session State

**CLI Actions:**
1. Authenticate to the application and use `curl` to capture the session token
2. Record all session-related cookies and tokens (session cookie, CSRF token, JWT, refresh token)
3. Use `curl` to confirm the session works by accessing a protected resource:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<authenticated_session_token>
   ``
4. Verify the response returns authenticated content (200 OK with user data)

### Step 2: Perform Logout and Capture Response

**CLI Actions:**
1. Trigger the logout action and use `curl` to capture the logout request and response
2. Examine the logout response for:
   - `Set-Cookie` headers that clear the session cookie (e.g., `Set-Cookie: session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT`)
   - Redirect to the login page
   - Any remaining cookies not being cleared
3. Use `curl` with pattern `Set-Cookie:.*=.*[Ee]xpires=.*1970|Max-Age=0|=deleted` to verify cookies are being expired

### Step 3: Test Server-Side Session Invalidation

**CLI Actions:**
1. After logout, use `curl` with the old (pre-logout) session token to access a protected resource:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<pre_logout_session_token>
   ``
2. If the request returns authenticated content (200 OK with user data), the session was not invalidated server-side
3. Test multiple protected endpoints with the old token:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<pre_logout_session_token>
   ``
   ``
   POST /api/settings/update HTTP/1.1
   Host: target.com
   Cookie: session=<pre_logout_session_token>
   Content-Type: application/json

   {"theme":"dark"}
   ``

### Step 4: Test JWT and Refresh Token Invalidation

**CLI Actions:**
1. If the application uses JWTs, capture the JWT before logout
2. After logout, use `curl` with the old JWT:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <pre_logout_jwt>
   ``
3. If the JWT is still accepted, the application does not maintain a token blocklist or revocation list
4. Test the refresh token after logout:
   ``
   POST /api/auth/refresh HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"refresh_token":"<pre_logout_refresh_token>"}
   ``
5. If a new access token is issued with the old refresh token, the refresh token was not revoked

### Step 5: Test Back Button and Cache Behavior

**CLI Actions:**
1. After logout, use `curl` to request previously visited authenticated pages:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   ``
   (without any session cookie, simulating a cached page request)
2. Check if the application sets proper cache headers on authenticated pages:
   - `Cache-Control: no-store, no-cache, must-revalidate`
   - `Pragma: no-cache`
   - `Expires: 0`
3. Use `curl` to examine cache-control headers on authenticated responses captured earlier

### Step 6: Test Multiple Session Invalidation (Logout Everywhere)

**CLI Actions:**
1. Authenticate the same user from two different sessions (simulating two browsers)
2. Record both session tokens
3. Perform logout on one session
4. Use `curl` to test if the other session is still active:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<second_session_token>
   ``
5. If the application offers a "logout all sessions" feature, test that it invalidates all sessions:
   - Use `curl` with all previously captured session tokens after "logout everywhere"

### Step 7: Test Cookie Clearing Completeness

**CLI Actions:**
1. Use `curl` to examine the logout response
2. Verify that every session-related cookie has a corresponding `Set-Cookie` header that expires it
3. Check for cookies that may not be cleared:
   - Remember-me tokens
   - Preference cookies with embedded session data
   - Third-party authentication cookies
4. Use `curl` with pattern `Set-Cookie:` in the logout response to list all cookies being set/cleared

## Payloads

Not applicable - this test focuses on session invalidation behavior rather than payload injection.

## Detection Criteria

A finding should be logged when:
- The pre-logout session token still works after logout (server-side session not invalidated)
- The JWT or access token is still accepted after logout
- The refresh token still generates new access tokens after logout
- Session cookies are not cleared (no expiration Set-Cookie header on logout)
- Authenticated pages are displayed from cache after logout
- The "logout everywhere" feature does not invalidate all sessions
- Logout is performed via GET request (susceptible to CSRF-triggered logout)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Session token remains valid server-side after logout | Medium |
| JWT accepted indefinitely after logout (no revocation) | Medium |
| Refresh token not revoked on logout | Medium |
| Session cookies not cleared on logout response | Low |
| Cached authenticated content accessible after logout | Low |
| No "logout all sessions" capability for compromised account recovery | Low |
| Logout uses GET method (vulnerable to forced logout via CSRF) | Low |
| Multiple session tokens remain active with no way to invalidate | Medium |

## Remediation

- Invalidate the session on the server side immediately upon logout
- Expire all session cookies with `Set-Cookie` headers setting `Max-Age=0` or past `Expires` date
- Maintain a JWT blocklist or use short-lived JWTs with revocable refresh tokens
- Revoke refresh tokens on logout
- Set `Cache-Control: no-store` on all authenticated pages to prevent back-button access
- Implement "logout all sessions" functionality for compromised account recovery
- Use POST method for the logout action to prevent CSRF-triggered logouts
- Clear all authentication-related cookies, including remember-me and third-party tokens

## References

- [OWASP Testing Guide - Logout Functionality](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality)
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

