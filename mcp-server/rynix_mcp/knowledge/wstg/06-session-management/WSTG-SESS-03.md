---
id: WSTG-SESS-03
title: Testing for Session Fixation
category: Session Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
---

# WSTG-SESS-03: Testing for Session Fixation

## Summary

Session fixation attacks occur when an attacker sets or forces a known session identifier on a victim before the victim authenticates. If the application does not regenerate the session token upon successful authentication, the attacker can use the pre-set session token to hijack the victim's authenticated session. This test verifies whether session tokens are regenerated after authentication and whether session tokens can be externally set via cookies, URL parameters, or other mechanisms.

## Test Objectives

- Determine if the application regenerates session tokens after successful authentication
- Test if session tokens can be set or injected before authentication
- Verify that pre-authentication session tokens become invalid after login
- Test for cookie injection vectors that could enable session fixation

## Prerequisites

- Target application has authentication functionality with session management
- A valid test account for authentication
- Docker pentest container capturing traffic before and after authentication

## Test Steps

### Step 1: Capture Pre-Authentication Session Token

**CLI Actions:**
1. Clear all cookies and visit the application landing page
2. Use `curl` to capture the initial response and any `Set-Cookie` headers
3. Record the pre-authentication session token value (e.g., `JSESSIONID`, `PHPSESSID`, `session`, `connect.sid`)
4. Use `curl` with pattern `Set-Cookie:.*([Ss]ession|JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid)` to identify all session cookie names

### Step 2: Authenticate and Compare Tokens

**CLI Actions:**
1. Using the same browser session (with the pre-authentication token), perform authentication:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Cookie: session=<pre_auth_token>
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
2. Use `curl` to send the login request and examine the response
3. Check the `Set-Cookie` header in the response for a new session token
4. Compare the pre-authentication token with the post-authentication token
5. If the tokens are identical, the application is vulnerable to session fixation

### Step 3: Test Session Fixation via Cookie Setting

**CLI Actions:**
1. Use `curl` to set a known session token and then authenticate with it:
   ``
   GET /login HTTP/1.1
   Host: target.com
   Cookie: session=ATTACKER_CONTROLLED_TOKEN_12345
   ``
2. Then authenticate using the same token:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Cookie: session=ATTACKER_CONTROLLED_TOKEN_12345
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
3. After authentication, test if the attacker's token is now an authenticated session:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=ATTACKER_CONTROLLED_TOKEN_12345
   ``
4. If the dashboard returns authenticated content, session fixation is confirmed

### Step 4: Test Session Fixation via URL Parameters

**CLI Actions:**
1. Some applications accept session tokens in URL parameters. Use `curl` to test:
   ``
   GET /login?JSESSIONID=ATTACKER_TOKEN HTTP/1.1
   Host: target.com
   ``
   ``
   GET /login;jsessionid=ATTACKER_TOKEN HTTP/1.1
   Host: target.com
   ``
2. Authenticate and check if the URL-provided session token becomes the authenticated session
3. Use `curl` with pattern `[?;&](session|sid|JSESSIONID|PHPSESSID|token)=` to find session tokens in URLs

### Step 5: Test Cross-Subdomain Cookie Injection

**CLI Actions:**
1. If the application sets cookies with a broad domain scope (e.g., `Domain=.target.com`), a compromised or attacker-controlled subdomain could inject cookies
2. Use `curl` to check the `Domain` attribute of session cookies
3. Simulate cookie injection by using `curl` with an attacker-set cookie value:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=INJECTED_FROM_SUBDOMAIN_VALUE
   ``
4. If the application accepts the externally set cookie for an authenticated session, it is vulnerable

### Step 6: Verify Token Invalidation

**CLI Actions:**
1. Record the pre-authentication token
2. Authenticate and get a new post-authentication token
3. Use `curl` to test if the old pre-authentication token still works:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<pre_auth_token>
   ``
4. If the pre-authentication token provides authenticated access, the application failed to invalidate the old session

## Payloads

### Fixation Test Tokens
```
ATTACKER_FIXED_SESSION_001
AAAAAAAAAAAAAAAAAAAAAA
fixation_test_token_12345
0000000000000000
custom_session_value
```

### URL-Based Session Parameters
```
?JSESSIONID=ATTACKER_TOKEN
;jsessionid=ATTACKER_TOKEN
?PHPSESSID=ATTACKER_TOKEN
?session=ATTACKER_TOKEN
?sid=ATTACKER_TOKEN
?token=ATTACKER_TOKEN
```

## Detection Criteria

A finding should be logged when:
- The session token is not regenerated (changed) after successful authentication
- A pre-set or attacker-supplied session token becomes an authenticated session after login
- Session tokens accepted via URL parameters persist through authentication
- Pre-authentication session tokens remain valid after login
- Cookie injection from a broader domain scope allows session fixation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Session token not regenerated after login and attacker can set the token | High |
| Session accepted via URL parameter and not regenerated on login | High |
| Pre-authentication token remains valid alongside new token | Medium |
| Session token regenerated but old token not invalidated | Medium |
| Application rejects externally set tokens but does not regenerate on login | Medium |
| Token is regenerated on login but not on privilege changes (e.g., role switch) | Low |

## Remediation

- Always regenerate the session token after successful authentication
- Invalidate (destroy) the pre-authentication session on the server after issuing a new token
- Reject session tokens that were not issued by the server
- Do not accept session tokens from URL parameters
- Set cookie attributes properly: `HttpOnly`, `Secure`, `SameSite=Lax`
- Restrict cookie `Domain` to the specific application subdomain
- Regenerate session tokens on any privilege level change (e.g., password change, role change)
- Implement session binding (tie sessions to client fingerprints like IP or User-Agent as an additional layer)

## References

- [OWASP Testing Guide - Session Fixation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

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

