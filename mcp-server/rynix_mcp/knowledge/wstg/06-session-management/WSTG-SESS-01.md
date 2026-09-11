---
id: WSTG-SESS-01
title: Testing for Session Management Schema
category: Session Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema
---

# WSTG-SESS-01: Testing for Session Management Schema

## Summary

Session management is critical for maintaining user state across HTTP requests. Weak session management can lead to session hijacking, fixation, or prediction attacks. This test evaluates the overall session management implementation.

## Test Objectives

- Analyze session token generation for randomness and entropy
- Determine if session tokens are predictable or guessable
- Evaluate session lifecycle management (creation, use, expiration, destruction)

## Prerequisites

- Target application has authentication and session management
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Collect Session Tokens

**CLI Actions:**
1. Use `curl` to perform multiple login requests and collect session tokens:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
2. Repeat 10-20 times, recording each `Set-Cookie` session value
3. Use `curl` to collect additional session tokens from browsing

### Step 2: Analyze Token Format and Entropy

Examine collected tokens for:
- **Length**: Tokens should be at least 128 bits (32 hex characters)
- **Character set**: Should use a large alphabet (hex, base64, etc.)
- **Structure**: Check if tokens contain encoded data (try `base64 -d`)
- **Predictability**: Look for sequential patterns, timestamps, or user data embedded in tokens

**CLI Actions:**
1. Use `base64 -d` on session tokens to check for embedded plaintext data
2. Compare sequential tokens for patterns (incrementing values, timestamps)

### Step 3: Test Token Transmission Security

**CLI Actions:**
1. Use `curl` to verify tokens are only sent over HTTPS
2. Check if session tokens appear in URLs (vulnerable to referer leakage):
   - Use `curl` with pattern `session|token|sid|JSESSIONID|PHPSESSID` in URLs

### Step 4: Test Session Expiration

**CLI Actions:**
1. Authenticate and note the session token
2. Wait for an extended period (idle timeout test)
3. Use `curl` to send an authenticated request with the old token
4. Check if the session is still valid after the expected timeout period
5. Test absolute timeout: authenticate and keep using the session - check if it eventually expires regardless of activity

### Step 5: Test Session Invalidation on Logout

**CLI Actions:**
1. Authenticate and note the session token
2. Perform the logout action
3. Use `curl` with the old (pre-logout) session token to access a protected page:
   ``
   GET /dashboard HTTP/1.1
   Cookie: session=<old_token>
   ``
4. If the old token still works, the session was not properly invalidated

### Step 6: Test Session Renewal on Authentication

**CLI Actions:**
1. Visit the application and note any pre-authentication session token
2. Authenticate and note the post-authentication session token
3. If they are the same, the application is vulnerable to session fixation

## Payloads

Not directly applicable - this is an analysis test. Use collected session tokens as test data.

## Detection Criteria

A finding should be logged when:
- Session tokens are short (<128 bits) or use a limited character set
- Tokens contain decodable user data or predictable patterns
- Sessions don't expire after a reasonable idle period (e.g., 30 minutes)
- Sessions don't expire with an absolute timeout (e.g., 8-24 hours)
- Logout doesn't invalidate the server-side session
- Session tokens are not regenerated after authentication
- Tokens appear in URLs

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Predictable or sequential session tokens | High |
| Session not invalidated on logout | Medium |
| No session timeout (lives forever) | Medium |
| Token not regenerated after authentication (fixation risk) | Medium |
| Session token in URL | Medium |
| Short token length but random | Low |

## Remediation

- Use a cryptographically secure random number generator for tokens
- Tokens should be at least 128 bits of entropy
- Regenerate session tokens after authentication
- Invalidate sessions server-side on logout
- Implement idle timeout (15-30 minutes recommended)
- Implement absolute timeout (8-24 hours)
- Never transmit tokens in URLs
- Set Secure, HttpOnly, and SameSite cookie attributes

## References

- [OWASP Testing Guide - Session Management Schema](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema)
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

