---
id: WSTG-ATHN-05
title: Testing for Vulnerable Remember Password
category: Authentication
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password
---

# WSTG-ATHN-05: Testing for Vulnerable Remember Password

## Summary

"Remember me" or "keep me logged in" functionality allows users to stay authenticated across browser sessions. When implemented insecurely, these mechanisms can expose credentials or persistent tokens that enable account takeover. Common flaws include storing cleartext credentials in cookies, using predictable remember-me tokens, or failing to properly expire persistent sessions. Attackers who gain access to these tokens (via XSS, physical access, or network interception) can hijack accounts indefinitely.

## Test Objectives

- Analyze how the remember-me functionality is implemented
- Determine if credentials are stored insecurely in cookies or local storage
- Test whether remember-me tokens are predictable or reversible
- Verify that persistent sessions expire appropriately
- Check for secure cookie attributes on remember-me tokens

## Prerequisites

- Target application has a "remember me" or "keep me logged in" feature
- Valid user account for testing
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Identify Remember-Me Implementation

**CLI Actions:**
1. Log in with the "remember me" option checked
2. Use `curl` to capture the login response and all subsequent requests
3. Examine the `Set-Cookie` headers for persistent cookies (those with `Expires` or `Max-Age` attributes)
4. Use `curl` with pattern `remember|rememberme|persistent|keep.?logged|stay.?signed|autologin` to find related cookies and parameters
5. Document all cookies set during the remember-me login process, noting their names, values, expiry, and flags

### Step 2: Analyze Remember-Me Token Content

**CLI Actions:**
1. Capture the remember-me cookie value
2. Use `base64 -d` to check if the token is base64-encoded:
   - If it decodes to readable content (e.g., `username:timestamp`), this is a finding
3. Use `python3 -c "import urllib.parse; ..."` to check for URL-encoded components
4. Look for patterns in the token:
   - Does it contain the username?
   - Does it contain a timestamp?
   - Is it a simple hash of known values?
5. Use `curl` to log in with a different account and compare remember-me tokens:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=user2&password=pass2&remember_me=true
   ``
6. Compare tokens from both accounts for predictable patterns

### Step 3: Test Token Predictability

**CLI Actions:**
1. Collect multiple remember-me tokens by logging in repeatedly
2. Use `curl` to perform several login requests:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=validpass&remember=on
   ``
3. Use `base64 -d` on each collected token to look for sequential or predictable components
4. If tokens appear to be hashed, check if they are simple hashes of known values (e.g., MD5 of username + timestamp)
5. If a pattern is identified, attempt to forge a token for a different user and test it:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: remember_me=<forged_token>
   ``

### Step 4: Test Cookie Security Attributes

**CLI Actions:**
1. Use `curl` to find the login response containing the remember-me cookie
2. Examine the `Set-Cookie` header for security attributes:
   - `Secure` flag (should be present for HTTPS-only transmission)
   - `HttpOnly` flag (should be present to prevent JavaScript access)
   - `SameSite` attribute (should be `Strict` or `Lax`)
   - `Expires`/`Max-Age` (should not be excessively long)
3. Use `curl` to check if the cookie is sent over HTTP:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: remember_me=<token_value>
   ``
4. Note if the cookie lacks any security attributes

### Step 5: Test Token Expiration and Revocation

**CLI Actions:**
1. Log in with remember-me, capture the token, then explicitly log out
2. Use `curl` to test if the remember-me token still works after logout:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: remember_me=<old_token>
   ``
3. Test if the token survives a password change:
   - Log in, capture remember-me token
   - Change the password
   - Use `curl` with the old remember-me token
4. Test token expiration by checking if extremely old tokens are still valid:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: remember_me=<captured_token_from_days_ago>
   ``
5. Use `rynix_plugin_run('template-scan')` to check for any cookie security findings

### Step 6: Test for Credential Storage

**CLI Actions:**
1. Use `curl` with pattern `password|passwd|credential|secret` to check if credentials appear in any cookies or local storage values
2. Examine the remember-me cookie for encoded credentials:
   ``
   Cookie: remember_me=dXNlcm5hbWU6cGFzc3dvcmQ=
   ``
3. Use `base64 -d` to decode any suspicious values
4. Check if the login form has `autocomplete="off"` to prevent browser password storage:
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
5. Look for credentials stored in hidden form fields or JavaScript variables in the response

## Payloads

Not applicable - this is primarily an analysis and token security test. Testing involves examining and manipulating existing tokens rather than injecting payloads.

## Detection Criteria

A finding should be logged when:
- Remember-me tokens contain plaintext or encoded credentials
- Tokens are predictable or can be forged for other users
- Tokens lack the `Secure` flag (transmitted over HTTP)
- Tokens lack the `HttpOnly` flag (accessible via JavaScript)
- Tokens remain valid after logout or password change
- Token expiration is excessively long (e.g., years)
- Credentials are stored in cookies, local storage, or hidden fields
- `SameSite` attribute is missing from persistent cookies

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Plaintext credentials stored in cookies | High |
| Remember-me tokens can be forged for arbitrary users | High |
| Tokens remain valid after password change | High |
| Tokens not invalidated upon logout | Medium |
| Missing `Secure` flag on remember-me cookie | Medium |
| Missing `HttpOnly` flag on remember-me cookie | Medium |
| Token expiration exceeds 30 days | Low |
| Missing `SameSite` attribute on persistent cookie | Low |
| `autocomplete` not disabled on password fields | Low |

## Remediation

- Never store credentials (plaintext or encoded) in cookies or client-side storage
- Generate cryptographically random, non-guessable remember-me tokens
- Store a hashed version of the token server-side, tied to the user account
- Invalidate all remember-me tokens upon logout and password change
- Set reasonable expiration periods (7-30 days maximum)
- Always set `Secure`, `HttpOnly`, and `SameSite` attributes on persistent cookies
- Implement token rotation: issue a new token on each use and invalidate the old one
- Limit the number of active remember-me tokens per account
- Allow users to view and revoke active persistent sessions

## References

- [OWASP Testing Guide - Vulnerable Remember Password](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-539: Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

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

- V2 Authentication — credential storage, lockout, MFA.
- V3 Session Management — session binding and rotation.

## CWE references

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-798: Use of Hard-coded Credentials

## Rynix tooling

- Primary tools: ``auth_login``, ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test password policy, lockout, and MFA bypass paths.
- Verify tokens/sessions invalidated on logout and password change.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

