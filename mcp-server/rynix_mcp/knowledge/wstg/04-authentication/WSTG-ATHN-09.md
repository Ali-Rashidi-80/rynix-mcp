---
id: WSTG-ATHN-09
title: Testing for Weak Password Change or Reset Functionality
category: Authentication
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionality
---

# WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionality

## Summary

Password change and reset mechanisms are critical authentication functions. If implemented poorly, they can be exploited for account takeover. Weaknesses include predictable reset tokens, lack of token expiration, missing current password verification for changes, IDOR vulnerabilities allowing password changes for other users, and token leakage through referrer headers or URL parameters. These flaws can allow an attacker to change any user's password and gain full access to their account.

## Test Objectives

- Test the security of password reset token generation and lifecycle
- Verify that password change requires current password verification
- Check for IDOR or authorization flaws in password change endpoints
- Test token expiration and single-use enforcement
- Identify token leakage through URLs, referrer headers, or responses

## Prerequisites

- Target application has password change and password reset functionality
- Valid user accounts for testing
- Ability to receive password reset emails (or access to the reset link)
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Analyze Password Reset Token

**CLI Actions:**
1. Initiate a password reset for a test account
2. Use `curl` to capture the reset flow
3. Extract the reset token from the email link or API response
4. Use `base64 -d` to check if the token is base64-encoded and reveals user information
5. Use `python3 -c "import urllib.parse; ..."` to decode any URL-encoded components
6. Request multiple reset tokens for the same account and compare them:
   ``
   POST /forgot-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   email=testuser@test.com
   ``
7. Analyze tokens for predictable patterns (sequential numbers, timestamps, user ID hashes)
8. Request tokens for different accounts at the same time and look for sequential or related values

### Step 2: Test Token Expiration and Reuse

**CLI Actions:**
1. Request a password reset token
2. Wait for different intervals (5 min, 15 min, 1 hour, 24 hours) and test if the token still works
3. Use `curl` to submit the token after the expected expiration:
   ``
   POST /reset-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   token=<reset_token>&new_password=NewPass123!&confirm_password=NewPass123!
   ``
4. After successfully resetting a password with a token, use `curl` to reuse the same token:
   ``
   POST /reset-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   token=<same_reset_token>&new_password=AnotherPass123!&confirm_password=AnotherPass123!
   ``
5. Test if requesting a new reset token invalidates previous tokens

### Step 3: Test Password Change Authorization

**CLI Actions:**
1. Capture the password change request while logged in
2. Use `save to manual-review file` to modify the request
3. Use `curl` to test changing password without the current password:
   ``
   POST /account/change-password HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   new_password=NewPass123!&confirm_password=NewPass123!
   ``
4. Test IDOR by changing another user's password:
   ``
   POST /api/users/OTHER_USER_ID/password HTTP/1.1
   Host: target.com
   Cookie: session=<attacker_session>
   Content-Type: application/json

   {"new_password":"Hacked123!"}
   ``
5. Test changing password with an invalid current password:
   ``
   POST /account/change-password HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   current_password=wrong&new_password=NewPass123!&confirm_password=NewPass123!
   ``

### Step 4: Test Token Leakage

**CLI Actions:**
1. Click the password reset link and observe the full request
2. Use `curl` to check if the token appears in the URL:
   ``
   GET /reset-password?token=abc123def456 HTTP/1.1
   Host: target.com
   ``
3. After landing on the reset page, check if external resources are loaded (tracking scripts, images) that receive the `Referer` header containing the token
4. Use `curl` with pattern `Referer.*token=|Referer.*reset` to find token leakage in referrer headers
5. Check if the token appears in any JavaScript or AJAX requests captured in proxy history
6. Test if the token is logged in server responses:
   ``
   GET /api/audit-log HTTP/1.1
   Host: target.com
   Cookie: session=<admin_session>
   ``

### Step 5: Test Password Reset Flow Bypass

**CLI Actions:**
1. Start the password reset flow and capture all steps
2. Use `curl` to map out the complete multi-step reset process
3. Use `curl` to test skipping to the final reset step directly:
   ``
   POST /reset-password/complete HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   email=victim@test.com&new_password=Hacked123!
   ``
4. Test if the reset endpoint accepts a user identifier instead of a token:
   ``
   POST /reset-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   user_id=VICTIM_ID&new_password=Hacked123!
   ``
5. Test manipulating the email parameter to receive the reset token at an attacker-controlled email:
   ``
   POST /forgot-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   email=victim@test.com&notification_email=attacker@evil.com
   ``

### Step 6: Test Host Header Injection in Reset Flow

**CLI Actions:**
1. Use `curl` to test Host header manipulation during password reset:
   ``
   POST /forgot-password HTTP/1.1
   Host: attacker.com
   Content-Type: application/x-www-form-urlencoded

   email=victim@test.com
   ``
2. Test with X-Forwarded-Host:
   ``
   POST /forgot-password HTTP/1.1
   Host: target.com
   X-Forwarded-Host: attacker.com
   Content-Type: application/x-www-form-urlencoded

   email=victim@test.com
   ``
3. If the reset link is generated using the Host header, the token could be sent to the attacker's domain
4. Use `rynix_plugin_run('template-scan')` to check for any host header injection findings

### Step 7: Test Session Invalidation After Password Reset

**CLI Actions:**
1. Log into the account on two separate sessions (capture both session tokens)
2. Reset the password using one session
3. Use `curl` to test if the other session is still valid:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<old_session_token>
   ``
4. Test if API tokens remain valid after password reset:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Authorization: Bearer <old_api_token>
   ``

## Payloads

### Host Header Injection Payloads
```
Host: attacker.com
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Original-URL: /reset?token=steal
Host: target.com@attacker.com
Host: target.com%0d%0aX-Injected: header
```

### Token Manipulation Payloads
```
token=
token=null
token=undefined
token=0
token=1
token=true
token=admin
token=../../../../etc/passwd
token=<original_token_with_last_char_changed>
```

## Detection Criteria

A finding should be logged when:
- Reset tokens are predictable or reversible
- Tokens do not expire within a reasonable timeframe (15-60 minutes)
- Tokens can be reused after successful reset
- Password change does not require current password verification
- IDOR allows changing other users' passwords
- Token is leaked through URL parameters and referrer headers
- Host header injection allows token theft
- Old sessions remain valid after password change or reset
- Reset flow steps can be bypassed or skipped

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Host header injection allows stealing reset tokens | Critical |
| Reset tokens are predictable or forgeable | Critical |
| IDOR allows changing any user's password | Critical |
| Reset flow steps can be bypassed entirely | High |
| Password change accepted without current password | High |
| Token does not expire (valid indefinitely) | High |
| Token reusable after successful password reset | Medium |
| Token leaked via referrer header to external domains | Medium |
| Old sessions not invalidated after password change | Medium |
| Token expiration is too long (> 1 hour) | Low |

## Remediation

- Generate cryptographically random reset tokens with sufficient entropy (128+ bits)
- Set token expiration to 15-60 minutes maximum
- Invalidate tokens immediately after successful use (single-use enforcement)
- Invalidate all previous tokens when a new reset is requested
- Always require current password for password change operations
- Invalidate all active sessions and tokens after a password change or reset
- Use POST-based token submission (not URL parameters) to prevent referrer leakage
- Validate the Host header against a whitelist to prevent header injection
- Implement rate limiting on password reset requests (per account and per IP)
- Do not reveal whether an email address exists during password reset
- Log all password change and reset events for audit purposes

## References

- [OWASP Testing Guide - Weak Password Change or Reset](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionality)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-620: Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)
- [CWE-302: Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

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

