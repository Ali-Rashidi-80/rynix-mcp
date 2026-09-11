---
id: WSTG-ATHN-11
title: Testing Multi-Factor Authentication
category: Authentication
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
---

# WSTG-ATHN-11: Testing Multi-Factor Authentication

## Summary

Multi-factor authentication (MFA) adds a second verification layer beyond passwords, typically using something the user has (phone, hardware key) or something the user is (biometrics). However, MFA implementations can contain flaws that allow bypass. Common weaknesses include race conditions in token validation, reusable OTP codes, brute-forceable tokens, insecure fallback mechanisms, flawed step-up authentication logic, and missing MFA enforcement on alternative channels. A bypassed MFA renders the additional security layer entirely ineffective.

## Test Objectives

- Test if MFA can be bypassed by skipping the second factor verification step
- Check if OTP/TOTP codes can be brute-forced
- Verify that MFA tokens are single-use and time-limited
- Test fallback and recovery mechanisms for weaknesses
- Identify race conditions in MFA validation
- Verify MFA is enforced consistently across all access paths

## Prerequisites

- Target application implements multi-factor authentication
- Valid user account with MFA enabled
- Access to the MFA device/method for legitimate testing
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Map the MFA Flow

**CLI Actions:**
1. Complete a full MFA login flow and capture all requests
2. Use `curl` to document the complete authentication sequence
3. Identify the specific requests for each step:
   - Step 1: Username/password submission
   - Step 2: MFA challenge presentation
   - Step 3: MFA code submission
   - Step 4: Authenticated session establishment
4. Use `curl` with pattern `mfa|otp|totp|2fa|two.?factor|verify.?code|challenge|token|sms.?code` to find all MFA-related endpoints
5. Use `save to manual-review file` to save key requests in the MFA flow for manipulation

### Step 2: Test MFA Step Bypass

**CLI Actions:**
1. Complete Step 1 (username/password) and capture the intermediate session or token
2. Use `curl` to skip Step 2/3 and directly access a protected resource:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<post_step1_session>
   ``
3. Test if the MFA verification endpoint can be skipped by directly navigating to the post-auth URL:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   Cookie: session=<post_step1_session>
   ``
4. Test if adding a parameter bypasses MFA:
   ``
   GET /dashboard?mfa_verified=true HTTP/1.1
   Host: target.com
   Cookie: session=<post_step1_session>
   ``
5. Test if changing the response from Step 1 (intercepting "MFA required" and changing to "authenticated") allows bypass
6. Use `curl` to test direct API access after Step 1:
   ``
   GET /api/user/data HTTP/1.1
   Host: target.com
   Cookie: session=<post_step1_session>
   ``

### Step 3: Test OTP Brute-Force

**CLI Actions:**
1. Initiate the MFA challenge to receive a code
2. Use `save to manual-review file` with the OTP submission request
3. Use `curl` to test multiple incorrect codes and check for rate limiting:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   code=000000
   ``
4. Send 10-20 incorrect codes and monitor for:
   - Account lockout
   - Session invalidation
   - Rate limiting (HTTP 429)
   - CAPTCHA enforcement
   - Increasing delays
5. If no protection exists, use `fuzz-cli` to configure a brute-force attack:
   - For 6-digit OTP: range 000000-999999
   - For 4-digit OTP: range 0000-9999
6. Test if expired OTP codes from previous sessions are accepted

### Step 4: Test OTP Reuse

**CLI Actions:**
1. Request an MFA code and capture it
2. Use `curl` to submit the valid code and authenticate
3. Log out, then re-authenticate with username/password to trigger a new MFA challenge
4. Use `curl` to submit the old code from step 1:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<new_mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   code=<previously_used_code>
   ``
5. Test if the same code can be used multiple times within its validity window:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   code=<valid_code>
   ``
   Immediately replay:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<same_session>
   Content-Type: application/x-www-form-urlencoded

   code=<same_valid_code>
   ``

### Step 5: Test Fallback and Recovery Mechanisms

**CLI Actions:**
1. Use `curl` with pattern `backup|recovery|fallback|alternative|bypass|lost.?device|cant.?access` to find fallback MFA endpoints
2. Use `curl` to test the "lost device" or "can't access" flow:
   ``
   POST /mfa/fallback HTTP/1.1
   Host: target.com
   Cookie: session=<mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   method=email
   ``
3. Test if backup codes are predictable or brute-forceable:
   ``
   POST /mfa/verify-backup HTTP/1.1
   Host: target.com
   Cookie: session=<mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   backup_code=12345678
   ``
4. Test if the fallback mechanism effectively disables MFA:
   ``
   POST /mfa/disable HTTP/1.1
   Host: target.com
   Cookie: session=<mfa_pending_session>
   Content-Type: application/x-www-form-urlencoded

   reason=lost_device
   ``
5. Check if security questions alone can bypass MFA during recovery
6. Use `rynix_plugin_run('template-scan')` to review any MFA-related findings

### Step 6: Test Race Conditions

**CLI Actions:**
1. Initiate the MFA challenge
2. Use `save to manual-review file` to prepare two simultaneous OTP submission requests
3. Use `curl` to submit the same valid code in rapid succession (race condition test):
   - Send the valid OTP in Request A
   - Immediately send the same OTP in Request B with a different session
4. Test if simultaneous login attempts can share the MFA verification:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<session_A>
   Content-Type: application/x-www-form-urlencoded

   code=<valid_code>
   ``
   Simultaneously:
   ``
   POST /mfa/verify HTTP/1.1
   Host: target.com
   Cookie: session=<session_B>
   Content-Type: application/x-www-form-urlencoded

   code=<same_valid_code>
   ``
5. Test if completing MFA on one session grants access to another concurrent session for the same user

### Step 7: Test MFA Enrollment and Disabling

**CLI Actions:**
1. Use `curl` to test if MFA can be disabled without re-authentication:
   ``
   POST /account/mfa/disable HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
2. Test if MFA setup reveals the TOTP secret in the response:
   ``
   POST /account/mfa/setup HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
3. Use `base64 -d` to decode any QR code data or TOTP secrets returned in responses
4. Test if MFA can be re-enrolled (replacing the existing second factor) without verifying the current second factor:
   ``
   POST /account/mfa/reset HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/json

   {"method":"totp"}
   ``
5. Check if CSRF protection exists on MFA disable/reset endpoints (an attacker could trick a user into disabling their own MFA)

## Payloads

### OTP Brute-Force Ranges
```
4-digit: 0000-9999
6-digit: 000000-999999
8-digit backup codes: 00000000-99999999
```

### MFA Bypass Parameters
```
mfa_verified=true
otp_verified=1
skip_mfa=true
two_factor=passed
mfa=bypass
verify=true
step=3
authenticated=true
```

### Common Backup Code Formats
```
XXXX-XXXX (8 alphanumeric with dash)
XXXXXXXX (8 alphanumeric)
XXXXXX (6 digit numeric)
XXXX XXXX XXXX (12 alphanumeric with spaces)
```

## Detection Criteria

A finding should be logged when:
- Protected resources are accessible after Step 1 without completing MFA
- OTP codes can be brute-forced without rate limiting or lockout
- OTP codes are reusable (not single-use)
- Fallback mechanisms bypass MFA entirely (e.g., email link skips MFA)
- Race conditions allow shared MFA verification across sessions
- MFA can be disabled without re-authenticating the second factor
- TOTP secrets are exposed in API responses
- Backup codes are predictable or have insufficient entropy
- MFA is not enforced on alternative channels (mobile API, legacy endpoints)
- CSRF allows an attacker to disable a victim's MFA

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| MFA step can be bypassed entirely (direct access after Step 1) | Critical |
| OTP brute-force possible (no rate limiting on 4-6 digit codes) | Critical |
| Race condition allows MFA verification sharing across sessions | High |
| Fallback mechanism allows MFA bypass without proper verification | High |
| MFA not enforced on alternative API channels | High |
| OTP codes are reusable within validity window | Medium |
| MFA can be disabled without second-factor re-verification | Medium |
| TOTP secret exposed in API response after initial setup | Medium |
| Backup codes have low entropy or are predictable | Medium |
| CSRF on MFA disable endpoint | Medium |
| OTP validity window is excessively long (> 5 minutes) | Low |

## Remediation

- Enforce MFA verification server-side before granting access to any protected resource
- Implement strict rate limiting on OTP verification (e.g., 3-5 attempts, then lockout)
- Ensure OTP codes are single-use and expire after a short window (30-60 seconds for TOTP)
- Use cryptographically random backup codes with sufficient entropy
- Require current second-factor verification before disabling or re-enrolling MFA
- Implement atomic session state transitions to prevent race conditions
- Enforce MFA consistently across all channels (web, mobile, API, legacy)
- Protect MFA enrollment and disabling endpoints with CSRF tokens
- Do not expose TOTP secrets after initial enrollment
- Log and alert on MFA bypass attempts and brute-force patterns
- Ensure fallback mechanisms still require strong identity verification
- Consider WebAuthn/FIDO2 for phishing-resistant MFA

## References

- [OWASP Testing Guide - Testing Multi-Factor Authentication](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication)
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

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

