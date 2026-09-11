---
id: WSTG-IDNT-02
title: Test User Registration Process
category: Identity Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process
---

# WSTG-IDNT-02: Test User Registration Process

## Summary

The user registration process is a critical identity management function. If improperly implemented, it can be abused to create fraudulent accounts, enumerate existing users, bypass identity verification, or inject malicious data. Testing focuses on identifying weaknesses in input validation, duplicate account handling, identity verification, and abuse prevention mechanisms.

## Test Objectives

- Determine if the registration process can be abused for mass account creation
- Test whether duplicate accounts can be created with the same identity
- Identify weak or missing input validation on registration fields
- Verify that identity verification (email, phone) is properly enforced
- Check for race conditions in the registration process

## Prerequisites

- Target application has a user registration feature
- Understanding of required registration fields
- Docker pentest container is capturing traffic
- Ability to receive verification emails or SMS (if applicable)

## Test Steps

### Step 1: Analyze Registration Form and Requests

**CLI Actions:**
1. Complete a normal registration flow and capture all requests
2. Use `curl` to identify all requests involved in the registration process
3. Use `save to manual-review file` to save the registration request for modification
4. Document all required fields, optional fields, and hidden parameters

### Step 2: Test for Duplicate Account Creation

**CLI Actions:**
1. Register an account with a specific email/username
2. Use `curl` to attempt registering again with the same email/username:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=existinguser&email=existing@test.com&password=Password123!
   ``
3. Test case-sensitivity variations using `curl`:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=ExistingUser&email=Existing@test.com&password=Password123!
   ``
4. Test with leading/trailing whitespace and special Unicode characters:
   ``
   username=existinguser%20&email=existing@test.com
   username=%20existinguser&email=existing@test.com
   ``
5. Use `curl --data-urlencode` to properly encode special characters in test payloads

### Step 3: Test Input Validation on Registration Fields

**CLI Actions:**
1. Use `save to manual-review file` to set up the registration request
2. Use `curl` to test each field with invalid or malicious input:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=<script>alert(1)</script>&email=notanemail&password=a
   ``
3. Test excessively long values:
   ``
   username=AAAA....(5000 chars)&email=test@test.com&password=Password123!
   ``
4. Test SQL injection in registration fields:
   ``
   username=admin'--&email=test@test.com&password=Password123!
   ``
5. Test special characters and Unicode in username:
   ``
   username=admin%00&email=test@test.com&password=Password123!
   ``
6. Use `curl --data-urlencode` to encode payloads as needed

### Step 4: Test Email Verification Bypass

**CLI Actions:**
1. Register an account and capture the verification flow with `curl`
2. Use `curl` to attempt accessing the application before email verification:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<unverified_session>
   ``
3. Use `curl` with pattern `verify|confirm|activate|token` to find verification endpoints
4. Use `curl` to test manipulating the verification token:
   ``
   GET /verify?token=manipulated_token HTTP/1.1
   Host: target.com
   ``
5. Test if the verification endpoint accepts previously used or expired tokens

### Step 5: Test Mass Registration (Automation Abuse)

**CLI Actions:**
1. Use `curl` to submit multiple registration requests rapidly and check if rate limiting exists:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=botuser1&email=bot1@test.com&password=Password123!
   ``
2. Check if CAPTCHA or other anti-automation mechanisms are present
3. If CAPTCHA exists, test if the registration endpoint accepts requests without the CAPTCHA parameter
4. Use `fuzz-cli` to configure batched registration attempts with incremented values to test rate limits

### Step 6: Test Hidden Parameter Injection

**CLI Actions:**
1. Use `curl` to add unexpected parameters to the registration request:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":"newuser","email":"new@test.com","password":"Password123!","role":"admin","isVerified":true,"active":true}
   ``
2. Test mass assignment by adding role, permission, or status fields
3. Use `curl` with pattern `role|admin|verified|active|status|level` to identify any hidden fields in previous responses

## Payloads

### Username Injection Payloads
```
admin
admin'--
admin' OR '1'='1
<script>alert(1)</script>
${7*7}
../../../etc/passwd
admin%00
admin\x00suffix
```

### Email Bypass Payloads
```
test@test.com
test+tag@test.com
test@test.com%00@evil.com
"test"@test.com
test@[127.0.0.1]
test@test.com\n
```

### Duplicate Account Variations
```
user
User
USER
 user
user
us​er  (zero-width character)
```

## Detection Criteria

A finding should be logged when:
- Duplicate accounts can be created with the same identity
- Registration fields lack proper input validation
- Email/phone verification can be bypassed
- No rate limiting exists on registration endpoints
- Hidden parameters allow privilege escalation during registration
- CAPTCHA or anti-automation can be bypassed
- Registration process is vulnerable to injection attacks

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Hidden parameter injection grants admin role during registration | High |
| Email verification can be fully bypassed | High |
| No rate limiting allows mass account creation | Medium |
| Duplicate accounts can be created via case/encoding tricks | Medium |
| CAPTCHA can be bypassed on registration | Medium |
| Weak input validation on username/email fields | Low |
| Missing server-side validation (client-side only) | Low |

## Remediation

- Normalize usernames and emails before storage (lowercase, trim whitespace)
- Implement strong server-side input validation on all registration fields
- Require and enforce email or phone verification before account activation
- Implement rate limiting and CAPTCHA on registration endpoints
- Use parameterized queries to prevent injection attacks
- Reject unexpected parameters (allowlist known fields only)
- Log and monitor for mass registration attempts
- Implement account lockout or cooldown periods for repeated registration from the same IP

## References

- [OWASP Testing Guide - Test User Registration Process](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

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

- V2 Authentication — identity lifecycle and enumeration resistance.
- V4 Access Control — role assignment integrity.

## CWE references

- CWE-287: Improper Authentication
- CWE-306: Missing Authentication

## Rynix tooling

- Primary tools: ``http_probe``, ``auth_login``, ``compare_role_response``

## Test focus

- Test username enumeration via response timing and error messages.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

