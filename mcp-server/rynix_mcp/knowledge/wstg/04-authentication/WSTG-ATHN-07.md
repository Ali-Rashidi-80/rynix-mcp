---
id: WSTG-ATHN-07
title: Testing for Weak Password Policy
category: Authentication
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy
---

# WSTG-ATHN-07: Testing for Weak Password Policy

## Summary

A weak password policy allows users to set passwords that are easily guessable, brute-forced, or found in common password dictionaries. The policy should enforce minimum length, character complexity, and prevent the use of commonly breached passwords. Additionally, the application should prevent password reuse and enforce reasonable password change intervals. Weak policies are a leading cause of unauthorized access through credential-based attacks.

## Test Objectives

- Determine the minimum and maximum password length requirements
- Test character complexity enforcement (uppercase, lowercase, digits, special characters)
- Check if common or breached passwords are rejected
- Verify that password reuse is prevented
- Test if the password policy is enforced consistently across all password-setting endpoints

## Prerequisites

- Target application has user registration and password change functionality
- Ability to create test accounts
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Test Minimum Password Length

**CLI Actions:**
1. Use `save to manual-review file` with the registration or password change request
2. Use `curl` to test progressively shorter passwords:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=lentest1&email=len1@test.com&password=a
   ``
3. Continue testing increasing lengths:
   ``
   password=ab
   password=abc
   password=abcd
   password=abcde
   password=abcdef
   password=abcdefg
   password=abcdefgh
   ``
4. Document the minimum accepted length
5. Test with an empty password:
   ``
   username=lentest0&email=len0@test.com&password=
   ``

### Step 2: Test Maximum Password Length

**CLI Actions:**
1. Use `curl` to test very long passwords:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=maxlen&email=maxlen@test.com&password=AAAA...(128 chars)
   ``
2. Test progressively longer passwords (128, 256, 512, 1024 characters)
3. Check if extremely long passwords cause errors or truncation
4. Verify that the password set is the full-length password by logging in with it:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=maxlen&password=AAAA...(128 chars)
   ``
5. Test if the password is truncated by logging in with a shorter version

### Step 3: Test Complexity Requirements

**CLI Actions:**
1. Use `curl` to test passwords lacking specific character classes:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=complex1&email=c1@test.com&password=alllowercase
   ``
2. Test each complexity dimension independently:
   ``
   password=ALLUPPERCASE          (no lowercase, digits, or special)
   password=alllowercase          (no uppercase, digits, or special)
   password=1234567890            (digits only)
   password=!@#$%^&*()           (special characters only)
   password=Uppercase1            (no special character)
   password=lowercase1!           (no uppercase)
   password=UPPERCASE1!           (no lowercase)
   password=Abcdefgh!             (no digit)
   ``
3. Document which character classes are required vs. optional
4. Test if spaces are allowed in passwords:
   ``
   password=pass word with spaces
   ``
5. Use `curl --data-urlencode` to encode passwords with special characters

### Step 4: Test Common/Breached Password Rejection

**CLI Actions:**
1. Use `curl` to test commonly used passwords:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=common1&email=cmn1@test.com&password=password
   ``
2. Test additional common passwords:
   ``
   password=123456
   password=password123
   password=qwerty
   password=letmein
   password=welcome
   password=admin123
   password=iloveyou
   password=Password1
   password=abc123
   ``
3. Test context-specific passwords:
   ``
   password=<company_name>123
   password=<application_name>!
   password=<target_domain>1
   ``
4. Use `fuzz-cli` to batch-test a list of top 100 common passwords if manual testing reveals no blocking

### Step 5: Test Password Reuse Prevention

**CLI Actions:**
1. Create an account with password `OldPassword1!`
2. Change the password to `NewPassword1!`
3. Use `curl` to attempt changing back to the original password:
   ``
   POST /account/change-password HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   current_password=NewPassword1!&new_password=OldPassword1!&confirm_password=OldPassword1!
   ``
4. Test if the password history check is limited (change password N times, then try the first password again)
5. Test if slightly modified versions of old passwords are accepted:
   ``
   new_password=OldPassword2!
   new_password=OldPassword1!!
   ``

### Step 6: Test Password Policy Consistency Across Endpoints

**CLI Actions:**
1. Use `curl` with pattern `password|passwd|pass|pwd` to identify all endpoints that accept password input
2. Test the password policy on each endpoint:
   - Registration: `/register`
   - Password change: `/account/change-password`
   - Password reset: `/reset-password?token=xxx`
   - Admin user creation: `/admin/users/create`
   - API password update: `/api/users/password`
3. Use `curl` to submit a weak password (`a`) on each endpoint
4. Compare results to determine if all endpoints enforce the same policy
5. Use `rynix_plugin_run('template-scan')` to check for any password policy findings

## Payloads

### Weak Passwords for Testing
```
a
ab
abc
1234
password
123456
qwerty
letmein
welcome
admin
root
test
guest
master
dragon
monkey
shadow
sunshine
trustno1
iloveyou
```

### Complexity Test Passwords
```
alllowercase
ALLUPPERCASE
1234567890
!@#$%^&*()
Aa1!
Password1
password1!
PASSWORD1!
Abcdefgh!
```

### Context-Specific Passwords
```
<company>123
<company>!
<domain>2024
Summer2024!
Winter2024!
Welcome1!
Changeme1!
```

## Detection Criteria

A finding should be logged when:
- Passwords shorter than 8 characters are accepted
- No complexity requirements are enforced (e.g., digits, special characters)
- Common or breached passwords (top 10,000) are accepted
- Password reuse is not prevented
- Empty passwords are accepted
- Password policy differs across endpoints
- Excessively long passwords are truncated silently
- Context-specific passwords (company name, domain) are accepted

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No password policy at all (any string accepted) | High |
| Empty passwords are accepted | High |
| Common passwords (top 100) accepted | High |
| Minimum length less than 8 characters | Medium |
| No complexity requirements enforced | Medium |
| Password reuse is not prevented | Medium |
| Policy not enforced on all endpoints (e.g., API allows weak passwords) | Medium |
| Password silently truncated beyond a certain length | Low |
| No check against breached password databases | Low |

## Remediation

- Enforce a minimum password length of at least 8 characters (12+ recommended)
- Allow maximum password length of at least 64 characters
- Require at least 3 of 4 character classes: uppercase, lowercase, digits, special characters
- Check passwords against a breached password database (e.g., Have I Been Pwned)
- Prevent reuse of the last 5-10 passwords
- Do not silently truncate passwords
- Enforce the same password policy across all endpoints (registration, change, reset, API)
- Consider implementing password strength meters for user guidance
- Support passphrase-style passwords (allow spaces and long inputs)
- Implement progressive lockout or rate limiting to mitigate brute-force attacks

## References

- [OWASP Testing Guide - Weak Password Policy](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [NIST SP 800-63B: Digital Identity Guidelines - Authentication](https://pages.nist.gov/800-63-3/sp800-63b.html)

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

