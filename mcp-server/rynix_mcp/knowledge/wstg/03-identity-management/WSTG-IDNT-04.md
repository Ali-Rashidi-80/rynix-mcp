---
id: WSTG-IDNT-04
title: Testing for Account Enumeration and Guessability
category: Identity Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessability
---

# WSTG-IDNT-04: Testing for Account Enumeration and Guessability

## Summary

Account enumeration occurs when an application reveals whether a given username or email exists in the system. Attackers use this to compile a list of valid accounts for targeted attacks like brute-force, credential stuffing, or phishing.

## Test Objectives

- Determine whether it is possible to enumerate valid usernames or email addresses
- Identify differences in application responses for valid vs. invalid accounts
- Test all authentication-related endpoints for enumeration vectors

## Prerequisites

- Target application has login, registration, and/or password reset functionality
- At least one known valid account (for comparison)
- At least one known invalid account

## Test Steps

### Step 1: Test Login Page for Enumeration

**CLI Actions:**
1. Use `curl` to submit a login request with a **known valid username** and **wrong password**
2. Use `curl` to submit a login request with a **known invalid username** and **wrong password**
3. Compare responses carefully:

**What to Compare:**
- Response body text (error messages)
- HTTP status codes
- Response length (byte count)
- Response time (timing attacks)
- Set-Cookie headers
- Any redirect differences

**Common Enumeration Indicators:**
- Valid user: "Incorrect password" vs Invalid user: "User not found"
- Valid user: "Invalid credentials" (200, 1847 bytes) vs Invalid user: "Invalid credentials" (200, 1842 bytes)
- Valid user: response in 450ms vs Invalid user: response in 120ms (timing difference)

### Step 2: Test Registration Page

**CLI Actions:**
1. Use `curl` to attempt registration with a **known existing username/email**
2. Use `curl` to attempt registration with a **non-existing username/email**
3. Compare responses for differences that reveal account existence

**What to Look For:**
- "This email is already registered"
- "Username is taken"
- Different form validation responses

### Step 3: Test Password Reset

**CLI Actions:**
1. Use `curl` to request password reset for a **known valid email**
2. Use `curl` to request password reset for an **invalid email**
3. Compare responses

**What to Look For:**
- "Reset link sent to your email" vs "Email not found"
- Different response lengths or status codes
- Timing differences (sending an actual email takes longer)

### Step 4: Test API Endpoints

**CLI Actions:**
1. Use `curl` to find API calls related to user lookup
2. Use `curl` to test endpoints like:
   ``
   GET /api/users/check?username=admin
   GET /api/users/check?email=admin@target.com
   POST /api/auth/check-email
   ``
3. Check for verbose responses that confirm account existence

### Step 5: Timing-Based Enumeration

**CLI Actions:**
1. Use `curl` to send 10 login requests with a valid username and record response times
2. Use `curl` to send 10 login requests with an invalid username and record response times
3. If there's a consistent timing difference (e.g., valid users take 200ms longer due to password hashing), enumeration is possible via timing

## Payloads

### Common Test Usernames
```
admin
administrator
root
user
test
guest
info
support
sales
webmaster
```

### Common Test Emails
```
admin@target.com
info@target.com
test@target.com
support@target.com
noreply@target.com
```

## Detection Criteria

A finding should be logged when:
- Different error messages are returned for valid vs. invalid accounts
- Response length differs between valid and invalid account submissions
- Consistent timing differences exist (>50ms average difference)
- API endpoints explicitly confirm account existence
- Registration or password reset reveals existing accounts

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| API endpoint returns explicit "user exists" / "user not found" | Medium |
| Login page shows different error messages for valid/invalid users | Medium |
| Timing attack allows enumeration (>100ms consistent difference) | Low |
| Password reset confirms email existence | Low |
| Subtle response length differences only (< 20 bytes) | Low |

## Remediation

- Use generic error messages: "Invalid username or password" for all login failures
- Return identical responses (same length, same timing) for valid and invalid accounts
- Add artificial delay to normalize response times for authentication operations
- Password reset: always respond with "If this email exists, a reset link has been sent"
- Rate-limit authentication endpoints to slow enumeration attempts
- Consider CAPTCHA after several failed attempts

## References

- [OWASP Testing Guide - Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessability)
- [CWE-203: Observable Discrepancy](https://cwe.mitre.org/data/definitions/203.html)

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

