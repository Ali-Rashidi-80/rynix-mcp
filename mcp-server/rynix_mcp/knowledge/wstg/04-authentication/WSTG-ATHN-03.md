---
id: WSTG-ATHN-03
title: Testing for Weak Lock Out Mechanism
category: Authentication
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism
---

# WSTG-ATHN-03: Testing for Weak Lock Out Mechanism

## Summary

Account lockout mechanisms protect against brute-force password attacks by temporarily or permanently locking accounts after a number of failed login attempts. A weak or absent lockout mechanism allows unlimited password guessing.

## Test Objectives

- Determine if an account lockout mechanism exists
- Evaluate the lockout threshold and duration
- Test if the lockout can be bypassed
- Assess if the lockout mechanism can be abused for denial of service

## Prerequisites

- Target application has a login page
- A test account is available (to avoid locking legitimate accounts)

## Test Steps

### Step 1: Test for Lockout Existence

**CLI Actions:**
1. Use `curl` to submit 10-15 login attempts with a valid username and incorrect passwords
2. After each attempt, note the response message, status code, and response time
3. Check if the account eventually gets locked

### Step 2: Determine Lockout Threshold

**CLI Actions:**
1. Use a fresh test account
2. Use `curl` to submit login attempts one at a time with wrong passwords
3. Count how many failures before lockout occurs
4. Common thresholds: 3, 5, 10 attempts
5. If no lockout after 20+ attempts, there is likely no lockout mechanism

### Step 3: Determine Lockout Duration

**CLI Actions:**
1. After triggering a lockout, wait and test at intervals:
   - Wait 1 minute, try login with `curl`
   - Wait 5 minutes, try login
   - Wait 15 minutes, try login
   - Wait 30 minutes, try login
2. Note when the account becomes accessible again

### Step 4: Test Lockout Bypass Techniques

**CLI Actions:**

**a) IP rotation bypass:**
1. Use `curl` with different `X-Forwarded-For` headers:
   ``
   POST /login HTTP/1.1
   Host: target.com
   X-Forwarded-For: 1.2.3.4
   ``

**b) Case variation bypass:**
1. Try username variations: `admin`, `Admin`, `ADMIN`, `aDmIn`
2. Try with spaces: `admin `, ` admin`

**c) Rate limit bypass:**
1. Add null bytes or extra characters to the username
2. Test if adding/removing URL parameters resets the counter

### Step 5: Test for DoS via Account Lockout

**CLI Actions:**
1. Determine if an attacker can lock out any account by knowing the username
2. Check if there's a CAPTCHA or other protection after initial failures
3. Assess the impact: can an attacker lock out all admin accounts?

## Payloads

### Username Variations for Bypass Testing
```
admin
Admin
ADMIN
admin%00
admin%20
%20admin
admin+
```

### X-Forwarded-For Values for IP Bypass
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Automated Lockout Testing with hydra

**CLI Actions:**
Use `hydra` to send multiple failed login attempts and observe lockout behavior:

```bash
rynix_plugin_run('wstg') hydra -l admin -P /opt/wordlists/passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid" -t 1 -o ./engagements/<eid>/tool-output/hydra-lockout.txt
```

Monitor the responses after 5, 10, 20, and 50 attempts. Look for:
- Account lockout messages (indicates lockout mechanism exists)
- CAPTCHA enforcement after N failed attempts
- Rate limiting (increasing response times or 429 status codes)
- No change in behavior (indicates weak/missing lockout -- log as finding)

Use `-t 1` (single thread) to avoid false positives from parallel lockout triggers.

## Detection Criteria

A finding should be logged when:
- No account lockout mechanism exists (unlimited login attempts)
- Lockout threshold is too high (>10 attempts)
- Lockout duration is too short (<5 minutes)
- Lockout can be bypassed via IP header manipulation
- Lockout can be used to deny service to legitimate users without CAPTCHA escalation
- CAPTCHA is not implemented after initial failed attempts

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No lockout mechanism at all | Medium |
| Lockout bypassed via header manipulation | Medium |
| Lockout threshold >10 without CAPTCHA | Low |
| Lockout causes permanent account DoS | Low |
| Short lockout duration (<2 minutes) | Low |
| Reasonable lockout with CAPTCHA escalation | Informational |

## Remediation

- Implement account lockout after 5 failed attempts
- Lock accounts for 15-30 minutes, then automatically unlock
- Use progressive delays (1s, 2s, 4s, 8s...) instead of or in addition to lockout
- Implement CAPTCHA after 3 failed attempts
- Do not rely on client IP alone for rate limiting
- Alert administrators on repeated lockouts
- Consider multi-factor authentication for high-value accounts

## References

- [OWASP Testing Guide - Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
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

