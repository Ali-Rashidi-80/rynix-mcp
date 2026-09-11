---
id: WSTG-BUSL-05
title: Test Number of Times a Function Can Be Used
category: Business Logic
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used
---

# WSTG-BUSL-05: Test Number of Times a Function Can Be Used

## Summary

Many application functions should have usage limits: coupons should be single-use, password reset tokens should expire after use, free trials should not be re-registerable, and API endpoints should be rate-limited. When these limits are not enforced, attackers can abuse functionality through repeated use, leading to resource exhaustion, financial loss, denial of service, or circumvention of business constraints.

## Test Objectives

- Identify functions that should have usage limits
- Test if single-use tokens or codes can be reused
- Assess rate limiting on sensitive endpoints
- Test for resource exhaustion through repeated function calls
- Verify that free trial and promotional restrictions are enforced

## Prerequisites

- Target application is accessible through Docker pentest container
- Functions with expected usage limits have been identified
- Test accounts and test data (coupon codes, reset tokens) are available

## Test Steps

### Step 1: Identify Functions with Expected Limits

**CLI Actions:**
Use `curl` to map application functionality and identify operations that should be limited:

- Coupon/discount code redemption
- Password reset token usage
- Email verification links
- Free trial registration
- OTP/MFA code validation
- Download or export limits
- API call quotas

### Step 2: Test Single-Use Token Reuse

**CLI Actions:**
Use `save to manual-review file` to capture a single-use operation. After the first successful use, replay the same request:

```
POST /api/coupon/redeem HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"coupon_code": "SAVE20", "order_id": "ORD001"}
```

Send this request again with the same coupon code. Then try with a different order_id:

```
POST /api/coupon/redeem HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"coupon_code": "SAVE20", "order_id": "ORD002"}
```

Check if the coupon is applied again.

### Step 3: Test Password Reset Token Reuse

**CLI Actions:**
Use `curl` to trigger a password reset:

```
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json

{"email": "testuser@example.com"}
```

After using the reset token once, use `curl` to try the same token again:

```
POST /reset-password HTTP/1.1
Host: target.com
Content-Type: application/json

{"token": "abc123resettoken", "new_password": "NewPass456!"}
```

Check if the token can be reused to set the password multiple times.

### Step 4: Test Rate Limiting

**CLI Actions:**
Use `fuzz-cli` to send rapid repeated requests to sensitive endpoints:

Login endpoint:
```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "testuser", "password": "§password§"}
```

Configure Intruder with a wordlist and maximum request rate. Monitor for:
- HTTP 429 (Too Many Requests) responses
- Account lockout after N failed attempts
- CAPTCHA challenges
- Increasing response delays

Test rate limiting on:
- Login attempts
- Password reset requests
- OTP verification
- API endpoints
- File upload/download

### Step 5: Test Free Trial Abuse

**CLI Actions:**
Use `curl` to register for a free trial:

```
POST /api/register HTTP/1.1
Host: target.com
Content-Type: application/json

{"email": "test1@example.com", "plan": "free_trial"}
```

Test if the same user can re-register:

```
POST /api/register HTTP/1.1
Host: target.com
Content-Type: application/json

{"email": "test1+trial2@example.com", "plan": "free_trial"}
```

Test with email aliases (`+` addressing), different domains, and similar usernames.

### Step 6: Test OTP/MFA Code Reuse

**CLI Actions:**
Use `save to manual-review file` to capture an OTP verification request:

```
POST /api/verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json

{"otp": "123456", "session": "sess_abc"}
```

After successful verification:
1. Replay the same OTP
2. Try the OTP with a different session
3. Test if expired OTPs are still accepted

### Step 7: Test Resource Exhaustion

**CLI Actions:**
Use `fuzz-cli` to repeatedly trigger resource-intensive operations:

```
POST /api/export HTTP/1.1
Host: target.com
Authorization: Bearer <token>
Content-Type: application/json

{"format": "pdf", "all_records": true}
```

Monitor for:
- Server performance degradation
- Memory or disk exhaustion indicators
- Queue overflow
- Whether the application imposes any limit on concurrent or total exports

Use `rynix_plugin_run('template-scan')` to check for rate limiting or resource-related findings.

## Payloads

### Rate Limiting Test Patterns
```
# Rapid successive requests
10 identical requests in 1 second
50 identical requests in 10 seconds
100 identical requests in 30 seconds

# Vary parameters slightly to bypass simple dedup
request with param=value1
request with param=value1 (space appended)
request with PARAM=value1 (case change)
```

### Token Reuse Patterns
```
# Exact replay
Same token, same parameters
Same token, different parameters
Same token, different session

# Expired tokens
Token used after stated expiry time
Token used after password change
Token used after logout
```

### Email Alias Patterns (for trial abuse)
```
user@domain.com
user+1@domain.com
user+trial@domain.com
u.s.e.r@domain.com  (Gmail dots)
user@googlemail.com  (Gmail alias)
USER@domain.com      (case variation)
```

### Brute Force Wordlists
```
# OTP brute force (4-digit)
0000-9999

# OTP brute force (6-digit)
000000-999999

# Common passwords
password123
admin123
letmein
```

## Detection Criteria

A finding should be logged when:
- Single-use tokens (coupons, reset tokens, OTPs) can be reused
- No rate limiting exists on login, OTP verification, or password reset endpoints
- Free trial registration restrictions can be bypassed with email aliases
- Resource-intensive operations have no usage caps
- API endpoints have no request quotas
- Brute force attacks against OTP or passwords are feasible due to missing lockout

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No rate limiting on login, allowing unlimited brute force | Medium |
| Single-use coupon/discount codes reusable for financial gain | Medium |
| OTP codes reusable or brute-forceable (no lockout) | Medium |
| Password reset tokens reusable indefinitely | Medium |
| Free trial can be endlessly re-registered | Low |
| Resource-intensive exports can be triggered without limits | Low |
| API rate limits exist but are too generous (>1000 req/min) | Low |
| Rate limiting IP-based only, bypassable via proxy rotation | Low |
| Proper rate limiting and single-use enforcement on all functions | Not a finding |

## Remediation

- Invalidate single-use tokens immediately after first use
- Implement rate limiting on all sensitive endpoints (login, OTP, password reset, API)
- Use progressive delays or account lockout after failed authentication attempts
- Set expiration times on all tokens (password reset, OTP, verification links)
- Track free trial usage by multiple identifiers (email, device fingerprint, payment method)
- Implement CAPTCHA after repeated failed attempts
- Use token buckets or sliding window algorithms for rate limiting
- Apply rate limits at multiple layers (application, API gateway, WAF)
- Monitor and alert on abnormal usage patterns
- Set per-user and per-IP quotas for resource-intensive operations

## References

- [OWASP Testing Guide - Test Number of Times a Function Can Be Used](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
- [CWE-837: Improper Enforcement of a Single, Unique Action](https://cwe.mitre.org/data/definitions/837.html)

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

- V11 Business Logic — workflow integrity and limit enforcement.
- V4 Access Control — state transitions require proper authorization.

## CWE references

- CWE-840: Business Logic Errors
- CWE-362: Race Condition

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test price/quantity manipulation and workflow step skipping.
- Parallel requests for race windows on limits and balances.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

