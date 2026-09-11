---
id: WSTG-BUSL-07
title: Test Defenses Against Application Misuse
category: Business Logic
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse
---

# WSTG-BUSL-07: Test Defenses Against Application Misuse

## Summary

Applications should implement defenses against automated misuse, including brute force attacks, credential stuffing, scraping, spam submission, and other forms of abuse. Common defenses include CAPTCHAs, rate limiting, account lockout, bot detection, and behavioral analysis. Testing these defenses ensures they are effective and cannot be easily circumvented, while also verifying they do not create denial-of-service conditions for legitimate users.

## Test Objectives

- Identify anti-automation and abuse prevention mechanisms
- Test the effectiveness of CAPTCHA implementations
- Assess rate limiting and account lockout policies
- Determine if anti-automation defenses can be bypassed
- Verify that defenses do not cause denial of service for legitimate users

## Prerequisites

- Target application is accessible through Docker pentest container
- Login and registration pages have been identified
- Understanding of expected application usage patterns

## Test Steps

### Step 1: Identify Anti-Automation Mechanisms

**CLI Actions:**
Use `curl` to access key pages and identify defenses:

```
GET /login HTTP/1.1
Host: target.com
```

```
GET /register HTTP/1.1
Host: target.com
```

Look in responses for:
- CAPTCHA implementations (reCAPTCHA, hCaptcha, custom CAPTCHAs)
- Hidden honeypot fields
- JavaScript challenges
- Rate limiting headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`)
- Bot detection scripts (Cloudflare, Akamai, PerimeterX)

### Step 2: Test Account Lockout Policy

**CLI Actions:**
Use `fuzz-cli` to test account lockout by submitting multiple failed login attempts:

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=testuser&password=§wrong_password§
```

Configure Intruder with a list of wrong passwords. Monitor:
- At what attempt count does lockout occur?
- Is the lockout message consistent (avoid user enumeration)?
- How long does lockout last?
- Does lockout apply per-username, per-IP, or both?
- Can locked accounts still receive password reset emails?

### Step 3: Test CAPTCHA Effectiveness

**CLI Actions:**
Use `save to manual-review file` to test CAPTCHA bypass methods:

1. Submit the form without the CAPTCHA token:
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test
```

2. Submit with an empty CAPTCHA value:
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test&g-recaptcha-response=
```

3. Reuse a previously valid CAPTCHA token:
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test&g-recaptcha-response=<previously_valid_token>
```

4. Submit with a static/hardcoded CAPTCHA value for custom implementations.

### Step 4: Test Rate Limiting Boundaries

**CLI Actions:**
Use `fuzz-cli` to determine rate limit thresholds:

```
GET /api/search?q=§test§ HTTP/1.1
Host: target.com
```

Gradually increase request rate and document:
- Requests per minute before rate limit triggers
- The rate limit response (429, 503, or custom)
- Whether rate limiting is per-IP, per-session, per-user, or global
- Recovery time after rate limit is reached

Test rate limit bypass techniques:
- Add `X-Forwarded-For: 127.0.0.1` header
- Add `X-Real-IP: different_ip` header
- Rotate User-Agent strings
- Use different API keys or sessions

```
GET /api/search?q=test HTTP/1.1
Host: target.com
X-Forwarded-For: §127.0.0.§1
```

### Step 5: Test Honeypot Fields

**CLI Actions:**
Use `curl` to identify and test honeypot fields. These are hidden fields that should remain empty:

```
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&email=test@test.com&password=Pass123!&phone_hidden=bot_value
```

Submit with the honeypot field filled in vs. empty to determine if it triggers bot detection.

### Step 6: Test Lockout Denial of Service

**CLI Actions:**
Use `fuzz-cli` to test if an attacker can lock out a legitimate user:

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim_user&password=§wrong§
```

If accounts lock after N failures regardless of source IP, an attacker can deny service to any user by deliberately failing login attempts.

Use `rynix_plugin_run('template-scan')` to check for CAPTCHA and rate-limiting findings.

## Payloads

### Rate Limit Bypass Headers
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Originating-IP: 192.168.1.1
X-Remote-IP: 172.16.0.1
X-Remote-Addr: 8.8.8.8
X-Client-IP: 1.1.1.1
True-Client-IP: 2.2.2.2
CF-Connecting-IP: 3.3.3.3
Forwarded: for=4.4.4.4
```

### CAPTCHA Bypass Values
```
(empty string)
null
undefined
0
true
test
AAAA
<previously_used_valid_token>
```

### Lockout Test Passwords
```
password1
password2
password3
...
password20
(sequence to trigger lockout threshold)
```

### Bot Detection Evasion Headers
```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://target.com/
```

## Detection Criteria

A finding should be logged when:
- No CAPTCHA or anti-automation on login, registration, or contact forms
- CAPTCHA can be bypassed by omitting, reusing, or submitting empty tokens
- No rate limiting on sensitive endpoints (login, password reset, API)
- Rate limiting can be bypassed via header manipulation (X-Forwarded-For)
- Account lockout creates a denial-of-service vector for legitimate users
- No honeypot or behavioral analysis to detect automated submissions
- Lockout duration is too short (< 15 minutes) or too long (permanent without admin unlock)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No rate limiting or lockout on login, enabling brute force | Medium |
| CAPTCHA completely bypassable (omit or reuse tokens) | Medium |
| Rate limiting bypassable via X-Forwarded-For header | Medium |
| Account lockout creates denial of service for legitimate users | Medium |
| No anti-automation on contact or feedback forms (spam vector) | Low |
| Rate limiting exists but threshold is too high (>100 req/min on login) | Low |
| CAPTCHA present but uses weak/solvable image challenges | Low |
| Account lockout with reasonable duration and alert to user | Informational |
| Effective rate limiting, CAPTCHA, and lockout with DoS protection | Not a finding |

## Remediation

- Implement CAPTCHA (reCAPTCHA v3, hCaptcha) on login, registration, and public forms
- Validate CAPTCHA tokens server-side and reject missing or reused tokens
- Implement progressive rate limiting: warn, delay, then block
- Apply rate limiting at multiple layers (application, WAF, CDN)
- Do not trust client-supplied IP headers (X-Forwarded-For) for rate limiting unless behind a trusted proxy
- Use account lockout with increasing duration (1 min, 5 min, 15 min, 1 hour)
- Notify users of account lockout via email
- Implement soft lockout (CAPTCHA required) before hard lockout (account locked)
- Use honeypot fields in forms to detect simple bots
- Implement behavioral analysis to detect non-human interaction patterns
- Allow account recovery via password reset even during lockout

## References

- [OWASP Testing Guide - Test Defenses Against Application Misuse](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
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

