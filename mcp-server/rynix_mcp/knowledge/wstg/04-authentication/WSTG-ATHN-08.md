---
id: WSTG-ATHN-08
title: Testing for Weak Security Question/Answer
category: Authentication
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer
---

# WSTG-ATHN-08: Testing for Weak Security Question/Answer

## Summary

Security questions are used as a secondary authentication mechanism, often for account recovery or password reset. Weak security questions can be easily guessed, researched through social media, or brute-forced. If the answers are stored in plaintext or the questions are insufficiently varied, attackers can bypass this layer of authentication entirely. This test evaluates the strength of the security questions offered, the enforcement of answer quality, and the overall resilience of the mechanism.

## Test Objectives

- Evaluate the quality and strength of available security questions
- Test if security question answers can be brute-forced
- Check if answers are case-sensitive and validated properly
- Verify that security question responses are not stored in plaintext
- Test for information leakage through security question selection

## Prerequisites

- Target application uses security questions for account recovery or as a secondary authentication factor
- Valid user account with security questions configured
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Enumerate Available Security Questions

**CLI Actions:**
1. Navigate to the security question setup page (during registration or in account settings)
2. Use `curl` to capture the response containing available questions
3. Use `curl` with pattern `security.?question|secret.?question|challenge.?question` to find related endpoints
4. Use `curl` to fetch the security question list:
   ``
   GET /api/security-questions HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
5. Document all available questions and categorize their strength:
   - **Weak:** Answers easily found on social media (e.g., "What city were you born in?")
   - **Medium:** Requires some research (e.g., "What was the name of your first pet?")
   - **Strong:** Truly personal and not publicly available

### Step 2: Test Answer Validation

**CLI Actions:**
1. Set up a security question with a known answer
2. Use `save to manual-review file` to prepare the answer verification request
3. Use `curl` to test answer case sensitivity:
   ``
   POST /account/verify-security-question HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   question_id=1&answer=New York
   ``
   Then test variations:
   ``
   answer=new york
   answer=NEW YORK
   answer=new%20york
   answer=newyork
   ``
4. Test with leading/trailing whitespace:
   ``
   answer=%20New%20York%20
   ``
5. Use `curl --data-urlencode` to properly encode answer values with special characters
6. Document whether the application normalizes answers (case-insensitive comparison reduces entropy significantly)

### Step 3: Test Brute-Force Protection

**CLI Actions:**
1. Use `save to manual-review file` with the security question answer submission request
2. Use `curl` to submit multiple incorrect answers in succession:
   ``
   POST /account/verify-security-question HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   question_id=1&answer=wrong_answer_1
   ``
3. Submit 10-20 incorrect answers and check for:
   - Account lockout
   - Rate limiting
   - CAPTCHA enforcement
   - Increasing delays
4. If no protection exists, use `fuzz-cli` to configure a brute-force attack with common answers for the question type
5. Test if the security question changes or locks after multiple failures

### Step 4: Test for Answer Leakage

**CLI Actions:**
1. Use `curl` with pattern `answer|security_answer|secret_answer` to find any responses that expose stored answers
2. Use `curl` to check if the security question setup page reveals the current answer:
   ``
   GET /account/security-settings HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
3. Check if answers appear in:
   - HTML source (hidden fields)
   - JavaScript variables
   - API responses
   - Page comments
4. Use `base64 -d` to decode any obfuscated answer values found in responses
5. Test if the answer is included in account export or profile data endpoints:
   ``
   GET /api/account/export HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``

### Step 5: Test Security Question During Password Reset

**CLI Actions:**
1. Initiate the password reset flow and navigate to the security question step
2. Use `curl` to capture the full reset flow
3. Use `curl` to test if the question is shown before verifying the account exists (information leakage):
   ``
   POST /reset-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=targetuser
   ``
4. Check if the response reveals which security question is associated with the account
5. Test if the security question step can be bypassed by directly accessing the next step:
   ``
   POST /reset-password/step3 HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=targetuser&new_password=NewPass123!
   ``
6. Use `rynix_plugin_run('template-scan')` to check for any related findings

### Step 6: Test Self-Defined Questions

**CLI Actions:**
1. If the application allows users to define their own security questions, test with weak self-defined questions
2. Use `curl` to set a trivially simple question:
   ``
   POST /account/security-settings HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   custom_question=What+is+1%2B1&answer=2
   ``
3. Test if extremely short answers are accepted:
   ``
   custom_question=Any+question&answer=a
   ``
4. Test if the answer can be the same as the question:
   ``
   custom_question=test&answer=test
   ``

## Payloads

### Common Answers for "What city were you born in?"
```
New York
Los Angeles
Chicago
Houston
Phoenix
Philadelphia
San Antonio
San Diego
Dallas
London
```

### Common Answers for "What is your pet's name?"
```
Buddy
Max
Charlie
Cooper
Rocky
Bear
Duke
Bella
Lucy
Daisy
```

### Common Answers for "What is your mother's maiden name?"
```
Smith
Johnson
Williams
Brown
Jones
Garcia
Miller
Davis
Rodriguez
Martinez
```

### Answer Brute-Force Patterns
```
yes
no
none
n/a
unknown
(single character answers: a-z)
(common first names)
(common city names)
```

## Detection Criteria

A finding should be logged when:
- Security questions have easily guessable answers (publicly available information)
- Answers are not case-sensitive (reduces entropy significantly)
- No brute-force protection exists on security question verification
- Security question answers are exposed in API responses or HTML source
- Self-defined questions with trivially weak answers are accepted
- Security question step in password reset can be bypassed
- The application reveals which security question is assigned to an account
- Single-word or very short answers are accepted

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Security question step can be bypassed entirely | High |
| Answers stored or transmitted in plaintext/encoded form | High |
| No brute-force protection on answer verification | High |
| Only weak questions available (answers from social media) | Medium |
| Answers are case-insensitive with no rate limiting | Medium |
| Security question choice reveals information about the user | Medium |
| Self-defined questions with no quality enforcement | Medium |
| Short answers (1-3 characters) accepted | Low |
| Only one security question required (no defense in depth) | Low |

## Remediation

- Prefer modern account recovery methods (email/SMS verification, authenticator apps) over security questions
- If security questions must be used, offer only strong questions whose answers cannot be easily researched
- Enforce minimum answer length (e.g., 4+ characters)
- Hash security question answers just like passwords (bcrypt/argon2)
- Implement account lockout or rate limiting after 3-5 incorrect answers
- Normalize answers before comparison (trim whitespace, lowercase) but combine with rate limiting
- Never expose stored answers in any response
- Require multiple security questions for password reset
- Do not allow self-defined security questions without quality validation
- Do not reveal which security question is assigned to a specific account

## References

- [OWASP Testing Guide - Weak Security Question/Answer](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
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

