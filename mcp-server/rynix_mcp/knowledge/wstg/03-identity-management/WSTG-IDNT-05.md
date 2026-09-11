---
id: WSTG-IDNT-05
title: Testing for Weak or Unenforced Username Policy
category: Identity Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy
---

# WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy

## Summary

Weak or unenforced username policies allow attackers to predict, enumerate, or guess valid usernames. If usernames follow predictable patterns (e.g., first.last, employee IDs), attackers can generate lists of likely valid accounts for brute-force, credential stuffing, or social engineering attacks. Additionally, weak policies may allow creation of confusingly similar usernames for impersonation.

## Test Objectives

- Determine if the application enforces a username policy
- Identify predictable username patterns that allow enumeration
- Test for weak username requirements (length, character restrictions)
- Check if confusingly similar or visually identical usernames are allowed
- Assess whether default or well-known usernames exist

## Prerequisites

- Target application has user accounts with usernames
- Access to registration or account creation functionality
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Identify Username Format and Policy

**CLI Actions:**
1. Use `curl` to analyze captured traffic for exposed usernames in responses, URLs, or parameters
2. Use `curl` with pattern `username|user_id|login|author|created_by|modified_by|owner` to find username references
3. Use `curl` to check publicly accessible user listings or profiles:
   ``
   GET /api/users HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
4. Check for usernames exposed in application responses:
   ``
   GET /api/posts HTTP/1.1
   Host: target.com
   ``
5. Document the observed username format (e.g., email-based, first.last, numeric IDs)

### Step 2: Test Username Requirements

**CLI Actions:**
1. Use `save to manual-review file` with the registration or user creation request
2. Use `curl` to test minimum length enforcement:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=a&email=short@test.com&password=Password123!
   ``
3. Test maximum length:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=AAAAAAAAAA...(500 chars)&email=long@test.com&password=Password123!
   ``
4. Test with special characters:
   ``
   username=user<>!@#$%
   username=user'name
   username=user"name
   username=../admin
   ``
5. Use `curl --data-urlencode` to encode special characters in payloads as needed

### Step 3: Test for Predictable Username Patterns

**CLI Actions:**
1. Use `fuzz-cli` to configure an enumeration attack against the login endpoint
2. Use `curl` to test common username patterns:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=john.smith&password=invalid
   ``
3. Test sequential or predictable formats:
   ``
   username=user001
   username=user002
   username=EMP0001
   username=EMP0002
   ``
4. Compare response differences (status codes, body content, timing) between valid and invalid usernames
5. Use `curl` with pattern `(user|employee|staff|account)[_-]?\d+` to find sequential patterns in captured traffic

### Step 4: Test for Confusingly Similar Usernames

**CLI Actions:**
1. If a username like `admin` exists, use `curl` to attempt registering similar names:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=adm1n&email=lookalike1@test.com&password=Password123!
   ``
2. Test Unicode homoglyph attacks:
   ``
   username=аdmin  (Cyrillic 'а' instead of Latin 'a')
   username=admın  (Turkish dotless 'ı' instead of 'i')
   ``
3. Use `curl --data-urlencode` to properly encode Unicode characters for submission
4. Test with zero-width characters inserted into existing usernames:
   ``
   username=ad%E2%80%8Bmin  (zero-width space)
   username=ad%E2%80%8Cmin  (zero-width non-joiner)
   ``

### Step 5: Test for Default and Well-Known Usernames

**CLI Actions:**
1. Use `fuzz-cli` to test a list of default usernames against the login page
2. Use `curl` to check common administrative accounts:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=admin
   ``
3. Test application-specific defaults:
   ``
   username=administrator
   username=root
   username=sysadmin
   username=sa
   username=webmaster
   username=operator
   ``
4. Use `rynix_plugin_run('template-scan')` to check for any default credential findings

### Step 6: Test Username Enumeration via Registration

**CLI Actions:**
1. Use `curl` to attempt registration with predictable usernames:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin&email=test@test.com&password=Password123!
   ``
2. Observe if the response reveals whether the username is already taken
3. Use `curl` to check username availability endpoints if they exist:
   ``
   GET /api/check-username?username=admin HTTP/1.1
   Host: target.com
   ``
4. Compare response messages, status codes, and response lengths for taken vs. available usernames

## Payloads

### Default/Common Usernames
```
admin
administrator
root
sysadmin
webmaster
operator
sa
postgres
mysql
tomcat
manager
guest
test
demo
support
info
```

### Sequential Pattern Payloads
```
user001 through user999
EMP0001 through EMP9999
john.smith (first.last patterns)
jsmith (first initial + last name)
```

### Homoglyph Payloads
```
admin -> аdmin (Cyrillic a)
admin -> admіn (Cyrillic i)
admin -> adm1n (digit 1)
admin -> admin (fullwidth characters)
user -> user (Cyrillic u)
```

## Detection Criteria

A finding should be logged when:
- Usernames follow a predictable pattern that allows enumeration
- No minimum complexity requirements exist for usernames
- Confusingly similar or homoglyph usernames are accepted
- Default or well-known usernames are active in the system
- Username availability checks enable enumeration
- No restrictions on sequential or numeric-only usernames

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Default admin accounts with default credentials are active | Medium |
| Predictable sequential usernames allow bulk enumeration | Medium |
| Username availability API allows unlimited enumeration | Medium |
| Homoglyph usernames accepted (impersonation risk) | Medium |
| No minimum length requirement for usernames | Low |
| Usernames expose internal structure (e.g., employee IDs) | Low |
| Weak character restrictions on usernames | Low |

## Remediation

- Enforce a minimum username length (e.g., 3-6 characters minimum)
- Restrict username characters to a safe alphanumeric set
- Normalize usernames to prevent homoglyph and Unicode attacks
- Avoid predictable username patterns; allow users to choose their own usernames
- Disable or rename default accounts before deployment
- Rate-limit username availability checks
- Use generic responses that do not confirm whether a username exists
- Consider using email addresses as usernames to avoid pattern-based enumeration
- Implement detection for bulk username enumeration attempts

## References

- [OWASP Testing Guide - Testing for Weak or Unenforced Username Policy](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy)
- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)

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

