---
id: WSTG-ATHZ-02
title: Testing for Bypassing Authorization Schema
category: Authorization
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
---

# WSTG-ATHZ-02: Testing for Bypassing Authorization Schema

## Summary

Authorization bypass occurs when an attacker accesses resources or functionality that should be restricted. This can happen through URL manipulation, forced browsing, parameter modification, or exploiting inconsistent access controls.

## Test Objectives

- Assess if horizontal or vertical authorization controls can be bypassed
- Test if unauthenticated users can access protected resources
- Identify inconsistencies in access control enforcement

## Prerequisites

- Multiple test accounts at different privilege levels (user, moderator, admin)
- Knowledge of the application's role structure
- Docker pentest container capturing traffic from different user sessions

## Test Steps

### Step 1: Map Role-Based Access

**CLI Actions:**
1. Log in as admin and browse all functionality. Use `curl` to capture all admin requests
2. Log in as regular user and browse all functionality. Use `curl` to capture all user requests
3. Compare the two sets of URLs and identify admin-only endpoints

### Step 2: Test Forced Browsing (Unauthenticated)

**CLI Actions:**
1. Use `curl` to request protected pages **without** any session cookies:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   ``
2. Test each admin endpoint without authentication
3. Check if the response returns content, redirects, or returns 403

### Step 3: Test Horizontal Authorization Bypass

**CLI Actions:**
1. Using User A's session, use `curl` to access User B's resources:
   ``
   GET /api/profile/user-b-id HTTP/1.1
   Cookie: session=<user_a_session>
   ``
2. Test with different methods (GET, POST, PUT, DELETE) as some may have inconsistent controls

### Step 4: Test Vertical Authorization Bypass

**CLI Actions:**
1. Capture an admin action request from the admin session
2. Use `save to manual-review file` with this request
3. Replace the admin session cookie with a regular user's session cookie
4. Use `curl` to test if the action is still performed
5. Test admin API endpoints:
   ``
   POST /api/admin/create-user HTTP/1.1
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"username":"newadmin","role":"admin"}
   ``

### Step 5: Test Path Manipulation

**CLI Actions:**
Use `curl` to test URL variations that may bypass path-based access controls:

```
GET /admin/dashboard HTTP/1.1
GET /ADMIN/dashboard HTTP/1.1
GET /admin/./dashboard HTTP/1.1
GET /admin/../admin/dashboard HTTP/1.1
GET //admin/dashboard HTTP/1.1
GET /admin%2fdashboard HTTP/1.1
GET /%61dmin/dashboard HTTP/1.1
GET /admin/dashboard;.js HTTP/1.1
GET /admin/dashboard%00 HTTP/1.1
GET /admin/dashboard/ HTTP/1.1
GET /admin/dashboard? HTTP/1.1
```

### Step 6: Test HTTP Method Bypass

**CLI Actions:**
If GET returns 403, test other methods with `curl`:
```
POST /admin/dashboard HTTP/1.1
PUT /admin/dashboard HTTP/1.1
PATCH /admin/dashboard HTTP/1.1
HEAD /admin/dashboard HTTP/1.1
OPTIONS /admin/dashboard HTTP/1.1
```

## Payloads

### URL Path Bypass Variations
```
/admin/dashboard
/Admin/Dashboard
/ADMIN/DASHBOARD
/admin/./dashboard
/admin/../admin/dashboard
//admin//dashboard
/admin/dashboard/
/admin/dashboard/.
/admin/dashboard%00
/admin/dashboard%0d%0a
/admin/dashboard;.css
/admin/dashboard;.js
/admin/dashboard..;/
/.;/admin/dashboard
```

### Header-Based Bypasses
```
X-Original-URL: /admin/dashboard
X-Rewrite-URL: /admin/dashboard
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

## Detection Criteria

A finding should be logged when:
- Protected resources are accessible without authentication
- A lower-privileged user can access higher-privilege functionality
- Path manipulation bypasses access controls
- HTTP method changes bypass access controls
- Header manipulation grants unauthorized access

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Admin functionality accessible by regular users | Critical |
| Unauthenticated access to admin features | Critical |
| Horizontal access to other users' sensitive data | High |
| Path bypass accesses restricted content | High |
| Method bypass reveals restricted information (read-only) | Medium |

## Remediation

- Implement server-side authorization checks on every request
- Use a centralized authorization framework, not scattered checks
- Deny by default - require explicit grants for each role/resource
- Normalize URL paths before applying access controls
- Enforce authorization regardless of HTTP method
- Log and alert on authorization failures

## References

- [OWASP Testing Guide - Bypassing Authorization Schema](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

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

- V4 Access Control — horizontal and vertical privilege checks.
- V13 API — object-level authorization on every endpoint.

## CWE references

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control

## Rynix tooling

- Primary tools: ``run_idor_matrix``, ``compare_role_response``, ``rbac_matrix``, ``check_access``

## Test focus

- Mandatory cross-role comparison on every object ID parameter.
- Document 403 vs 404 behavior — both can indicate IDOR signals.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

