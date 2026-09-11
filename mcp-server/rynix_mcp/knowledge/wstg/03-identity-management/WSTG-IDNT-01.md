---
id: WSTG-IDNT-01
title: Test Role Definitions
category: Identity Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions
---

# WSTG-IDNT-01: Test Role Definitions

## Summary

Role definitions determine what actions and resources each type of user can access within an application. Poorly defined roles can lead to privilege escalation, unauthorized access to sensitive functionality, and violations of the principle of least privilege. Testing role definitions involves mapping out all roles in the system, verifying that each role has appropriate permissions, and confirming that separation of duties is properly enforced.

## Test Objectives

- Identify and document all user roles within the application
- Verify that each role grants only the minimum privileges necessary
- Test that role boundaries are enforced and users cannot access functionality outside their role
- Check for proper separation of duties between roles
- Identify any overly permissive or redundant role definitions

## Prerequisites

- Target application implements role-based access control (RBAC)
- Access to accounts with different privilege levels (e.g., anonymous, regular user, moderator, admin)
- Application documentation or knowledge of expected role hierarchy
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Enumerate Application Roles

**CLI Actions:**
1. Log in as each available role and browse all application functionality
2. Use `curl` to capture all requests made by each role
3. Use `curl` with pattern `role|permission|privilege|access|group|admin|user` to identify role-related parameters in requests and responses
4. Document each role and its accessible endpoints in a role-permission matrix

**What to Document:**
- Role names and hierarchy
- Accessible URLs and API endpoints per role
- Available actions (CRUD operations) per role
- Administrative functions and who can access them

### Step 2: Map Role-Specific Functionality

**CLI Actions:**
1. For each role, use `curl` to extract the complete list of URLs visited
2. Use `curl` to request administrative or privileged endpoints as each role:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<user_role_session>
   ``
3. Use `curl` to access user management endpoints:
   ``
   GET /api/users HTTP/1.1
   Host: target.com
   Cookie: session=<user_role_session>
   ``
4. Record which endpoints return 200, 403, 404, or redirect responses for each role

### Step 3: Test Role Separation

**CLI Actions:**
1. Use `save to manual-review file` to prepare requests for cross-role testing
2. Take a request captured from an admin session and replay it with a regular user session token using `curl`:
   ``
   POST /admin/users/create HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"username":"newuser","role":"admin"}
   ``
3. Test each privileged action with every lower-privilege role
4. Check if the application returns different responses or silently permits the action

### Step 4: Test Role Parameter Manipulation

**CLI Actions:**
1. Use `curl` with pattern `role=|usertype=|privilege=|group=|isAdmin|access_level` to find role-related parameters
2. Use `save to manual-review file` to modify role parameters in requests
3. Use `curl` to submit requests with altered role values:
   ``
   POST /api/profile/update HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"username":"regularuser","role":"admin"}
   ``
4. Test hidden form fields or API parameters that may control role assignment:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=test&password=pass123&role=admin
   ``

### Step 5: Verify Separation of Duties

**CLI Actions:**
1. Identify workflows that require multiple roles (e.g., request and approval)
2. Use `curl` to test if a single user can complete both steps:
   ``
   POST /api/expense/submit HTTP/1.1
   Host: target.com
   Cookie: session=<manager_session>
   Content-Type: application/json

   {"amount":5000,"description":"test"}
   ``
   Then attempt approval with the same session:
   ``
   POST /api/expense/approve/123 HTTP/1.1
   Host: target.com
   Cookie: session=<manager_session>
   ``
3. Use `rynix_plugin_run('template-scan')` to check for any access control findings template-scan has identified automatically

## Payloads

### Common Role Values to Test
```
admin
administrator
superadmin
root
manager
moderator
editor
supervisor
operator
support
user
guest
```

### Role Parameter Injection Values
```
role=admin
isAdmin=true
access_level=9999
group=administrators
privilege=full
usertype=1
admin=1
```

## Detection Criteria

A finding should be logged when:
- A user can access functionality designated for a higher-privilege role
- Role parameters in requests can be manipulated to escalate privileges
- Separation of duties is not enforced (single user can complete multi-step workflows)
- Roles grant more permissions than necessary (overly permissive)
- Undefined or default roles have excessive access
- Role checks are performed client-side only

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Regular user can access full admin functionality | High |
| Role parameter manipulation grants elevated privileges | High |
| Separation of duties can be bypassed | Medium |
| Roles are overly permissive but core admin functions protected | Medium |
| Minor functionality overlap between roles | Low |
| Role definitions exist but are not consistently documented | Low |

## Remediation

- Implement role-based access control at the server side for every request
- Follow the principle of least privilege when defining roles
- Enforce separation of duties for sensitive workflows
- Never trust client-supplied role parameters; derive roles from authenticated session data
- Regularly audit role definitions and remove unnecessary permissions
- Use centralized access control mechanisms rather than per-endpoint checks
- Log and alert on access control violations for monitoring

## References

- [OWASP Testing Guide - Test Role Definitions](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
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

