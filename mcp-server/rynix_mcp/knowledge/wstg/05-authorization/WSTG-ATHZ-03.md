---
id: WSTG-ATHZ-03
title: Testing for Privilege Escalation
category: Authorization
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation
---

# WSTG-ATHZ-03: Testing for Privilege Escalation

## Summary

Privilege escalation occurs when an attacker gains elevated access to resources or functionality that should be restricted to higher-privileged users. Vertical privilege escalation involves gaining access to functions of a higher role (e.g., user to admin). Horizontal privilege escalation involves accessing resources of another user at the same privilege level. This test verifies whether a user can elevate privileges by modifying roles, parameters, tokens, or cookies.

## Test Objectives

- Determine if a user can modify their role or privilege level through parameter manipulation
- Test if role or privilege information stored client-side can be tampered with
- Verify that privilege checks are enforced server-side on every privileged operation
- Identify hidden parameters or API fields that control user roles

## Prerequisites

- At least two test accounts: one regular user and one admin (or higher-privilege) user
- Knowledge of the application's role hierarchy
- Docker pentest container capturing traffic from both user sessions
- Authenticated sessions for both accounts

## Test Steps

### Step 1: Identify Role and Privilege Indicators

**CLI Actions:**
1. Use `curl` to review all captured requests and responses after logging in as both a regular user and an admin user
2. Use `curl` with pattern `(role|privilege|is_admin|isAdmin|user_type|userType|access_level|accessLevel|group|permission)` to find parameters that indicate privilege levels
3. Look for role indicators in:
   - Request parameters (query strings, POST bodies)
   - Cookies
   - JWT claims (decode tokens with `base64 -d`)
   - Hidden form fields
   - JSON response bodies

### Step 2: Test Role Parameter Manipulation

**CLI Actions:**
1. Capture a request from the regular user that contains a role indicator (e.g., `role=user`)
2. Use `save to manual-review file` with this request
3. Use `curl` to modify the role parameter and resend:
   ``
   POST /api/profile/update HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"username":"testuser","role":"admin"}
   ``
4. Try various role values: `admin`, `administrator`, `superuser`, `root`, `manager`, `moderator`
5. Test numeric role values: `role=0`, `role=1`, `role=2`, `role=99`

### Step 3: Test Hidden Parameter Injection

**CLI Actions:**
1. Capture a normal profile update or registration request
2. Use `curl` to add extra fields that may control privileges:
   ``
   POST /api/user/update HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"name":"Test User","email":"test@test.com","is_admin":true}
   ``
3. Try adding fields like: `admin`, `is_admin`, `isAdmin`, `role`, `privilege`, `access_level`, `group_id`, `user_type`
4. Use `curl` to test mass assignment by including all known fields from the admin response in a regular user's update request

### Step 4: Test Cookie-Based Privilege Escalation

**CLI Actions:**
1. Use `curl` to examine all cookies set by the application
2. Use `base64 -d` on cookie values to check for encoded role data
3. If a cookie contains role information (e.g., `userinfo=base64({"role":"user"})`):
   - Decode with `base64 -d`
   - Modify the role value
   - Re-encode with `base64`
   - Use `curl` with the modified cookie:
     ``
     GET /admin/dashboard HTTP/1.1
     Host: target.com
     Cookie: session=<session_token>; userinfo=<modified_base64>
     ``

### Step 5: Test Token-Based Privilege Escalation

**CLI Actions:**
1. If the application uses JWTs or other tokens, decode the token payload with `base64 -d`
2. Look for claims like `role`, `admin`, `scope`, `groups`, or `permissions`
3. If the JWT uses a weak or none algorithm, modify the claims and resign (see WSTG-SESS-10)
4. Use `curl` with a modified token:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   Authorization: Bearer <modified_jwt>
   ``

### Step 6: Test API Endpoint Privilege Escalation

**CLI Actions:**
1. Use `curl` with pattern `(admin|manage|config|settings|users/create|users/delete|role)` to identify admin-only API endpoints
2. Use `curl` to access these endpoints with the regular user session:
   ``
   GET /api/admin/users HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   ``
3. Test POST/PUT/DELETE methods on admin endpoints with regular user credentials
4. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified any access control issues

### Step 7: Test Registration or Signup Privilege Escalation

**CLI Actions:**
1. Capture the user registration request
2. Use `curl` to add privilege parameters during registration:
   ``
   POST /api/register HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":"newuser","password":"Password1!","email":"new@test.com","role":"admin"}
   ``
3. Test adding various admin/role fields to the registration payload

## Payloads

### Role Parameter Values
```
admin
administrator
superuser
root
manager
moderator
super
sysadmin
operator
1
0
99
true
```

### Hidden Field Names to Inject
```
role
is_admin
isAdmin
admin
user_type
userType
access_level
accessLevel
privilege
group
group_id
groupId
permissions
scope
tier
```

### Cookie Manipulation Values
```
admin=true
role=admin
isAdmin=1
access=full
privilege=elevated
```

## Detection Criteria

A finding should be logged when:
- Modifying a role parameter in a request successfully changes the user's privilege level
- Adding hidden parameters (e.g., `is_admin=true`) during registration or profile update grants elevated access
- Modifying cookie values changes the user's access level
- Tampering with JWT claims grants access to admin functionality
- A regular user can successfully call admin-only API endpoints after parameter manipulation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Regular user gains full admin access via parameter manipulation | Critical |
| User can modify own role to a higher privilege level | Critical |
| Mass assignment allows setting admin fields during registration | Critical |
| Cookie tampering grants elevated privileges | High |
| JWT claim manipulation grants admin access | High |
| User can access some admin read-only endpoints but not perform actions | Medium |
| Role parameter is accepted but server overrides it (no actual escalation) | Informational |

## Remediation

- Never rely on client-side role or privilege indicators for authorization decisions
- Implement server-side authorization checks on every privileged operation
- Use an allowlist of accepted fields for mass assignment protection
- Do not expose role or privilege parameters in client-side requests
- Sign and validate all tokens server-side (use strong JWT signing algorithms)
- Implement role-based access control (RBAC) with a centralized authorization framework
- Log and alert on failed privilege escalation attempts
- Use the principle of least privilege: default to no access and grant explicitly

## References

- [OWASP Testing Guide - Privilege Escalation](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-266: Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

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

