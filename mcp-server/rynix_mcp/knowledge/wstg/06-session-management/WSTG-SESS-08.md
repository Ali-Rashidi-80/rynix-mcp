---
id: WSTG-SESS-08
title: Testing for Session Puzzling
category: Session Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling
---

# WSTG-SESS-08: Testing for Session Puzzling

## Summary

Session puzzling (also known as session variable overloading) occurs when an application uses the same session variable for multiple purposes across different functionalities. When a session variable set by one function is interpreted by another function in an unintended way, an attacker can manipulate application logic, bypass authentication, escalate privileges, or skip workflow steps. For example, a password reset flow might set a session variable that is also used by the authentication check, allowing an unauthenticated user to gain access.

## Test Objectives

- Identify session variables that are shared across different application functions
- Test if session variables set by one workflow can influence another workflow
- Determine if session variable overloading can bypass authentication or authorization
- Verify that session variables are properly scoped and isolated between functions

## Prerequisites

- A valid test account for authentication
- Access to multiple application workflows (login, registration, password reset, profile update)
- Docker pentest container capturing traffic across all workflows

## Test Steps

### Step 1: Map Session Variable Usage Across Functions

**CLI Actions:**
1. Use `curl` to capture traffic from all major application workflows:
   - Login flow
   - Registration flow
   - Password reset flow
   - Profile update flow
   - Multi-step forms or wizards
   - Two-factor authentication flow
2. Use `curl` with pattern `Set-Cookie:` to identify when new session variables or cookies are set during each workflow
3. Document which session cookies or variables are created or modified during each function
4. Look for common variable names like `user`, `username`, `authenticated`, `verified`, `step`, `role`

### Step 2: Test Password Reset to Authentication Bypass

**CLI Actions:**
1. Start the password reset flow (without authenticating) by providing a valid username:
   ``
   POST /forgot-password HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=admin
   ``
2. Use `curl` to capture the session state after this step
3. Without completing the password reset, use `curl` to navigate to an authenticated page using the same session:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_from_password_reset>
   ``
4. If the dashboard loads with authenticated content, the password reset flow set a session variable (e.g., `user=admin`) that the authentication check also relies on

### Step 3: Test Registration Flow to Privilege Escalation

**CLI Actions:**
1. Start a registration flow, entering details that set session variables:
   ``
   POST /register/step1 HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded
   Cookie: session=<session_token>

   username=newuser&email=new@test.com
   ``
2. Do not complete registration. Instead, use `curl` to access other application areas:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_from_partial_registration>
   ``
3. Test if the username or role set during registration influences other authorization checks

### Step 4: Test Multi-Step Workflow Variable Overloading

**CLI Actions:**
1. Identify multi-step processes (checkout, application forms, account setup)
2. Complete Step 1 of a workflow to set session variables
3. Use `curl` to skip to later steps:
   ``
   POST /checkout/step3 HTTP/1.1
   Host: target.com
   Cookie: session=<session_from_step1>
   Content-Type: application/x-www-form-urlencoded

   payment_confirmed=true
   ``
4. Test if the application validates that all intermediate steps were completed or if it only checks session variables

### Step 5: Test Two-Factor Authentication Bypass

**CLI Actions:**
1. Start the login flow and complete the username/password step:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=testuser&password=testpass
   ``
2. The application may set a session variable like `user=testuser` and redirect to the 2FA page
3. Without providing the 2FA code, use `curl` to access authenticated pages:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<session_after_password_step>
   ``
4. If the application checks only whether the `user` session variable is set (not whether 2FA was completed), the user gains access

### Step 6: Test Cross-Functional Session Variable Conflicts

**CLI Actions:**
1. Authenticate as User A (regular user)
2. Initiate an admin-related function that sets session variables (e.g., viewing an admin's public profile):
   ``
   GET /users/admin/profile HTTP/1.1
   Host: target.com
   Cookie: session=<user_a_session>
   ``
3. Use `curl` to check if this sets any session variables related to the viewed user
4. Use `curl` to then access admin functionality:
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<user_a_session>
   ``
5. If viewing another user's profile overwrites the session's `current_user` or `role` variable, privilege escalation may occur

### Step 7: Test Session Variable Manipulation via Cookie Values

**CLI Actions:**
1. Use `curl` to examine all cookies set by the application
2. Use `base64 -d` on cookie values to check for serialized session data
3. If session data is stored in cookies (e.g., Flask sessions), decode and examine the structure
4. Use `base64` to create modified session data and test with `curl`:
   ``
   GET /dashboard HTTP/1.1
   Host: target.com
   Cookie: session=<modified_encoded_session>
   ``
5. Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any session handling anomalies

## Payloads

### Session Variable Override Attempts
```
username=admin
user=admin
role=admin
authenticated=true
verified=true
is_admin=true
step=complete
2fa_verified=true
mfa_complete=true
```

### Workflow Skip Parameters
```
step=3
stage=final
complete=true
verified=true
payment_confirmed=true
```

## Detection Criteria

A finding should be logged when:
- Starting one workflow (e.g., password reset) grants access to authenticated pages
- Incomplete workflows leave session variables that influence other functions
- Skipping steps in a multi-step process succeeds due to shared session variables
- 2FA can be bypassed by accessing pages directly after the first authentication factor
- Viewing another user's data causes session variable overloading that changes the active user context
- Session variables from one function are reused by a different function without proper validation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Password reset flow enables authentication bypass | High |
| 2FA bypass via session variable overloading | High |
| Privilege escalation through cross-functional session confusion | High |
| Workflow step skipping that bypasses payment or verification | High |
| Registration flow influences authentication state | Medium |
| Session variables allow skipping non-critical steps | Medium |
| Session data viewable but not exploitable for access control bypass | Low |

## Remediation

- Use distinct session variable names for each application function (namespace session variables)
- Validate complete workflow state at each step, not just the presence of a session variable
- Clear function-specific session variables when a workflow is abandoned or completed
- Never use the same session variable for authentication state and other workflows
- Implement proper 2FA state tracking with a dedicated session flag that is separate from the user identity variable
- Use server-side session stores with structured objects rather than flat key-value pairs
- Validate all required workflow preconditions at each step
- Implement session variable isolation between security-critical functions

## References

- [OWASP Testing Guide - Session Puzzling](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling)
- [Session Puzzling Attack (OWASP)](https://owasp.org/www-community/attacks/Session_Puzzling)
- [CWE-488: Exposure of Data Element to Wrong Session](https://cwe.mitre.org/data/definitions/488.html)

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

- V3 Session Management — fixation, timeout, secure cookie flags.
- V2 Authentication — session binding to client fingerprint where applicable.

## CWE references

- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``auth_login``

## Test focus

- Test cookie flags, rotation on login, and concurrent session limits.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

