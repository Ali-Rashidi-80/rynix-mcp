---
id: WSTG-IDNT-03
title: Test Account Provisioning Process
category: Identity Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process
---

# WSTG-IDNT-03: Test Account Provisioning Process

## Summary

Account provisioning encompasses the full lifecycle of user accounts: creation, modification, suspension, and deletion. Weaknesses in any stage can allow unauthorized account creation, privilege escalation during modification, improper deactivation leaving residual access, or incomplete deletion leaving recoverable data. This test evaluates the security controls at each stage of the account lifecycle.

## Test Objectives

- Test the security of the account creation/provisioning workflow
- Verify that account modification cannot lead to privilege escalation
- Confirm that account suspension fully revokes access
- Ensure account deletion is complete and irreversible
- Check that the provisioning process has proper authorization controls

## Prerequisites

- Access to an administrative account that can provision users (if applicable)
- Access to standard user accounts for testing modification and deletion
- Understanding of the application's user management workflows
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Analyze Account Creation Process

**CLI Actions:**
1. Navigate through the account creation process (admin panel or self-registration) and capture all requests
2. Use `curl` to identify the complete request flow for account creation
3. Use `save to manual-review file` to save the account creation request
4. Use `curl` to test creating an account without proper authorization:
   ``
   POST /api/admin/users HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":"unauthorized_user","email":"unauth@test.com","password":"Password123!","role":"user"}
   ``
5. Test without authentication headers (remove Cookie or Authorization header entirely)

### Step 2: Test Account Modification Controls

**CLI Actions:**
1. As a regular user, capture the profile update request
2. Use `save to manual-review file` to modify the request
3. Use `curl` to test modifying another user's account:
   ``
   PUT /api/users/OTHER_USER_ID HTTP/1.1
   Host: target.com
   Cookie: session=<current_user_session>
   Content-Type: application/json

   {"email":"attacker@evil.com"}
   ``
4. Test modifying your own role or privilege level:
   ``
   PUT /api/users/MY_USER_ID HTTP/1.1
   Host: target.com
   Cookie: session=<current_user_session>
   Content-Type: application/json

   {"role":"admin","isAdmin":true}
   ``
5. Use `curl` with pattern `PUT|PATCH.*user|profile|account` to find all modification endpoints
6. Test IDOR by iterating through sequential user IDs

### Step 3: Test Account Suspension/Deactivation

**CLI Actions:**
1. If possible, have an admin suspend a test account
2. Use `curl` to test if the suspended account's session is still valid:
   ``
   GET /api/profile HTTP/1.1
   Host: target.com
   Cookie: session=<suspended_account_session>
   ``
3. Test if the suspended account can still authenticate:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=suspended_user&password=original_password
   ``
4. Test if API tokens or other credentials from the suspended account still function:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Authorization: Bearer <suspended_account_token>
   ``
5. Use `rynix_plugin_run('template-scan')` to check for any session management findings related to deactivated accounts

### Step 4: Test Account Deletion Completeness

**CLI Actions:**
1. Delete a test account through the normal process
2. Use `curl` to attempt re-authentication with the deleted account:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=deleted_user&password=original_password
   ``
3. Test if the deleted account's session tokens remain valid:
   ``
   GET /api/profile HTTP/1.1
   Host: target.com
   Cookie: session=<deleted_account_session>
   ``
4. Test if the deleted username can be re-registered:
   ``
   POST /register HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=deleted_user&email=new@test.com&password=NewPass123!
   ``
5. Check if data associated with the deleted account is still accessible via API:
   ``
   GET /api/users/DELETED_USER_ID HTTP/1.1
   Host: target.com
   Cookie: session=<admin_session>
   ``

### Step 5: Test Provisioning Authorization Controls

**CLI Actions:**
1. Capture an admin-level account provisioning request
2. Use `save to manual-review file` to prepare the request with a non-admin session
3. Use `curl` to replay provisioning actions as a regular user:
   ``
   POST /api/admin/users HTTP/1.1
   Host: target.com
   Cookie: session=<regular_user_session>
   Content-Type: application/json

   {"username":"escalation_test","role":"admin","password":"Test123!"}
   ``
4. Test if provisioning endpoints are accessible without authentication:
   ``
   POST /api/admin/users HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":"noauth_test","role":"user","password":"Test123!"}
   ``
5. Use `curl` with pattern `admin|provision|create.*user|manage.*account` to find all provisioning-related endpoints

### Step 6: Test Bulk Provisioning and Import

**CLI Actions:**
1. Use `curl` to identify any bulk user import functionality
2. If CSV/file upload provisioning exists, use `curl` to test with malicious payloads:
   ``
   POST /api/admin/users/import HTTP/1.1
   Host: target.com
   Cookie: session=<admin_session>
   Content-Type: multipart/form-data; boundary=----Boundary

   ------Boundary
   Content-Disposition: form-data; name="file"; filename="users.csv"
   Content-Type: text/csv

   username,email,role
   hacker,hacker@evil.com,admin
   ------Boundary--
   ``
3. Test if the import process validates roles and permissions in bulk data
4. Use `base64` to encode payloads if the import expects base64-encoded data

## Payloads

### Privilege Escalation Parameters
```
role=admin
isAdmin=true
privilege=superuser
access_level=10
group=administrators
userType=admin
permissions=["*"]
admin=1
staff=true
```

### IDOR Test Patterns
```
/api/users/1
/api/users/2
/api/users/100
/api/users/admin
/api/users/0
/api/users/-1
/api/users/999999
```

## Detection Criteria

A finding should be logged when:
- Unauthorized users can create accounts through provisioning endpoints
- Account modification allows privilege escalation via parameter tampering
- Suspended accounts retain active sessions or can re-authenticate
- Deleted accounts are not fully purged (sessions remain valid)
- Provisioning endpoints lack proper authorization checks
- Bulk import does not validate role assignments
- IDOR allows modification or deletion of other users' accounts

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Unauthenticated access to account provisioning endpoints | High |
| Account modification allows privilege escalation to admin | High |
| Suspended account retains full access via existing sessions | High |
| Deleted account sessions remain valid | Medium |
| IDOR allows viewing other users' profiles | Medium |
| Deleted username can be re-registered (account takeover risk) | Medium |
| Incomplete data deletion after account removal | Low |
| Bulk import lacks role validation | Medium |

## Remediation

- Implement strict authorization checks on all provisioning endpoints
- Invalidate all sessions and tokens immediately upon account suspension or deletion
- Use indirect object references (UUIDs) instead of sequential IDs
- Validate and sanitize all fields during account modification (allowlist approach)
- Implement server-side role validation that ignores client-supplied role parameters
- Ensure complete data purging upon account deletion (or proper anonymization per GDPR)
- Prevent re-registration of recently deleted usernames for a cooldown period
- Log all provisioning actions for audit trails
- Implement approval workflows for sensitive provisioning operations

## References

- [OWASP Testing Guide - Test Account Provisioning Process](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-262: Not Using Password Aging](https://cwe.mitre.org/data/definitions/262.html)

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

