---
id: WSTG-ATHN-02
title: Testing for Default Credentials
category: Authentication
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials
---

# WSTG-ATHN-02: Testing for Default Credentials

## Summary

Many web applications and appliances ship with default credentials that are well-documented. Administrators often fail to change these defaults, leaving systems vulnerable to unauthorized access.

## Test Objectives

- Identify default or common credentials for the target application
- Test if default credentials allow authentication
- Check for default credentials on administrative interfaces

## Prerequisites

- Target application login page is identified
- Application/framework type has been fingerprinted (WSTG-INFO-02, WSTG-INFO-08)

## Test Steps

### Step 1: Identify Application Type

**CLI Actions:**
1. Use `curl` to review past requests and identify the application type
2. Use `curl` to check for common admin paths:
   ``
   GET /admin/ HTTP/1.1
   GET /administrator/ HTTP/1.1
   GET /wp-admin/ HTTP/1.1
   GET /manager/html HTTP/1.1
   GET /phpmyadmin/ HTTP/1.1
   ``

### Step 2: Test Default Credentials

**CLI Actions:**
For each identified login page, use `curl` to attempt login with common default credentials:

### Step 3: Test with fuzz-cli parameter sweep

**CLI Actions:**
1. Use `save to manual-review file` with the login request for manual testing
2. Use `fuzz-cli` for automated credential testing against the login endpoint

## Payloads

### Common Default Credentials
```
admin:admin
admin:password
admin:admin123
admin:12345
administrator:administrator
root:root
root:toor
root:password
test:test
guest:guest
user:user
demo:demo
```

### Application-Specific Defaults
```
# Apache Tomcat
tomcat:tomcat
admin:tomcat
tomcat:s3cret
manager:manager

# WordPress
admin:admin
admin:password

# Joomla
admin:admin

# phpMyAdmin
root:(empty)
root:root
root:mysql

# Jenkins
admin:admin
admin:password

# Grafana
admin:admin

# Elasticsearch
elastic:changeme

# MongoDB
(no auth by default)

# Redis
(no auth by default)

# RabbitMQ
guest:guest

# PostgreSQL
postgres:postgres

# MySQL
root:(empty)
root:root

# Spring Boot Actuator
user:password (check /actuator endpoints)

# Default router/appliance
admin:admin
admin:password
admin:1234
```

### Automated Default Credential Testing with hydra

**CLI Actions:**
Use `hydra` to test common default credentials against login forms:

```bash
# HTTP POST form login
rynix_plugin_run('wstg') hydra -L /opt/wordlists/default-users.txt -P /opt/wordlists/default-passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid" -t 4 -o ./engagements/<eid>/tool-output/hydra-defaults.txt

# HTTP Basic Auth
rynix_plugin_run('wstg') hydra -L /opt/wordlists/default-users.txt -P /opt/wordlists/default-passwords.txt target.com http-get /admin -t 4 -o ./engagements/<eid>/tool-output/hydra-basic.txt
```

Adjust the form parameters (`username`, `password`, failure string `F=Invalid`) based on the actual login endpoint. Use `-t 4` to limit parallel tasks and avoid triggering rate limits.

Common default credential pairs to test: `admin:admin`, `admin:password`, `root:root`, `admin:12345`, `guest:guest`, `admin:changeme`.

## Detection Criteria

A finding should be logged when:
- Default credentials allow successful authentication
- Default admin accounts exist and are accessible
- Default service accounts have not been changed
- Password-less accounts are accessible

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Default admin credentials grant full application access | Critical |
| Default credentials access limited functionality | High |
| Default credentials for non-critical services | Medium |
| Default account exists but password has been changed | Informational |

## Remediation

- Change all default credentials immediately upon deployment
- Disable or remove default accounts that are not needed
- Implement account lockout after failed login attempts
- Force password change on first login for default accounts
- Use strong, unique passwords for all accounts
- Regularly audit for default credentials in infrastructure

## References

- [OWASP Testing Guide - Default Credentials](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CIRT Default Password Database](https://www.cirt.net/passwords)

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

