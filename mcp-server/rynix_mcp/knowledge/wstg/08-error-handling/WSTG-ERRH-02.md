---
id: WSTG-ERRH-02
title: Testing for Stack Traces
category: Error Handling
severity_range: Informational-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces
---

# WSTG-ERRH-02: Testing for Stack Traces

## Summary

Stack traces are detailed error outputs generated when an application encounters an unhandled exception. They typically reveal internal class names, method names, file paths, line numbers, framework versions, and database connection strings. When exposed to end users in production, stack traces provide attackers with a roadmap of the application internals, significantly reducing the effort required to craft targeted exploits.

## Test Objectives

- Trigger unhandled exceptions that produce stack traces
- Identify stack traces exposed in HTTP responses, API error bodies, and response headers
- Assess the sensitivity of information disclosed in stack traces
- Determine whether stack trace disclosure is consistent across the application

## Prerequisites

- Target URL is accessible via `http_probe`
- Basic application functionality and input parameters have been mapped
- Authentication credentials available (if applicable) to test authenticated endpoints

## Test Steps

### Step 1: Trigger Exceptions via Malformed Input

**CLI Actions:**
Use `curl` to send requests with inputs designed to cause unhandled exceptions:

```
GET /api/user/abc HTTP/1.1
Host: target.com
```

```
GET /api/user/-1 HTTP/1.1
Host: target.com
```

```
GET /api/user/9999999999999999999 HTTP/1.1
Host: target.com
```

```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json

{malformed json here
```

```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/xml

<root><unclosed>
```

Use `save to manual-review file` with each request to iterate quickly on different malformed inputs and observe responses.

### Step 2: Trigger Database-Related Stack Traces

**CLI Actions:**
Use `curl` to inject SQL meta-characters into all identified parameters:

```
GET /product?id=1' HTTP/1.1
Host: target.com
```

```
GET /search?q='; DROP TABLE-- HTTP/1.1
Host: target.com
```

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin'&password=test
```

Look for stack traces containing JDBC/ODBC driver names, SQL query fragments, database schema details, or connection strings.

### Step 3: Trigger Type Confusion and Serialization Errors

**CLI Actions:**
Use `curl` to submit unexpected data types:

```
POST /api/order HTTP/1.1
Host: target.com
Content-Type: application/json

{"quantity": "not_a_number", "price": [1,2,3], "item": {"nested": true}}
```

```
POST /api/process HTTP/1.1
Host: target.com
Content-Type: application/json

{"data": null, "callback": true, "id": -9999999999999999999}
```

Use `curl --data-urlencode` to encode special characters before injecting into URL parameters:

```
GET /page?param=%00%ff%fe HTTP/1.1
Host: target.com
```

### Step 4: Trigger Framework-Specific Error Pages

**CLI Actions:**
Use `curl` to probe for framework-specific debug/error pages:

```
GET /elmah.axd HTTP/1.1
Host: target.com
```

```
GET /debug/default/view HTTP/1.1
Host: target.com
```

```
GET /actuator/health HTTP/1.1
Host: target.com
```

```
GET /error HTTP/1.1
Host: target.com
```

```
GET /_debug HTTP/1.1
Host: target.com
```

Test forcing exceptions via HTTP method manipulation:

```
PATCH / HTTP/1.1
Host: target.com
```

```
DELETE /api/user/1 HTTP/1.1
Host: target.com
```

### Step 5: Search Proxy History for Stack Traces

**CLI Actions:**
Use `curl` with patterns to find stack traces already captured:

- Pattern: `at [a-zA-Z]+\.[a-zA-Z]+\(` (Java stack traces)
- Pattern: `Traceback \(most recent call last\)` (Python stack traces)
- Pattern: `Stack Trace:` (.NET stack traces)
- Pattern: `Fatal error:.*in /` (PHP stack traces)
- Pattern: `Error:.*at Object\.` (Node.js stack traces)

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has already identified any stack trace disclosures.

### Step 6: Analyze Disclosed Information

**CLI Actions:**
For every stack trace found, use `save to manual-review file` to reproduce the triggering request. Document:

- **Class/function names** - reveal application architecture
- **File paths** - reveal server directory structure (e.g., `/opt/app/src/controllers/UserController.java`)
- **Line numbers** - help attackers pinpoint vulnerable code
- **Framework and library versions** - enable targeted CVE exploitation
- **Database details** - connection strings, schema names, table names
- **Internal hostnames/IPs** - reveal network topology
- **Configuration details** - environment variables, feature flags

## Payloads

### Type Confusion Inputs
```
abc
-1
0
99999999999999999999
1.1.1.1
true
false
null
undefined
NaN
Infinity
[]
{}
```

### Malformed Data Payloads
```
{malformed json
<unclosed xml
%00%ff%fe
\x00\x01\x02
{{template_injection}}
${expression}
#{expression}
@(expression)
```

### SQL Error Triggers
```
'
''
' OR '1'='1
'; SELECT 1--
1 UNION SELECT NULL--
1' AND 1=CONVERT(int,'a')--
```

### Path-Based Error Triggers
```
/../../../etc/passwd
/..%00/
/./././././
/%2e%2e%2f
/AAAA(8000+ chars)
```

### HTTP Method Confusion
```
PATCH
PROPFIND
TRACE
OPTIONS
CONNECT
```

## Detection Criteria

A finding should be logged when:
- Full or partial stack traces appear in HTTP response bodies
- Error messages contain class names, method names, or file paths
- Database connection strings or query fragments are visible
- Framework or library version numbers are exposed via error pages
- Debug or diagnostic endpoints are accessible in production
- Stack trace details appear in HTTP response headers (e.g., `X-Error`, custom headers)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Stack traces reveal database connection strings or credentials | Medium |
| Full stack traces with file paths and line numbers exposed | Medium |
| Stack traces reveal internal IP addresses or hostnames | Medium |
| Framework debug pages accessible in production (e.g., Django debug, Spring Boot actuator) | Medium |
| Partial stack traces with class/method names only | Low |
| Technology or framework version revealed via error page | Low |
| Generic error page with a stack trace ID or correlation ID only | Informational |
| Custom error page with no technical details | Not a finding |

## Remediation

- Configure a global exception handler that catches all unhandled exceptions
- Return generic, user-friendly error messages in production (e.g., "An error occurred. Please try again.")
- Log full stack traces server-side to centralized logging (ELK, Splunk, CloudWatch)
- Disable debug mode, development error pages, and verbose error output in production
- Remove or restrict access to framework diagnostic endpoints (actuator, elmah, debug panels)
- Implement custom error pages for all HTTP status codes (400, 403, 404, 500, 502, 503)
- Strip stack trace information from API error responses before returning to clients
- Use error correlation IDs so support teams can trace issues without exposing internals

## References

- [OWASP Testing Guide - Stack Traces](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

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

- V7 Error Handling — no stack traces or internal paths in responses.
- V14 Configuration — custom error pages in production.

## CWE references

- CWE-209: Generation of Error Message Containing Sensitive Information

## Rynix tooling

- Primary tools: ``http_probe``, ``record_finding``

## Test focus

- Trigger edge-case inputs and verify generic error responses only.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

