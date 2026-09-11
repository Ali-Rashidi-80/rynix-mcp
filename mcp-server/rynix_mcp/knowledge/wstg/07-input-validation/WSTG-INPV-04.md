---
id: WSTG-INPV-04
title: Testing for HTTP Parameter Pollution
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
---

# WSTG-INPV-04: Testing for HTTP Parameter Pollution

## Summary

HTTP Parameter Pollution (HPP) occurs when an attacker submits multiple parameters with the same name in a single HTTP request. Different web technologies handle duplicate parameters differently -- some take the first value, some the last, some concatenate them, and some create arrays. This inconsistency can be exploited to bypass input validation, alter application logic, bypass WAFs, or manipulate server-side operations. HPP can occur in both the query string (server-side) and in form fields or URL parameters used by client-side code.

## Test Objectives

- Determine how the application handles duplicate HTTP parameters
- Test if HPP can bypass input validation or security controls
- Identify HPP vulnerabilities in both server-side and client-side contexts
- Assess whether WAFs or filters can be bypassed using parameter pollution

## Prerequisites

- Target URL is accessible via `http_probe`
- Application entry points and parameters have been mapped (WSTG-INFO-06)
- Understanding of the server-side technology stack (for predicting parameter precedence behavior)

## Test Steps

### Step 1: Identify Parameter Handling Behavior

**CLI Actions:**
1. Use `curl` to identify endpoints with query string parameters
2. For a known parameter, use `curl` to submit duplicate values:
   ``
   GET /search?q=first&q=second HTTP/1.1
   Host: target.com
   ``
3. Examine which value appears in the response:
   - If `first` appears: server uses first occurrence
   - If `second` appears: server uses last occurrence
   - If `first,second` or `first second` appears: server concatenates
   - If both appear separately: server creates an array
4. Use `save to manual-review file` to save the test request for iteration

**Parameter Precedence by Technology:**
| Technology | Behavior |
|-----------|----------|
| ASP.NET / IIS | Concatenates with comma: `first,second` |
| PHP / Apache | Last occurrence: `second` |
| JSP / Tomcat | First occurrence: `first` |
| Python Flask | First occurrence: `first` |
| Python Django | Last occurrence: `second` |
| Node.js Express | First occurrence (or array) |
| Ruby on Rails | Last occurrence: `second` |
| Perl CGI | First occurrence: `first` |

### Step 2: Test HPP in Form Parameters

**CLI Actions:**
1. Use `curl` to find POST requests with form data
2. Use `curl` to submit duplicate form parameters:
   ``
   POST /transfer HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   amount=100&recipient=alice&recipient=attacker
   ``
3. Check which recipient value the application processes
4. Test mixing GET and POST parameters:
   ``
   POST /transfer?recipient=attacker HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   amount=100&recipient=alice
   ``

### Step 3: Test HPP for Validation Bypass

**CLI Actions:**
Use `curl` to test if input validation can be bypassed with duplicate parameters:

**Scenario: Bypassing numeric validation**
```
GET /account?id=1&id=2 OR 1=1 HTTP/1.1
Host: target.com
```
If the validator checks the first `id` parameter (numeric) but the backend uses the second, the SQL injection payload may bypass validation.

**Scenario: Bypassing WAF rules**
```
GET /search?q=SELECT&q=1 FROM users-- HTTP/1.1
Host: target.com
```
A WAF may not flag individual parameters that look benign, but when concatenated on the server they form a malicious query.

### Step 4: Test HPP in URL Rewriting and Redirects

**CLI Actions:**
1. Identify redirects or URL-building functionality
2. Use `curl` to inject additional parameters:
   ``
   GET /redirect?url=https://legit.com&url=https://evil.com HTTP/1.1
   Host: target.com
   ``
3. Check which URL the application redirects to
4. Test with URL-encoded ampersands in parameter values:
   ``
   GET /share?link=https://target.com/page%26param=injected HTTP/1.1
   Host: target.com
   ``
   Use `curl --data-urlencode` to encode the ampersand if needed.

### Step 5: Test Client-Side HPP

**CLI Actions:**
1. Use `curl` to identify pages that construct URLs from parameters in JavaScript
2. Use `curl` to fetch a page with injected parameters:
   ``
   GET /page?param=value%26injected=malicious HTTP/1.1
   Host: target.com
   ``
3. Examine if the response contains JavaScript that uses the polluted parameter in links, forms, or AJAX calls
4. Check if client-side code fails to properly parse or sanitize duplicate parameters

### Step 6: Test HPP with Different Content Types

**CLI Actions:**
Use `curl` to test parameter pollution across content types:

**JSON body with duplicate keys:**
```
POST /api/transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 100, "recipient": "alice", "recipient": "attacker"}
```

**Mixed query string and JSON body:**
```
POST /api/transfer?recipient=attacker HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 100, "recipient": "alice"}
```

## Payloads

### Basic HPP Payloads (Query String)
```
?param=value1&param=value2
?param=value1&param=value2&param=value3
?param[]=value1&param[]=value2
?param=value1&Param=value2
?param=value1&PARAM=value2
```

### HPP for Validation Bypass
```
?id=1&id=2 OR 1=1--
?q=harmless&q=<script>alert(1)</script>
?page=1&page=../../etc/passwd
?email=valid@test.com&email="><script>alert(1)</script>
```

### HPP for WAF Bypass
```
?q=SEL&q=ECT * FROM users
?input=<scr&input=ipt>alert(1)</script>
?cmd=;ca&cmd=t /etc/passwd
```

### HPP via URL Encoding
```
?param=value1%26param=value2
?url=https://legit.com%26redirect=https://evil.com
?callback=safe%26callback=malicious
```

### HPP in POST Body
```
amount=100&recipient=alice&recipient=attacker
user=admin&role=user&role=admin
action=view&action=delete
```

### HPP with Case Variations
```
?param=value1&Param=value2
?param=value1&PARAM=value2
?Param=value1&param=value2
```

## Detection Criteria

A finding should be logged when:
- The application processes a different parameter occurrence than what the input validator checks
- Duplicate parameters alter application logic or data flow
- HPP enables bypass of WAF or input validation rules
- Parameter pollution changes the target of a redirect or form action
- Duplicate JSON keys are resolved in favor of the attacker-controlled value

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| HPP bypasses authentication or authorization controls | High |
| HPP enables SQL injection or XSS via validation bypass | High |
| HPP alters financial transactions or business logic | High |
| HPP bypasses WAF to enable other attacks | Medium |
| HPP manipulates redirect targets for phishing | Medium |
| HPP causes unexpected behavior without security impact | Low |
| Duplicate parameters accepted but no exploitable effect | Informational |

## Remediation

- Explicitly define which parameter occurrence to use (first, last) and enforce consistently
- Reject requests with duplicate parameter names where duplicates are not expected
- Use a strict input validation layer that inspects all parameter occurrences, not just one
- URL-encode user input before incorporating it into URLs
- Avoid constructing URLs from user-controlled parameters on the client side
- Use framework-level protections that normalize parameters before processing
- Test validation logic against duplicate parameters during development

## References

- [OWASP Testing Guide - HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [HTTP Parameter Pollution - OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [CWE-235: Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

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

