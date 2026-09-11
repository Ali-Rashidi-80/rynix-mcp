---
id: WSTG-CONF-03
title: Test File Extensions Handling for Sensitive Information
category: Configuration and Deployment Management
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information
---

# WSTG-CONF-03: Test File Extensions Handling for Sensitive Information

## Summary

File extension handling determines how a web server processes different file types. Misconfigured servers may serve source code instead of executing it, expose sensitive configuration files, or allow upload of executable content with unexpected extensions. Understanding how the server maps extensions to MIME types and handlers is critical for identifying information disclosure and code execution risks.

## Test Objectives

- Determine how the web server handles requests for files with various extensions
- Identify file extensions that cause source code or configuration disclosure
- Detect extensions that are processed by unexpected handlers
- Find extensions that bypass security controls (e.g., upload filters)

## Prerequisites

- Target URL is accessible via `http_probe`
- Web server technology has been identified (from WSTG-CONF-01)

## Test Steps

### Step 1: Identify File Extensions in Use

**CLI Actions:**
1. Use `curl` to review browsed requests and identify file extensions used by the application (e.g., `.php`, `.asp`, `.aspx`, `.jsp`, `.do`, `.html`, `.js`, `.json`)
2. Use `curl` with patterns to find specific extension types:
   - Pattern: `\.(php|asp|aspx|jsp|do|action|cfm|cgi|pl)` to find server-side file types
   - Pattern: `\.(config|xml|yml|yaml|properties|ini|env)` to find configuration file types
3. Note the `Content-Type` response header for each extension type

### Step 2: Test for Source Code Disclosure via Extension Manipulation

**CLI Actions:**
1. For each identified server-side script, use `curl` to request variations that may cause source code disclosure:

   If the application uses `.php` files:
   ``
   GET /index.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.phps HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.bak HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php~ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.old HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.swp HTTP/1.1
   Host: target.com
   ``

2. If the application uses `.asp` or `.aspx`:
   ``
   GET /default.asp HTTP/1.1
   Host: target.com
   ``
   ``
   GET /default.asp. HTTP/1.1
   Host: target.com
   ``
   ``
   GET /default.asp%00.html HTTP/1.1
   Host: target.com
   ``
   ``
   GET /default.asp::$DATA HTTP/1.1
   Host: target.com
   ``

3. Use `save to manual-review file` to set up requests for systematic testing of extension variations

### Step 3: Test Extension Handling with Null Bytes and Special Characters

**CLI Actions:**
1. Use `curl --data-urlencode` to encode null bytes and special characters for extension testing
2. Use `curl` to send requests with encoded payloads:
   ``
   GET /index.php%00.jpg HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php%0a.html HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php;.jpg HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php%23.jpg HTTP/1.1
   Host: target.com
   ``
3. If the server returns the PHP source code (or equivalent) instead of executing it, the extension handling is misconfigured

### Step 4: Test for Sensitive File Type Exposure

**CLI Actions:**
1. Use `curl` to request common sensitive file types that should not be served:
   ``
   GET /.gitignore HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.env HTTP/1.1
   Host: target.com
   ``
   ``
   GET /composer.json HTTP/1.1
   Host: target.com
   ``
   ``
   GET /package.json HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Gemfile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /requirements.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Makefile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Dockerfile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /docker-compose.yml HTTP/1.1
   Host: target.com
   ``
2. Check if the server returns file contents (200) or properly blocks access (403/404)

### Step 5: Test Content-Type Consistency

**CLI Actions:**
1. Use `curl` to request files and verify the `Content-Type` header matches the file extension:
   ``
   GET /script.js HTTP/1.1
   Host: target.com
   ``
2. Check that `.js` files are served with `application/javascript` (not `text/html`)
3. Check that `.json` files are served with `application/json`
4. Incorrect `Content-Type` headers can enable MIME-sniffing attacks if `X-Content-Type-Options: nosniff` is absent
5. Use `rynix_plugin_run('template-scan')` to review any MIME-type related findings from the template-scan plugin

## Payloads

### Extension Variations for Source Disclosure
```
.phps
.php.bak
.php~
.php.old
.php.orig
.php.txt
.php.swp
.php.sav
.php.save
.php.tmp
.php.1
.php.2
.php_bak
.asp.
.asp::$DATA
.asp%00.html
.aspx.
.aspx%00.html
.jsp.
.jspx
.jspa
```

### Sensitive File Extensions to Check
```
.config
.xml
.yml
.yaml
.properties
.ini
.env
.bak
.backup
.old
.orig
.tmp
.swp
.log
.sql
.db
.sqlite
.key
.pem
.crt
.csr
```

## Detection Criteria

A finding should be logged when:
- Server-side source code is disclosed by requesting alternate extensions
- Null byte or special character injection causes source code disclosure
- Sensitive configuration files are accessible via HTTP
- Build or dependency management files are exposed (package.json, composer.json, etc.)
- File extensions are served with incorrect Content-Type headers
- Environment files (.env) containing secrets are accessible

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Source code disclosure revealing credentials or business logic | High |
| .env file with database credentials or API keys accessible | High |
| Server-side source code partially disclosed | Medium |
| Build/dependency files exposed (package.json, composer.json) | Medium |
| Incorrect Content-Type headers enabling MIME sniffing | Low |
| Non-sensitive configuration files accessible | Low |

## Remediation

- Configure the web server to only serve intended file types and block all others
- Remove backup files, editor temp files, and old versions from web-accessible directories
- Implement a whitelist of allowed file extensions rather than a blacklist
- Ensure proper Content-Type headers are set for all served file types
- Use `X-Content-Type-Options: nosniff` to prevent MIME sniffing
- Block access to dot-files (`.env`, `.git`, `.htaccess`) at the server level
- Move sensitive configuration files outside the web root

## References

- [OWASP Testing Guide - Test File Extensions Handling for Sensitive Information](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

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

- V14 Configuration — secure defaults for headers, TLS, methods.
- V13 API and Web Service — admin interfaces not exposed.

## CWE references

- CWE-16: Configuration
- CWE-319: Cleartext Transmission

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test HTTP methods, security headers, and TLS cipher suites.
- Verify admin/debug interfaces return 404 or require auth in production.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

