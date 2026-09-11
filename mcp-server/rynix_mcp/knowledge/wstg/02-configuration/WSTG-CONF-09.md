---
id: WSTG-CONF-09
title: Test File Permission
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission
---

# WSTG-CONF-09: Test File Permission

## Summary

File permissions on web servers control who can read, write, and execute files. Overly permissive file permissions can allow attackers to read sensitive configuration files, modify application code, upload web shells, or access data that should be restricted. While file permissions are primarily a server-level concern, their effects can often be observed and tested through HTTP requests by attempting to access or modify files that should be protected.

## Test Objectives

- Identify files and directories with overly permissive access controls
- Determine if sensitive files are readable by the web server process when they should not be
- Check if writable directories exist that could be exploited for code execution
- Assess whether directory listing is enabled, revealing file structure and permissions

## Prerequisites

- Target URL is accessible via `http_probe`
- Some knowledge of the application's file structure (from prior reconnaissance)

## Test Steps

### Step 1: Test for Directory Listing

**CLI Actions:**
1. Use `curl` to request directories without specifying a file to check for directory listing:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
   ``
   GET /images/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /uploads/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /assets/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /files/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /static/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /media/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /backup/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /temp/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /tmp/ HTTP/1.1
   Host: target.com
   ``
2. Look for directory index pages that list files (Apache auto-index, IIS directory browsing, nginx autoindex)
3. Use `save to manual-review file` to further explore any directories that return listings

### Step 2: Test Access to Sensitive Configuration Files

**CLI Actions:**
1. Use `curl` to attempt to read files that should have restricted permissions:
   ``
   GET /etc/passwd HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.htaccess HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.htpasswd HTTP/1.1
   Host: target.com
   ``
   ``
   GET /web.config HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.env HTTP/1.1
   Host: target.com
   ``
   ``
   GET /config/database.yml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-config.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /configuration.php HTTP/1.1
   Host: target.com
   ``
2. A 200 response with file contents indicates overly permissive file access
3. A 403 response is expected and appropriate for these files

### Step 3: Test Upload Directory Permissions

**CLI Actions:**
1. If upload directories were identified, use `curl` to check if uploaded files can be executed:
   ``
   GET /uploads/ HTTP/1.1
   Host: target.com
   ``
2. If file upload functionality exists, test whether the upload directory allows script execution by requesting a known uploaded file with a server-side extension:
   ``
   GET /uploads/test.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /uploads/test.asp HTTP/1.1
   Host: target.com
   ``
   ``
   GET /uploads/test.jsp HTTP/1.1
   Host: target.com
   ``
3. Check if the server executes the script (dangerous) or serves it as a static file (safer)

### Step 4: Test Write Access via HTTP Methods

**CLI Actions:**
1. Use `curl` to test if the server allows writing files via PUT:
   ``
   PUT /test-write-check.txt HTTP/1.1
   Host: target.com
   Content-Type: text/plain
   Content-Length: 19

   Permission test file
   ``
2. Then verify if the file was created:
   ``
   GET /test-write-check.txt HTTP/1.1
   Host: target.com
   ``
3. If the PUT succeeds, the web root has write permissions and the PUT method is enabled, which is a significant vulnerability
4. Test WebDAV-related methods if applicable:
   ``
   MKCOL /testdir/ HTTP/1.1
   Host: target.com
   ``

### Step 5: Check for Sensitive File Exposure via Error Messages

**CLI Actions:**
1. Use `curl` to trigger errors that may reveal file paths and permission information:
   ``
   GET /../../../../etc/passwd HTTP/1.1
   Host: target.com
   ``
   ``
   GET /%00 HTTP/1.1
   Host: target.com
   ``
2. Examine error messages for file path disclosures or "permission denied" messages that confirm file existence
3. Use `curl` to search for permission-related error messages in previous responses:
   - Pattern: `(permission denied|access denied|forbidden|cannot read|cannot write)`
   - Pattern: `(/var/www|/home/|C:\\inetpub|/usr/local)`
4. Use `rynix_plugin_run('template-scan')` to check for any file permission or directory listing findings

## Detection Criteria

A finding should be logged when:
- Directory listing is enabled on any web-accessible directory
- Sensitive configuration files are readable via HTTP
- Upload directories allow execution of server-side scripts
- The server allows writing files via PUT or WebDAV methods
- Error messages reveal file paths and permission details
- Backup or temporary directories are listable and contain sensitive files
- Source code files are served as plaintext due to incorrect permissions

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Write access to web root via PUT/WebDAV | High |
| Upload directory allows script execution | High |
| Sensitive config files with credentials readable via HTTP | High |
| Directory listing enabled exposing sensitive files | Medium |
| .htpasswd or credential files accessible | Medium |
| Directory listing enabled on non-sensitive directories | Low |
| Error messages reveal internal file paths | Low |
| Files accessible but containing no sensitive information | Low |

## Remediation

- Disable directory listing on all web-accessible directories
- Set restrictive file permissions: configuration files should not be world-readable
- Disable PUT, DELETE, and WebDAV methods unless explicitly required
- Configure upload directories to prevent script execution (e.g., deny handler for script extensions)
- Use separate partitions or directories for uploads with no-execute flags
- Run the web server process with minimal required privileges (least privilege principle)
- Restrict access to dot-files (`.htaccess`, `.htpasswd`, `.env`) at the server level
- Implement proper error handling that does not reveal file paths or permissions
- Regularly audit file and directory permissions on web servers
- Use chroot or containerization to limit the web server's file system access

## References

- [OWASP Testing Guide - Test File Permission](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-276: Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

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

