---
id: WSTG-INPV-08
title: Testing for XML Injection
category: Input Validation
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
---

# WSTG-INPV-08: Testing for XML Injection

## Summary

XML Injection occurs when user-supplied input is incorporated into XML documents or XML-based queries without proper sanitization. Attackers can manipulate XML structure by injecting XML metacharacters and tags, alter the document's logic, add new XML elements, or modify existing data. This is distinct from XXE (XML External Entity) injection -- XML injection focuses on manipulating the XML document structure itself, while XXE exploits entity processing. XML injection can affect SOAP web services, XML-based APIs, XML data stores, and applications that construct XML dynamically from user input.

## Test Objectives

- Identify parameters whose values are embedded in XML documents
- Test if XML metacharacters can alter the document structure
- Determine if additional XML elements or attributes can be injected
- Assess the impact of XML injection on application logic and data integrity

## Prerequisites

- Target application processes or generates XML data
- Docker pentest container capturing traffic
- Identified endpoints that accept or produce XML (SOAP services, XML APIs, REST endpoints with XML content type)

## Test Steps

### Step 1: Identify XML Processing Points

**CLI Actions:**
1. Use `curl` to identify requests and responses containing XML
2. Use `curl` with pattern `(text/xml|application/xml|application/soap|<\?xml)` to find XML-based traffic
3. Look for:
   - SOAP web service endpoints
   - REST APIs accepting `Content-Type: application/xml`
   - Endpoints that return XML responses
   - Parameters whose values appear in XML responses
4. Use `save to manual-review file` for each XML endpoint

### Step 2: Test for XML Metacharacter Handling

**CLI Actions:**
Use `curl` to inject XML metacharacters into parameters:

**Single quote and double quote:**
```
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/xml

<user><name>test'test</name></user>
```

```
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/xml

<user><name>test"test</name></user>
```

**Angle brackets:**
```
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/xml

<user><name>test<injected>data</injected></name></user>
```

**Ampersand:**
```
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/xml

<user><name>test&amp;test</name></user>
```

If the application returns XML parsing errors or the injected content appears in the output without encoding, the application may be vulnerable.

### Step 3: Test XML Tag Injection

**CLI Actions:**
Use `curl` to inject additional XML elements:

**Injecting a new element to modify data:**
```
POST /api/order HTTP/1.1
Host: target.com
Content-Type: application/xml

<order>
  <item>Widget</item>
  <price>10.00</price>
  <quantity>1</quantity>
</order>
```

Now inject a price override:
```
POST /api/order HTTP/1.1
Host: target.com
Content-Type: application/xml

<order>
  <item>Widget</item>
  <price>10.00</price><price>0.01</price>
  <quantity>1</quantity>
</order>
```

Check if the application processes the second `<price>` element, potentially using the attacker-controlled value.

### Step 4: Test XML Injection in SOAP Services

**CLI Actions:**
Use `curl` to inject into SOAP parameters:

**Normal SOAP request:**
```
POST /ws/userService HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "getUser"

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <username>admin</username>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

**Injected SOAP request:**
```
POST /ws/userService HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "getUser"

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <username>admin</username><role>superadmin</role>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

### Step 5: Test XML Injection via Non-XML Parameters

**CLI Actions:**
Some applications embed regular form parameters into XML server-side. Use `curl`:

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=test</query><role>admin</role><query>test
```

Use `curl --data-urlencode` to properly encode the XML characters:
```
query=test%3C%2Fquery%3E%3Crole%3Eadmin%3C%2Frole%3E%3Cquery%3Etest
```

### Step 6: Test XPath-Based Attacks via XML

**CLI Actions:**
If XML data is queried with XPath, use `curl` to test XPath injection through XML values:

```
POST /api/search HTTP/1.1
Host: target.com
Content-Type: application/xml

<search>
  <field>name</field>
  <value>' or '1'='1</value>
</search>
```

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified any XML-related vulnerabilities.

## Payloads

### XML Metacharacter Payloads
```
< (less than)
> (greater than)
& (ampersand)
' (single quote)
" (double quote)
]]> (CDATA end)
<!-- (comment start)
<![CDATA[ (CDATA start)
```

### XML Tag Injection Payloads
```
<injected>test</injected>
</original><injected>test</injected><original>
"><injected>test</injected><"
</name><role>admin</role><name>
</item><price>0.01</price><item>
```

### SOAP Injection Payloads
```
</username><role>admin</role><username>
</param><admin>true</admin><param>
</value></getUser><deleteUser><username>admin</username></deleteUser><getUser><value>
```

### CDATA Injection Payloads
```
<![CDATA[<script>alert('XSS')</script>]]>
]]><injected>data</injected><![CDATA[
]]>-->
```

### XML Comment Injection
```
<!--injected comment-->
--><injected>data</injected><!--
```

### URL-Encoded XML Payloads
```
%3Cinjected%3Etest%3C%2Finjected%3E
%3C%2Fname%3E%3Crole%3Eadmin%3C%2Frole%3E%3Cname%3E
%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B
```

## Detection Criteria

A finding should be logged when:
- XML metacharacters cause parsing errors revealing XML structure
- Injected XML elements are processed and affect application behavior
- Additional XML tags modify data values (prices, roles, permissions)
- SOAP message manipulation alters service behavior
- XML injection enables bypassing authentication or authorization

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| XML injection modifies critical business data (prices, roles, permissions) | High |
| SOAP injection enables unauthorized service operations | High |
| XML injection bypasses authentication or access controls | High |
| XML tag injection adds data but with limited impact | Medium |
| XML parsing errors reveal internal structure or schema | Medium |
| XML metacharacters cause errors but injection not exploitable | Low |
| XML is properly encoded/escaped in all contexts | Informational |

## Remediation

- Validate and sanitize all user input before embedding in XML documents
- Escape XML special characters: `<` `>` `&` `'` `"` to their entity equivalents
- Use XML schema validation to reject malformed or unexpected elements
- Use parameterized XML construction (DOM APIs) instead of string concatenation
- Implement strict allowlists for expected XML element values
- Apply input length restrictions appropriate to the data field
- Use XML parsers that reject duplicate elements or unexpected structure
- Validate SOAP message structure against the WSDL definition

## References

- [OWASP Testing Guide - XML Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [CWE-91: XML Injection](https://cwe.mitre.org/data/definitions/91.html)
- [CWE-112: Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

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

