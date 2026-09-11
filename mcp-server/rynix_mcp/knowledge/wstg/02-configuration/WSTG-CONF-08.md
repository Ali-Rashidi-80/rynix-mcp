---
id: WSTG-CONF-08
title: Test RIA Cross Domain Policy
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy
---

# WSTG-CONF-08: Test RIA Cross Domain Policy

## Summary

Rich Internet Application (RIA) cross-domain policy files (`crossdomain.xml` for Flash/Adobe products and `clientaccesspolicy.xml` for Silverlight) define which external domains are allowed to make cross-domain requests to the application. Overly permissive policies can allow any external domain to interact with the application on behalf of authenticated users, leading to cross-site request forgery, data theft, and unauthorized actions. Although Flash and Silverlight are largely deprecated, these policy files may still be present on servers and could affect security if legacy clients are in use. Additionally, CORS misconfigurations follow a similar pattern and should be assessed.

## Test Objectives

- Determine if `crossdomain.xml` and `clientaccesspolicy.xml` files are present
- Assess whether the policies are overly permissive
- Identify if wildcard permissions allow any domain to access the application
- Check for CORS header misconfigurations that follow similar patterns

## Prerequisites

- Target URL is accessible via `http_probe`

## Test Steps

### Step 1: Retrieve Cross-Domain Policy Files

**CLI Actions:**
1. Use `curl` to check for the presence of cross-domain policy files at the web root:
   ``
   GET /crossdomain.xml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /clientaccesspolicy.xml HTTP/1.1
   Host: target.com
   ``
2. Also check for policy files in subdirectories (Flash allows per-directory policy files):
   ``
   GET /api/crossdomain.xml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /assets/crossdomain.xml HTTP/1.1
   Host: target.com
   ``
3. Use `save to manual-review file` to save requests for further analysis of discovered policy files

### Step 2: Analyze crossdomain.xml Permissions

**CLI Actions:**
1. If `crossdomain.xml` is found, examine the content for dangerous configurations:

   **Overly permissive (dangerous):**
   ``xml
   <cross-domain-policy>
     <allow-access-from domain="*"/>
   </cross-domain-policy>
   ``

   **Wildcard subdomain (risky):**
   ``xml
   <cross-domain-policy>
     <allow-access-from domain="*.example.com"/>
   </cross-domain-policy>
   ``

   **Secure headers allowed from any domain (dangerous):**
   ``xml
   <cross-domain-policy>
     <allow-http-request-headers-from domain="*" headers="*"/>
   </cross-domain-policy>
   ``

2. Check for the `<site-control>` meta-policy:
   - `permitted-cross-domain-policies="none"` - Most restrictive (good)
   - `permitted-cross-domain-policies="master-only"` - Only root policy (acceptable)
   - `permitted-cross-domain-policies="all"` - Any policy file is trusted (dangerous)

### Step 3: Analyze clientaccesspolicy.xml Permissions

**CLI Actions:**
1. If `clientaccesspolicy.xml` is found, examine for dangerous configurations:

   **Overly permissive (dangerous):**
   ``xml
   <access-policy>
     <cross-domain-access>
       <policy>
         <allow-from http-request-headers="*">
           <domain uri="*"/>
         </allow-from>
         <grant-to>
           <resource path="/" include-subpaths="true"/>
         </grant-to>
       </policy>
     </cross-domain-access>
   </access-policy>
   ``

2. Check if `<domain uri="*"/>` is used (allows any domain)
3. Check if `<resource path="/" include-subpaths="true"/>` grants access to the entire site
4. Verify that `http-request-headers` is not set to `*` (allows custom headers from any origin)

### Step 4: Test CORS Configuration

**CLI Actions:**
1. Use `curl` to test CORS behavior by sending a request with an `Origin` header:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Origin: https://evil.com
   ``
2. Check the response for:
   - `Access-Control-Allow-Origin: *` (overly permissive)
   - `Access-Control-Allow-Origin: https://evil.com` (reflects arbitrary origin - dangerous)
   - `Access-Control-Allow-Credentials: true` with a wildcard or reflected origin (critical)
3. Test with a null origin:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Origin: null
   ``
4. Test with a subdomain variation:
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Origin: https://evil-target.com
   ``
   ``
   GET /api/data HTTP/1.1
   Host: target.com
   Origin: https://target.com.evil.com
   ``
5. Test preflight request handling:
   ``
   OPTIONS /api/data HTTP/1.1
   Host: target.com
   Origin: https://evil.com
   Access-Control-Request-Method: POST
   Access-Control-Request-Headers: X-Custom-Header
   ``

### Step 5: Review Proxy History for Cross-Origin Patterns

**CLI Actions:**
1. Use `curl` to search for cross-domain policy references in response headers:
   - Pattern: `Access-Control-Allow-Origin`
   - Pattern: `Access-Control-Allow-Credentials`
2. Use `curl` to review all API responses for CORS headers
3. Use `rynix_plugin_run('template-scan')` to check for any CORS or cross-domain policy findings from the template-scan plugin

## Detection Criteria

A finding should be logged when:
- `crossdomain.xml` contains `<allow-access-from domain="*"/>`
- `clientaccesspolicy.xml` contains `<domain uri="*"/>`
- Cross-domain policy allows custom HTTP headers from any domain
- Meta-policy allows policy files in any directory (`permitted-cross-domain-policies="all"`)
- CORS reflects arbitrary `Origin` values in `Access-Control-Allow-Origin`
- CORS uses `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- CORS allows the `null` origin with credentials
- Cross-domain policy files exist when no cross-domain access is needed

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CORS reflects origin with Allow-Credentials: true | High |
| crossdomain.xml allows all domains with credentials | High |
| CORS allows null origin with credentials | Medium |
| crossdomain.xml allows all domains without credentials | Medium |
| CORS reflects origin without credentials | Medium |
| clientaccesspolicy.xml allows all domains | Medium |
| Cross-domain policy exists but is restrictive | Low |
| Legacy policy files present but Flash/Silverlight not used | Low |

## Remediation

- Remove `crossdomain.xml` and `clientaccesspolicy.xml` if Flash/Silverlight are not used
- If cross-domain policy files are needed, restrict to specific trusted domains only:
  ``xml
  <cross-domain-policy>
    <allow-access-from domain="trusted.example.com"/>
  </cross-domain-policy>
  ``
- Set the meta-policy to `master-only` or `none`:
  ``xml
  <site-control permitted-cross-domain-policies="master-only"/>
  ``
- For CORS, explicitly whitelist allowed origins rather than reflecting the `Origin` header
- Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Validate the `Origin` header against a strict allowlist on the server side
- Do not allow the `null` origin when credentials are enabled
- Regularly audit cross-domain policies as part of security reviews

## References

- [OWASP Testing Guide - Test RIA Cross Domain Policy](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy)
- [Adobe Cross-Domain Policy File Specification](https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

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

