---
id: WSTG-INFO-06
title: Identify Application Entry Points
category: Information Gathering
severity_range: Informational
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
---

# WSTG-INFO-06: Identify Application Entry Points

## Summary

Enumerating the application's entry points and mapping its attack surface is a critical prerequisite for thorough security testing. Entry points include all URLs, parameters, headers, and data channels that accept user input.

## Test Objectives

- Map all application endpoints that accept user input
- Identify all HTTP parameters (GET, POST, cookie, header-based)
- Understand data flows and how input reaches the application
- Document the attack surface for subsequent testing phases

## Prerequisites

- Target application has been browsed through Docker pentest container to build proxy history
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Review Proxy History for Endpoints

**CLI Actions:**
1. Use `curl` to retrieve all captured requests
2. Use `curl` with patterns to find interesting endpoints:
   - Pattern: `\?.*=` (URLs with query parameters)
   - Pattern: `api/|rest/|graphql` (API endpoints)
   - Pattern: `login|auth|register|signup` (authentication endpoints)
   - Pattern: `upload|import|file` (file handling endpoints)
   - Pattern: `admin|manage|config|dashboard` (admin endpoints)

### Step 2: Enumerate Parameters per Endpoint

**CLI Actions:**
1. For each interesting endpoint found in Step 1, use `save to manual-review file` for manual inspection
2. Use `curl` to resend requests and analyze which parameters are reflected or processed

**Parameters to Document:**
- URL query string parameters (GET)
- POST body parameters (form data, JSON, XML)
- URL path parameters (e.g., `/user/123/profile`)
- Cookie values that influence behavior
- HTTP headers that are processed (e.g., `X-Forwarded-For`, `Referer`, `User-Agent`)
- Custom headers (e.g., `X-API-Key`, `Authorization`)

### Step 3: Identify Hidden Parameters and Endpoints

**CLI Actions:**
1. Use `curl` to test for common hidden parameters by appending them:
   - `?debug=true`, `?test=1`, `?admin=1`
   - `?_method=PUT`, `?_format=json`
   - `?callback=test` (JSONP)
2. Check for common API versioning patterns:
   - `/api/v1/`, `/api/v2/`, `/api/v3/`
3. Check response differences with different `Accept` headers:
   - `Accept: application/json`
   - `Accept: application/xml`
   - `Accept: text/html`

### Step 4: Map Authentication and Session Boundaries

**CLI Actions:**
1. Use `curl` to identify which endpoints require authentication
2. Use `curl` to test each endpoint without auth cookies/tokens
3. Document: public endpoints, authenticated endpoints, admin-only endpoints

### Step 5: Document the Attack Surface

Create a summary of all identified entry points organized by:
- **Forms**: All HTML forms and their action URLs + parameters
- **API endpoints**: REST/GraphQL/SOAP endpoints
- **File uploads**: Any upload functionality
- **Redirects**: Parameters controlling redirects
- **Search/filter**: Parameters for search and filtering
- **User profile**: Fields that accept user content

## Payloads

Not applicable - this is an enumeration/mapping test.

## Detection Criteria

This test produces a map of the attack surface rather than findings. Log a finding if:
- Undocumented or hidden endpoints are discovered (e.g., debug endpoints in production)
- Admin interfaces are accessible without proper authentication
- API endpoints lack authentication requirements
- Excessive information is returned in API responses

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Unauthenticated admin or debug endpoints | High |
| API endpoints returning excessive data without auth | Medium |
| Hidden parameters that alter application behavior | Low |
| General attack surface documentation | Informational |

## Remediation

- Remove debug and test endpoints from production
- Implement consistent authentication across all endpoints
- Apply principle of least privilege to API responses
- Document and maintain an API specification (OpenAPI/Swagger)

## References

- [OWASP Testing Guide - Identify Application Entry Points](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points)

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

- V1 Architecture — document exposed surfaces found via recon.
- V14 Configuration — verify no sensitive paths in robots/sitemap.

## CWE references

- CWE-200: Exposure of Sensitive Information

## Rynix tooling

- Primary tools: ``scope_check``, ``http_probe``, ``analyze_repo``, ``get_wstg_test``

## Test focus

- Passive recon only — no destructive probes.
- Correlate search-engine findings with live `http_probe` status.
- Save interesting URLs to engagement context for later phases.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

