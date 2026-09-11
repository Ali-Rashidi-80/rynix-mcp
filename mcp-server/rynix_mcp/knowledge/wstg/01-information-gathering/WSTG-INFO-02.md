---
id: WSTG-INFO-02
title: Fingerprint Web Server
category: Information Gathering
severity_range: Informational
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
---

# WSTG-INFO-02: Fingerprint Web Server

## Summary

Determining the type and version of a running web server allows testers to identify known vulnerabilities and appropriate exploits. Web servers reveal identity through HTTP headers, error pages, and behavioral differences.

## Test Objectives

- Determine the type and version of the web server
- Identify the underlying operating system and technology stack
- Discover known vulnerabilities associated with the identified versions

## Prerequisites

- Target URL is accessible via `http_probe`

## Test Steps

### Step 1: Analyze HTTP Response Headers

**CLI Actions:**
1. Use `curl` to send a simple GET request to the target root:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Examine response headers for server identification

**Headers to Look For:**
- `Server` - Often reveals web server type and version (e.g., `Apache/2.4.41`, `nginx/1.18.0`)
- `X-Powered-By` - Reveals backend technology (e.g., `PHP/7.4.3`, `ASP.NET`)
- `X-AspNet-Version` - .NET framework version
- `X-Generator` - CMS identification (e.g., `WordPress 5.x`)
- `Via` - Proxy server information
- `X-Server` - Additional server info in some configurations

### Step 2: Probe with Different HTTP Methods

**CLI Actions:**
1. Use `curl` with an OPTIONS request:
   ``
   OPTIONS / HTTP/1.1
   Host: target.com
   ``
2. Use `curl` with a HEAD request:
   ``
   HEAD / HTTP/1.1
   Host: target.com
   ``
3. Use `curl` with an invalid method:
   ``
   FAKEVERB / HTTP/1.1
   Host: target.com
   ``
4. Compare error page formats and headers - different servers produce distinct error pages

### Step 3: Trigger Error Pages

**CLI Actions:**
1. Use `curl` to request a non-existent page:
   ``
   GET /this-page-does-not-exist-12345 HTTP/1.1
   Host: target.com
   ``
2. Use `curl` with a very long URL (8000+ characters) to trigger 414 errors
3. Use `curl` with malformed headers to trigger 400 errors

**What to Look For:**
- Default error page templates differ by server type
- Error messages may include version strings
- Stack traces may reveal technology stack

### Step 4: Check Common Server-Specific Paths

**CLI Actions:**
Send `curl` for each of these paths:

```
/server-status       (Apache)
/server-info         (Apache)
/.htaccess           (Apache)
/nginx_status        (Nginx)
/web.config          (IIS)
/elmah.axd           (ASP.NET)
/trace.axd           (ASP.NET)
/wp-login.php        (WordPress)
/administrator/      (Joomla)
/user/login          (Drupal)
```

### Step 5: HTTP Header Order Analysis

**CLI Actions:**
1. Use `curl` and note the order of response headers
2. Different servers return headers in characteristic orders:
   - Apache typically: `Date, Server, Content-Type`
   - Nginx typically: `Server, Date, Content-Type`
   - IIS typically: `Content-Type, Server, Date`

## Payloads

Not applicable - this is a passive/semi-passive fingerprinting test.

## Detection Criteria

A finding should be logged when:
- Exact server version is disclosed (e.g., `Apache/2.4.41 (Ubuntu)`)
- Backend technology versions are revealed (e.g., `PHP/7.4.3`)
- The identified version has known CVEs
- Default or debug pages are accessible

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Server version with known critical CVEs | Medium |
| Exact server and OS version disclosed | Low |
| Generic server type identified (no version) | Informational |
| Technology stack versions revealed (PHP, .NET) | Low |

## Remediation

- Configure server to suppress or customize the `Server` header
- Remove `X-Powered-By` and similar technology disclosure headers
- Customize error pages to not reveal server identity
- Disable server status/info pages in production
- Keep server software updated to latest stable versions

## References

- [OWASP Testing Guide - Fingerprint Web Server](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

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

