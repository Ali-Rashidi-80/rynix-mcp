---
id: WSTG-CONF-13
title: Test Path Confusion
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/13-Test_Path_Confusion
---

# WSTG-CONF-13: Test Path Confusion

## Summary

Path confusion vulnerabilities arise from differences in how URL paths are interpreted by different components in the request processing chain, such as reverse proxies, web servers, application frameworks, and CDNs. When these components normalize, decode, or parse URL paths differently, attackers can craft URLs that bypass access controls, expose unintended resources, poison caches, or reach endpoints that should be restricted. Common techniques include path traversal sequences, URL encoding variations, path parameter injection, and exploiting differences between how a proxy routes a request and how the backend interprets it.

## Test Objectives

- Identify discrepancies in path parsing between reverse proxies and backend servers
- Test for path traversal via URL normalization differences
- Assess if path confusion can bypass authentication or authorization controls
- Determine if cache poisoning is possible through path confusion
- Check for path parameter injection vulnerabilities

## Prerequisites

- Target URL is accessible via `http_probe`
- Knowledge of the infrastructure stack (reverse proxy, web server, framework) is helpful

## Test Steps

### Step 1: Test Path Normalization Differences

**CLI Actions:**
1. Use `curl` to test how the server handles various path normalization sequences. Start with a known protected path (e.g., `/admin/dashboard`):
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   ``
2. Test path traversal with dot segments:
   ``
   GET /public/../admin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/./dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/anything/../dashboard HTTP/1.1
   Host: target.com
   ``
3. Test with double URL-encoded traversal sequences:
   ``
   GET /admin%2f..%2fadmin/dashboard HTTP/1.1
   Host: target.com
   ``
4. Use `curl --data-urlencode` to encode path components:
   - Encode `../` to test for double-encoding bypass
   - Encode `/admin/` to test for path matching bypass

### Step 2: Test URL Encoding Variations

**CLI Actions:**
1. Use `curl` with various URL encoding techniques to test path parsing:
   ``
   GET /admin%2fdashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /%61dmin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard%00 HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard%20 HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard%0a HTTP/1.1
   Host: target.com
   ``
2. Test double URL encoding:
   ``
   GET /%2561dmin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin%252fdashboard HTTP/1.1
   Host: target.com
   ``
3. Use `curl --data-urlencode` to prepare encoded payloads and `python3 -c "import urllib.parse; ..."` to verify correct encoding
4. Compare responses - if a protected path returns different results with encoded variants, the proxy and backend disagree on path interpretation

### Step 3: Test Path Parameter Injection

**CLI Actions:**
1. Use `curl` to test path parameters (semicolons) that some frameworks interpret as parameters:
   ``
   GET /admin/dashboard;.js HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard;foo=bar HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin;/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /public/..;/admin/dashboard HTTP/1.1
   Host: target.com
   ``
2. The `..;/` pattern is particularly important: some servers (e.g., Tomcat, Jetty) treat `;` as a path parameter delimiter and ignore everything between `;` and `/`, effectively resolving `..;/` as `../`
3. While a reverse proxy like nginx may see `/public/..;/admin/dashboard` as a path under `/public/`, Tomcat may resolve it to `/admin/dashboard`
4. Use `save to manual-review file` to test multiple path parameter variations systematically

### Step 4: Test Trailing Character Confusion

**CLI Actions:**
1. Use `curl` to test how trailing characters affect path routing:
   ``
   GET /admin/dashboard/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard. HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard.. HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard.html HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard.js HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard.css HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard.ico HTTP/1.1
   Host: target.com
   ``
2. Some reverse proxies route requests to static file handlers based on extension. If `/admin/dashboard.js` is routed differently than `/admin/dashboard`, it may bypass auth checks applied at the proxy level
3. Compare response status codes and content across all variations

### Step 5: Test Cache Poisoning via Path Confusion

**CLI Actions:**
1. Use `curl` to test if path confusion can poison a CDN or caching layer:
   ``
   GET /account/profile%2f..%2fstatic/image.jpg HTTP/1.1
   Host: target.com
   ``
2. If the cache keys on the URL path as-is, but the backend resolves the path differently, the response for `/account/profile` (authenticated content) might be cached under a path that appears to be a static asset
3. Test cache behavior:
   ``
   GET /account/profile/..%2fstatic%2ftest.css HTTP/1.1
   Host: target.com
   ``
4. Check response headers for caching indicators:
   - `X-Cache: HIT` / `X-Cache: MISS`
   - `Age` header
   - `Cache-Control` header
   - `CF-Cache-Status` (Cloudflare)
5. Use `curl` to search for caching headers across responses:
   - Pattern: `(X-Cache|CF-Cache-Status|X-Varnish|Age:)`

### Step 6: Test Proxy vs Backend Path Disagreement for ACL Bypass

**CLI Actions:**
1. If the application uses a reverse proxy for access control, use `curl` to test bypass techniques:
   ``
   GET /api/admin%2F HTTP/1.1
   Host: target.com
   ``
   ``
   GET //admin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /./admin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard?%2f HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Admin/Dashboard HTTP/1.1
   Host: target.com
   ``
2. Test backslash vs forward slash (Windows IIS may treat them identically):
   ``
   GET /admin\dashboard HTTP/1.1
   Host: target.com
   ``
3. Test with fragment-like characters:
   ``
   GET /admin/dashboard#fragment HTTP/1.1
   Host: target.com
   ``
4. Use `rynix_plugin_run('template-scan')` to check for any path confusion or normalization findings from the template-scan plugin

## Payloads

### Path Traversal and Normalization Sequences
```
../
..%2f
%2e%2e/
%2e%2e%2f
..%252f
..;/
..%00/
..%0d/
..%0a/
..\
..%5c
%2e%2e%5c
..%255c
/./
//
```

### Path Parameter Injection Patterns
```
;foo=bar
;.js
;.css
;.jpg
;.html
..;/
..;foo/
```

### Trailing Extension Bypass Patterns
```
.js
.css
.jpg
.png
.gif
.ico
.html
.json
.xml
.woff
.woff2
```

### Case and Encoding Variations
```
%2f (/)
%2F (/)
%5c (\)
%5C (\)
%252f (double-encoded /)
%252F (double-encoded /)
%2561 (double-encoded 'a')
%00 (null byte)
%20 (space)
%0a (newline)
%0d (carriage return)
```

### Automated CORS Testing with cors-probe

**CLI Actions:**
Use `cors-probe` for automated CORS misconfiguration detection:

```bash
rynix_plugin_run('wstg') python3 -m cors-probe.cors_scan -u https://target.com -o ./engagements/<eid>/tool-output/cors-probe.json
```

cors-probe tests for: wildcard origin (`*`) with credentials, null origin acceptance, reflected origin without validation, and sensitive data exposure via CORS. Findings are generally reliable — verify exploitability manually.

## Detection Criteria

A finding should be logged when:
- Path normalization differences allow access to protected endpoints
- URL encoding variations bypass access controls
- Path parameter injection (`..;/`) allows path traversal
- Trailing extensions cause different routing decisions that bypass authentication
- Cache poisoning is possible through path confusion
- Double-encoded paths bypass proxy-level access restrictions
- Different response codes or content are returned for semantically equivalent paths

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Path confusion bypasses authentication to access admin functionality | High |
| Cache poisoning exposes authenticated content to unauthenticated users | High |
| Path traversal via normalization differences accesses restricted files | High |
| Path confusion bypasses authorization for API endpoints | Medium |
| Path parameter injection reaches different endpoints than intended | Medium |
| Inconsistent path handling detected but no exploitable bypass found | Low |
| Trailing extension causes different caching behavior without data exposure | Low |

## Remediation

- Normalize paths at the earliest point in the request processing chain (ideally the reverse proxy)
- Ensure all components in the stack agree on path interpretation before making access control decisions
- Reject requests containing path traversal sequences (`../`, `..;/`, encoded variants) at the proxy level
- Decode URLs exactly once before making routing and access control decisions
- Use a consistent URL parsing library across all components
- Disable path parameter processing (semicolons) if not needed by the application
- Configure caches to include the full normalized path in cache keys
- Apply access controls at the application level, not solely at the proxy level
- Reject requests with double-encoded characters
- Test path handling thoroughly when adding or changing reverse proxy configurations

## References

- [OWASP Testing Guide - Test Path Confusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/13-Test_Path_Confusion)
- [CWE-436: Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Orange Tsai - Breaking Parser Logic: URL Parsing Confusion](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)

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

