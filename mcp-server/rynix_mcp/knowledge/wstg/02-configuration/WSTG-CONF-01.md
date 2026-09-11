---
id: WSTG-CONF-01
title: Test Network Infrastructure Configuration
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
---

# WSTG-CONF-01: Test Network Infrastructure Configuration

## Summary

Network infrastructure configuration testing involves understanding the architecture of the application's hosting environment and identifying potential weaknesses in network components. This includes web servers, reverse proxies, load balancers, firewalls, databases, and other infrastructure elements. Misconfigured network infrastructure can expose unnecessary services, reveal internal architecture details, or provide attack vectors that bypass application-level controls.

## Test Objectives

- Map the network and platform architecture supporting the application
- Identify the web server software and version in use
- Discover unnecessary services, open ports, and exposed management interfaces
- Detect default configurations or known vulnerable infrastructure components
- Identify information leakage through HTTP headers, error messages, or other responses

## Prerequisites

- Target URL is accessible via `http_probe`
- Target hostname or IP address is known
- Authorization to perform infrastructure-level testing

## Test Steps

### Step 1: Fingerprint the Web Server

**CLI Actions:**
1. Use `curl` to send a standard GET request and examine server headers:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Inspect the response for identifying headers:
   - `Server` (e.g., `Apache/2.4.51`, `nginx/1.21.4`, `Microsoft-IIS/10.0`)
   - `X-Powered-By` (e.g., `PHP/8.1`, `ASP.NET`, `Express`)
   - `X-AspNet-Version`
   - `X-Generator`
3. Use `curl` to review multiple responses and look for consistent server identification headers across different endpoints

### Step 2: Probe Server Behavior with Malformed Requests

**CLI Actions:**
1. Use `curl` to send requests that trigger distinctive error responses:
   ``
   GET /nonexistent-page-12345 HTTP/1.1
   Host: target.com
   ``
2. Send a request with an invalid HTTP version:
   ``
   GET / HTTP/3.0
   Host: target.com
   ``
3. Send a request with an invalid method to provoke a server-specific error page:
   ``
   FAKEVERB / HTTP/1.1
   Host: target.com
   ``
4. Send a long URL to trigger buffer or length-based error handling:
   ``
   GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
   Host: target.com
   ``
5. Compare error page formatting, default error text, and headers to known web server signatures

### Step 3: Identify Reverse Proxies, Load Balancers, and CDNs

**CLI Actions:**
1. Use `curl` and look for headers indicating proxy infrastructure:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check for revealing headers:
   - `Via` - indicates proxy servers in the chain
   - `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` - proxy headers
   - `X-Cache`, `X-Cache-Hits` - CDN or caching layer
   - `CF-RAY`, `CF-Cache-Status` - Cloudflare
   - `X-Amz-Cf-Id`, `X-Amz-Cf-Pop` - AWS CloudFront
   - `X-Azure-Ref` - Azure Front Door
   - `X-Served-By`, `X-Timer` - Fastly
3. Send multiple requests and compare response headers for inconsistencies that indicate load balancing (different `Server` headers, varying `X-Served-By` values)

### Step 4: Detect Unnecessary Services via Common Ports

**CLI Actions:**
1. Use `curl` to probe for services on common alternate ports:
   ``
   GET / HTTP/1.1
   Host: target.com:8080
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:8443
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:9090
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:3000
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:4443
   ``
2. Use `save to manual-review file` to set up requests for systematic testing of alternate ports
3. Note any services that respond, especially management interfaces, development servers, or API endpoints

### Step 5: Check for Virtual Host Misconfiguration

**CLI Actions:**
1. Use `curl` to test default virtual host behavior:
   ``
   GET / HTTP/1.1
   Host: localhost
   ``
   ``
   GET / HTTP/1.1
   Host: 127.0.0.1
   ``
2. Test with the server's IP address instead of hostname:
   ``
   GET / HTTP/1.1
   Host: <server-ip>
   ``
3. Test with an unrecognized hostname to see what the default vhost serves:
   ``
   GET / HTTP/1.1
   Host: invalid.host.example
   ``
4. Compare responses - differences may reveal additional applications or administrative interfaces hosted on the same server

### Step 6: Review Known Vulnerabilities

**CLI Actions:**
1. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has detected any known infrastructure vulnerabilities
2. Cross-reference the identified server software and versions against known CVE databases

## Detection Criteria

A finding should be logged when:
- Server software and version are disclosed in response headers
- Unnecessary services are accessible on alternate ports
- Default virtual host configuration exposes additional content
- Reverse proxy or load balancer information is leaked through headers
- Known vulnerable versions of server software are identified
- Internal IP addresses or hostnames are disclosed in headers or error pages
- Management or administrative interfaces are accessible on the same host

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Known vulnerable server version with public exploit | High |
| Unnecessary services exposed (e.g., database ports, debug endpoints) | High |
| Management interfaces accessible without restriction | Medium |
| Internal network architecture details leaked | Medium |
| Server version disclosed in headers | Low |
| Generic information leakage (software names without versions) | Low |

## Remediation

- Suppress or generalize server identification headers (`Server`, `X-Powered-By`)
- Disable unnecessary services and close unused ports
- Ensure default virtual host configuration does not expose unintended content
- Keep all server software updated to the latest stable versions
- Place management interfaces behind VPN or IP-restricted access
- Remove or restrict reverse proxy headers that leak internal architecture
- Use a Web Application Firewall (WAF) to filter responses containing sensitive infrastructure details

## References

- [OWASP Testing Guide - Test Network Infrastructure Configuration](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)

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

