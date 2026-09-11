---
id: WSTG-INFO-04
title: Enumerate Applications on Webserver
category: Information Gathering
severity_range: Informational - Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver
---

# WSTG-INFO-04: Enumerate Applications on Webserver

## Summary

A web server may host multiple applications across different base URLs, virtual hosts, or non-standard ports. These additional applications may have different security postures, be less maintained, or expose administrative interfaces. Enumerating all applications on a webserver is essential to ensure complete coverage of the attack surface.

## Test Objectives

- Enumerate all web applications hosted on the target web server
- Identify applications running on non-standard ports
- Discover virtual hosts and subdomains pointing to the same server
- Map different base URL paths hosting separate applications

## Prerequisites

- Target domain and IP address are known
- Docker pentest container (`rynix-tools`) is running
- DNS resolution is available for the target domain

## Test Steps

### Step 1: Identify Applications on Different Base URLs

**CLI Actions:**
1. Use `curl` to probe common application base paths:
   ``
   GET /app/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /portal/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /webmail/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /api/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /console/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /manager/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /dashboard/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /phpmyadmin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /jenkins/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /grafana/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /kibana/ HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to review all browsed paths and identify distinct applications by differing response patterns (different CSS frameworks, server headers, or cookie names)
3. Use `save to manual-review file` for each discovered application for further exploration

**What to Look For:**
- HTTP 200 or 301/302 responses indicating an application exists at that path
- Different `Server` or `X-Powered-By` headers suggesting a separate backend
- Distinct session cookie names indicating separate application contexts
- Different HTML structures, CSS frameworks, or JavaScript libraries

### Step 2: Discover Applications on Non-Standard Ports

**CLI Actions:**
1. Use `curl` to probe commonly used non-standard ports:
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
   Host: target.com:8888
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
   ``
   GET / HTTP/1.1
   Host: target.com:8000
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:9200
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:5601
   ``
2. For each port returning a response, use `save to manual-review file` to explore further
3. Note differences in `Server` headers, response content, and TLS certificate subjects across ports

**Common Non-Standard Ports:**
- 8080, 8000, 8888 -- Alternate HTTP
- 8443, 4443 -- Alternate HTTPS
- 3000 -- Node.js/Grafana
- 9090 -- Management interfaces/Prometheus
- 9200 -- Elasticsearch
- 5601 -- Kibana
- 8161 -- ActiveMQ
- 15672 -- RabbitMQ Management

### Step 3: Enumerate Virtual Hosts

**CLI Actions:**
1. Use `curl` to test for virtual host routing by changing the Host header while targeting the same IP:
   ``
   GET / HTTP/1.1
   Host: www.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: mail.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: dev.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: staging.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: test.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: beta.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: api.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: internal.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: intranet.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: admin.target.com
   ``
2. Compare response sizes, status codes, and content to identify distinct virtual hosts versus default responses
3. Use `curl` to test with a non-existent Host header to establish a baseline default response:
   ``
   GET / HTTP/1.1
   Host: does-not-exist.target.com
   ``
4. Any response that differs from the baseline indicates a valid virtual host

### Step 4: DNS-Based Subdomain Enumeration

**CLI Actions:**
1. For each discovered subdomain, use `curl` to confirm the application is reachable:
   ``
   GET / HTTP/1.1
   Host: discovered-subdomain.target.com
   ``
2. Use `curl` with pattern `target\.com` to identify any subdomains referenced in previously captured responses (e.g., in JavaScript files, API calls, CORS headers, CSP headers)
3. Use `save to manual-review file` for each confirmed subdomain application

**Manual Checks:**
- Check DNS TXT records for SPF entries listing mail servers
- Review Certificate Transparency logs for issued certificates revealing subdomains
- Check `Content-Security-Policy` response headers for whitelisted domains
- Check `Access-Control-Allow-Origin` headers for allowed origins

### Step 5: Analyze Differences Between Discovered Applications

**CLI Actions:**
1. For each discovered application, use `curl` to send identical requests and compare:
   - Response headers (especially `Server`, `X-Powered-By`, `Set-Cookie`)
   - Error page behavior (request a non-existent path on each)
   - TLS certificate details (different certificates may indicate different infrastructure)
2. Use `rynix_plugin_run('template-scan')` to check for any issues already identified across the discovered applications
3. Use `curl` to build a complete map of all discovered applications and their technology stacks

## Payloads

Not applicable -- this test involves enumeration through legitimate requests with varied Host headers and paths.

## Detection Criteria

A finding should be logged when:
- Additional applications are discovered that are not part of the documented scope
- Development, staging, or test applications are publicly accessible
- Administrative interfaces (phpMyAdmin, Jenkins, Grafana) are exposed
- Applications on non-standard ports lack authentication
- Virtual hosts respond to internal or development subdomain names
- Different applications on the same server have differing security configurations

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Unauthenticated admin or management interfaces discovered | Medium |
| Staging or development applications accessible from the internet | Medium |
| Internal applications reachable via virtual host manipulation | Medium |
| Additional production applications discovered with outdated software | Low |
| Non-standard ports exposing services with no sensitive data | Low |
| Additional applications discovered with equivalent security posture | Informational |

## Remediation

- Remove or restrict access to development, staging, and test environments from public networks
- Enforce authentication on all administrative and management interfaces
- Disable default virtual host responses or configure them to return a generic page
- Close unnecessary ports and services on production web servers
- Maintain an inventory of all applications hosted on each server
- Apply consistent security policies across all hosted applications
- Use network segmentation to isolate internal tools from public-facing servers

## References

- [OWASP Testing Guide - Enumerate Applications on Webserver](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [Certificate Transparency Logs](https://certificate.transparency.dev/)

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

