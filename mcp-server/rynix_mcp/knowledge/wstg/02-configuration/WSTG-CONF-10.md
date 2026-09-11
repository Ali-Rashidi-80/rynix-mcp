---
id: WSTG-CONF-10
title: Test for Subdomain Takeover
category: Configuration and Deployment Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
---

# WSTG-CONF-10: Test for Subdomain Takeover

## Summary

Subdomain takeover occurs when a subdomain's DNS record (typically a CNAME) points to an external service (such as a cloud hosting provider, CDN, or SaaS platform) that is no longer provisioned or has been decommissioned. An attacker can register the unclaimed resource on the external service and serve malicious content on the target's subdomain. This allows phishing attacks, credential theft, cookie theft (if cookies are scoped to the parent domain), and reputational damage, all appearing to come from the legitimate domain.

## Test Objectives

- Identify subdomains with dangling DNS records pointing to external services
- Determine if the external services referenced by DNS records are unclaimed or deprovisioned
- Assess the impact of potential subdomain takeover on the application and its users
- Check for CNAME records pointing to services known to be vulnerable to takeover

## Prerequisites

- Target URL is accessible via `http_probe`
- Target domain name is known
- List of subdomains has been enumerated (from prior reconnaissance)

## Test Steps

### Step 1: Identify Subdomains and Their DNS Records

**CLI Actions:**
1. Use `curl` to test known or enumerated subdomains and observe responses:
   ``
   GET / HTTP/1.1
   Host: www.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: blog.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: shop.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: staging.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: dev.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: app.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: status.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: docs.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: help.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: support.target.com
   ``
2. Note subdomains that return error pages from third-party services rather than the target's own infrastructure

### Step 2: Detect Dangling DNS Indicators in Responses

**CLI Actions:**
1. Use `curl` to request subdomains and look for telltale error messages from external services:
   ``
   GET / HTTP/1.1
   Host: blog.target.com
   ``
2. Check response bodies for known takeover-vulnerable service error messages:
   - **GitHub Pages**: `There isn't a GitHub Pages site here.`
   - **Heroku**: `No such app`
   - **AWS S3**: `NoSuchBucket` or `The specified bucket does not exist`
   - **AWS CloudFront**: `Bad Request: ERROR: The request could not be satisfied`
   - **Azure**: `404 Web Site not found`
   - **Shopify**: `Sorry, this shop is currently unavailable`
   - **Tumblr**: `There's nothing here.` or `Whatever you were looking for doesn't currently exist at this address`
   - **WordPress.com**: `Do you want to register`
   - **Pantheon**: `404 error unknown site`
   - **Fastly**: `Fastly error: unknown domain`
   - **Zendesk**: `Help Center Closed`
   - **Unbounce**: `The requested URL was not found on this server`
   - **Surge.sh**: `project not found`

3. Use `curl` to search response bodies for these patterns across all browsed subdomains:
   - Pattern: `(NoSuchBucket|No such app|GitHub Pages site here|not found on this server|unknown domain|unknown site)`

### Step 3: Verify Subdomain Takeover Feasibility

**CLI Actions:**
1. For any subdomain returning a third-party error page, use `curl` to confirm the behavior is consistent:
   ``
   GET / HTTP/1.1
   Host: vulnerable-sub.target.com
   ``
   ``
   GET /test HTTP/1.1
   Host: vulnerable-sub.target.com
   ``
2. Check if the response comes from the third-party service (examine `Server` headers, response format, SSL certificate issuer)
3. Use `save to manual-review file` to save the request for documentation and retesting

### Step 4: Test for Cookie Scoping Impact

**CLI Actions:**
1. Use `curl` to check how cookies are scoped on the main domain:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Examine `Set-Cookie` headers for domain scoping:
   - `Set-Cookie: session=abc123; Domain=.target.com` - Cookie sent to ALL subdomains (takeover can steal this)
   - `Set-Cookie: session=abc123; Domain=target.com` - Same as above
   - `Set-Cookie: session=abc123` - Cookie only sent to the exact host (safer)
3. If session cookies are scoped to the parent domain and a subdomain is vulnerable to takeover, the impact is elevated to session hijacking
4. Use `curl` to find all `Set-Cookie` headers with domain scoping:
   - Pattern: `Set-Cookie:.*Domain=`

### Step 5: Check for Subdomain Takeover via Unclaimed Services

**CLI Actions:**
1. Use `curl` to probe for common SaaS/PaaS service indicators:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check response headers for `CNAME`-related clues:
   - Response from AWS infrastructure: `x-amz-*` headers
   - Response from Azure: `x-ms-*` headers
   - Response from Cloudflare: `cf-ray` header
3. Use `rynix_plugin_run('template-scan')` to check for any subdomain-related findings from the template-scan plugin

## Payloads

### Common Subdomains to Test
```
www
blog
shop
store
mail
email
dev
staging
test
qa
uat
api
app
mobile
m
status
docs
help
support
portal
cdn
media
assets
images
static
vpn
remote
beta
alpha
demo
sandbox
```

### Known Vulnerable Service Fingerprints
```
GitHub Pages: "There isn't a GitHub Pages site here"
Heroku: "No such app" / "herokucdn.com/error-pages"
AWS S3: "NoSuchBucket" / "The specified bucket does not exist"
AWS CloudFront: "ERROR: The request could not be satisfied"
Azure: "404 Web Site not found"
Shopify: "Sorry, this shop is currently unavailable"
Tumblr: "There's nothing here"
Pantheon: "404 error unknown site"
Fastly: "Fastly error: unknown domain"
Zendesk: "Help Center Closed"
Surge.sh: "project not found"
Netlify: "Not Found - Request ID"
Bitbucket: "Repository not found"
Ghost: "The thing you were looking for is no longer here"
```

### Automated Subdomain Takeover Testing with dnsreaper

**CLI Actions:**
First, collect subdomains using `dns-enum-cli`:
```bash
rynix_plugin_run('wstg') dns-enum-cli -d target.com -o ./engagements/<eid>/tool-output/subdomains.txt -silent
```

Then test for takeover vulnerabilities with dnsreaper:
```bash
rynix_plugin_run('wstg') python3 /opt/dnsreaper/main.py file --filename ./engagements/<eid>/tool-output/subdomains.txt --out ./engagements/<eid>/tool-output/dnsreaper.json --out-format json
```

dnsreaper checks 50+ cloud providers (AWS S3, Azure, Heroku, GitHub Pages, Shopify, etc.) for dangling CNAME records that could be taken over. Verify CNAME records manually with `dig <subdomain> CNAME` before logging.

## Detection Criteria

A finding should be logged when:
- A subdomain returns an error page from a third-party service indicating an unclaimed resource
- DNS CNAME records point to services that are no longer provisioned
- A subdomain's SSL certificate belongs to a third-party service rather than the target organization
- Third-party service allows registration of the specific resource the CNAME points to
- Session cookies are scoped to the parent domain and a takeover-vulnerable subdomain exists

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Subdomain takeover possible with parent-domain-scoped session cookies | High |
| Subdomain takeover possible on a customer-facing subdomain | High |
| Subdomain takeover possible on internal/dev subdomain | Medium |
| Dangling CNAME detected but service does not allow free registration | Medium |
| Subdomain returns third-party error but DNS is not a CNAME (A record) | Low |

## Remediation

- Remove DNS records for decommissioned services immediately when the service is deprovisioned
- Implement a DNS hygiene process: regularly audit all DNS records and verify they point to active resources
- Deprovision external services only after removing the corresponding DNS records (not before)
- Scope cookies to the most specific domain possible, avoiding parent domain scoping
- Monitor DNS records for changes and alert on dangling references
- Use a subdomain monitoring service to detect potential takeover conditions
- Maintain an inventory of all external services and their corresponding DNS records
- Consider using DNS CAA records to restrict which certificate authorities can issue certificates for subdomains

## References

- [OWASP Testing Guide - Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [HackerOne: A Guide to Subdomain Takeovers](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
- [Can I Take Over XYZ - Service Fingerprint Reference](https://github.com/EdOverflow/can-i-take-over-xyz)

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

