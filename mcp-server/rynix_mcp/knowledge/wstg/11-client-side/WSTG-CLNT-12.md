---
id: WSTG-CLNT-12
title: Testing for Inclusion of Third-Party Functionality
category: Client-Side
severity_range: Low-Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_for_Inclusion_of_Third-Party_Functionality
---

# WSTG-CLNT-12: Testing for Inclusion of Third-Party Functionality

## Summary

Modern web applications routinely include third-party JavaScript libraries, widgets, analytics scripts, CDN-hosted resources, and social media integrations. Each external dependency introduces supply chain risk: if a third-party resource is compromised, the attacker's code executes in the context of the host application, with full access to the DOM, cookies, and user data. Risks include compromised CDN resources, malicious npm packages, lack of Subresource Integrity (SRI), and excessive permissions granted to third-party scripts.

## Test Objectives

- Inventory all third-party resources loaded by the application
- Check for Subresource Integrity (SRI) on external scripts and stylesheets
- Assess the trustworthiness and necessity of third-party inclusions
- Identify permissions and data access granted to third-party code
- Check for outdated or vulnerable third-party libraries

## Prerequisites

- Target application is accessible through Docker pentest container
- Application pages have been browsed to load all resources

## Test Steps

### Step 1: Inventory Third-Party Resources

**CLI Actions:**
Use `curl` to collect all resources loaded during application browsing. Identify requests to external domains:

- CDN domains (cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com)
- Analytics services (google-analytics.com, analytics.js)
- Social media widgets (platform.twitter.com, connect.facebook.net)
- Ad networks
- Font services (fonts.googleapis.com)
- Chat/support widgets

Use `curl` to find external script and stylesheet loads:
- Pattern: `<script.*src=.http` (external scripts)
- Pattern: `<link.*href=.http` (external stylesheets)

### Step 2: Check for Subresource Integrity

**CLI Actions:**
Use `curl` to fetch the main page and analyze the HTML:

```
GET / HTTP/1.1
Host: target.com
```

Check if external scripts and stylesheets include `integrity` attributes:

```html
<!-- With SRI (good) -->
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-abc123..."
        crossorigin="anonymous"></script>

<!-- Without SRI (vulnerable to supply chain attack) -->
<script src="https://cdn.example.com/lib.js"></script>
```

Document all external resources without SRI.

### Step 3: Check for Outdated Libraries

**CLI Actions:**
Use `curl` to fetch JavaScript libraries and check version information:

```
GET /static/js/jquery.min.js HTTP/1.1
Host: target.com
```

Check library headers or source code for version numbers. Common vulnerable versions:
- jQuery < 3.5.0 (XSS via `$.htmlPrefilter`)
- Angular.js < 1.6.9 (XSS via template injection)
- Lodash < 4.17.21 (prototype pollution)
- Bootstrap < 4.3.1 (XSS via tooltip/popover)

Use `curl` to search for version strings:
- Pattern: `jQuery v[0-9]`
- Pattern: `angular.*v[0-9]`
- Pattern: `version.*[0-9]+\.[0-9]+\.[0-9]+`

### Step 4: Assess Third-Party Data Access

**CLI Actions:**
Use `curl` to fetch pages and analyze what data third-party scripts can access:

```
GET / HTTP/1.1
Host: target.com
```

Check if third-party scripts are loaded:
- On pages with sensitive data (account, payment, admin)
- Before or alongside CSRF tokens
- With access to authentication cookies (not marked HttpOnly)
- With no CSP restrictions limiting their behavior

### Step 5: Check for Dynamic Script Loading

**CLI Actions:**
Use `curl` to find dynamically loaded external scripts:

- Pattern: `createElement\(.*script` (dynamic script creation)
- Pattern: `document\.write\(.*script` (document.write script injection)
- Pattern: `\.src\s*=\s*['"]http` (dynamic src assignment)

Dynamically loaded scripts cannot use SRI and may change without notice.

### Step 6: Check CSP Restrictions on Third-Party Scripts

**CLI Actions:**
Use `curl` to check the Content-Security-Policy header:

```
GET / HTTP/1.1
Host: target.com
```

Evaluate the CSP for third-party restrictions:
- Does `script-src` allow broad CDN domains?
- Is `unsafe-inline` or `unsafe-eval` enabled?
- Are third-party domains restricted to specific paths?
- Is `strict-dynamic` used to limit script chain loading?

Use `rynix_plugin_run('template-scan')` to check for SRI, outdated library, and CSP findings.

## Payloads

Not applicable - this is an inventory and configuration analysis test.

## Detection Criteria

A finding should be logged when:
- Third-party scripts are loaded without Subresource Integrity (SRI)
- Outdated or known-vulnerable versions of third-party libraries are in use
- Third-party scripts are loaded on sensitive pages (login, payment, admin)
- No CSP restrictions limit third-party script behavior
- Third-party scripts are loaded from HTTP (mixed content)
- Dynamically loaded scripts change without SRI verification
- Unnecessary third-party scripts are included (analytics on admin pages)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Known CVE in included third-party library (exploitable in context) | Medium-High |
| External scripts without SRI on pages with sensitive data | Medium |
| Third-party scripts loaded from HTTP (active mixed content) | Medium |
| Outdated library with known vulnerability but not exploitable in context | Medium |
| No SRI on CDN-hosted scripts (general supply chain risk) | Medium |
| Analytics/tracking scripts on login and payment pages | Low |
| Third-party fonts loaded without SRI | Low |
| All external resources have SRI, libraries up to date, CSP restricts scripts | Not a finding |

## Remediation

- Implement Subresource Integrity (SRI) on all external scripts and stylesheets
- Regularly audit and update third-party libraries for known vulnerabilities
- Self-host critical third-party libraries rather than loading from external CDNs
- Minimize third-party script inclusions to only essential functionality
- Avoid loading analytics and marketing scripts on sensitive pages
- Implement strict Content-Security-Policy to limit third-party script behavior
- Use `crossorigin="anonymous"` with SRI for CORS-enabled resources
- Monitor third-party library security advisories (Snyk, npm audit, GitHub Dependabot)
- Consider using a Software Composition Analysis (SCA) tool for dependency tracking
- Isolate third-party widgets in sandboxed iframes when possible

## References

- [OWASP Testing Guide - Inclusion of Third-Party Functionality](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_for_Inclusion_of_Third-Party_Functionality)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [MDN - Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

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

- V3 Session Management — client-side token storage.
- V5 Validation — DOM sinks and postMessage origins.

## CWE references

- CWE-79: XSS
- CWE-1021: Improper Restriction of Rendered UI Layers

## Rynix tooling

- Primary tools: ``list_frontend_routes``, ``http_probe``, ``rynix_plugin_run` (browser-debug)`

## Test focus

- Map client routes; verify server enforces auth regardless of UI guards.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

