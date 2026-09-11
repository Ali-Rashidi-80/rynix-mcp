---
id: WSTG-INFO-09
title: Fingerprint Web Application
category: Information Gathering
severity_range: Informational - Low
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application
---

# WSTG-INFO-09: Fingerprint Web Application

## Summary

Beyond identifying the framework (WSTG-INFO-08), this test focuses on identifying the specific web application itself and its exact version. Many organizations deploy known applications such as webmail clients, wikis, CRM platforms, issue trackers, or e-commerce solutions. Identifying the exact application and version allows testers to search for known vulnerabilities, default credentials, and application-specific attack vectors.

## Test Objectives

- Identify the specific web application deployed on the target
- Determine the exact version or build number of the application
- Discover default configurations, credentials, or known vulnerabilities for the identified application
- Identify installed plugins, modules, themes, or extensions and their versions

## Prerequisites

- Target application is accessible through Docker pentest container
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Identify the Application Through Visible Indicators

**CLI Actions:**
1. Use `curl` to fetch the main page:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to fetch the login page (often the most identifiable page):
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``
3. Use `curl` with pattern `<title>` to collect page titles from captured responses
4. Use `curl` with pattern `<meta name="generator"` to find application identification tags
5. Use `curl` with pattern `Powered by|Built with|Running on` to find footer or attribution text

**Visible Indicators:**
- Login page branding, logos, and layout (e.g., GitLab login page, Confluence login)
- Page titles (e.g., "Sign in -- GitLab", "Log In - Jira", "Roundcube Webmail")
- Footer text with application name and version
- Favicon (different applications have distinctive favicons)
- Copyright notices referencing specific software

### Step 2: Check Application-Specific Version Files

**CLI Actions:**
1. Use `curl` to probe common version disclosure files:

   **General:**
   ``
   GET /VERSION HTTP/1.1
   Host: target.com
   ``
   ``
   GET /version HTTP/1.1
   Host: target.com
   ``
   ``
   GET /version.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /CHANGES HTTP/1.1
   Host: target.com
   ``
   ``
   GET /CHANGELOG.md HTTP/1.1
   Host: target.com
   ``
   ``
   GET /RELEASE_NOTES HTTP/1.1
   Host: target.com
   ``

   **GitLab:**
   ``
   GET /api/v4/version HTTP/1.1
   Host: target.com
   ``
   ``
   GET /help HTTP/1.1
   Host: target.com
   ``

   **Jira:**
   ``
   GET /rest/api/2/serverInfo HTTP/1.1
   Host: target.com
   ``
   ``
   GET /secure/Dashboard.jspa HTTP/1.1
   Host: target.com
   ``

   **Confluence:**
   ``
   GET /rest/applinks/1.0/manifest HTTP/1.1
   Host: target.com
   ``

   **Jenkins:**
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
   (Check `X-Jenkins` header in response)

   **Grafana:**
   ``
   GET /api/health HTTP/1.1
   Host: target.com
   ``
   ``
   GET /login HTTP/1.1
   Host: target.com
   ``

   **phpMyAdmin:**
   ``
   GET /README HTTP/1.1
   Host: target.com
   ``
   ``
   GET /doc/html/index.html HTTP/1.1
   Host: target.com
   ``

   **Kibana:**
   ``
   GET /api/status HTTP/1.1
   Host: target.com
   ``

   **Roundcube:**
   ``
   GET /CHANGELOG HTTP/1.1
   Host: target.com
   ``
   ``
   GET /program/resources/localization/en_US.php HTTP/1.1
   Host: target.com
   ``

2. Use `save to manual-review file` for any version endpoint that returns useful information

### Step 3: Fingerprint via Static Asset Hashing

**CLI Actions:**
1. Use `curl` with pattern `\.(css|js|ico)\?v=|\.(css|js|ico)\?ver=` to find versioned static assets
2. Use `curl` to fetch known static files and compare their content or hashes against known versions:
   ``
   GET /favicon.ico HTTP/1.1
   Host: target.com
   ``
   ``
   GET /static/style.css HTTP/1.1
   Host: target.com
   ``
3. Use `curl` with pattern `ver=[\d\.]+|v=[\d\.]+|\?[\d\.]+` to extract version strings from asset URLs

**What to Look For:**
- Version query strings on CSS and JavaScript files (e.g., `style.css?ver=5.8.1`)
- Unique favicon hashes that map to specific applications (use Shodan favicon search)
- JavaScript or CSS files containing version comments or build identifiers
- Static file paths that include version directories (e.g., `/static/5.8.1/`)

### Step 4: Identify Installed Plugins, Themes, and Extensions

**CLI Actions:**
1. Use `curl` with pattern `wp-content/plugins/([^/]+)` to enumerate WordPress plugins
2. Use `curl` with pattern `wp-content/themes/([^/]+)` to identify WordPress themes
3. Use `curl` to check for common plugin version files:

   **WordPress Plugins:**
   ``
   GET /wp-content/plugins/akismet/readme.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-content/plugins/contact-form-7/readme.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-content/plugins/woocommerce/readme.txt HTTP/1.1
   Host: target.com
   ``

   **Drupal Modules:**
   ``
   GET /modules/contrib/ HTTP/1.1
   Host: target.com
   ``

   **Joomla Extensions:**
   ``
   GET /administrator/manifests/packages/ HTTP/1.1
   Host: target.com
   ``

4. Use `curl` with pattern `Stable tag:|Version:` in responses to extract plugin version numbers from readme files

### Step 5: Analyze Application-Specific API Responses

**CLI Actions:**
1. Use `curl` to query common API endpoints that return application metadata:
   ``
   GET /api/v1/status HTTP/1.1
   Host: target.com
   ``
   ``
   GET /api/info HTTP/1.1
   Host: target.com
   ``
   ``
   GET /api/health HTTP/1.1
   Host: target.com
   ``
   ``
   GET /api/version HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/openid-configuration HTTP/1.1
   Host: target.com
   ``
2. Use `curl` with pattern `"version"\s*:\s*"` to find version information in JSON API responses
3. Use `curl` with pattern `"build"|"commit"|"revision"` to find build metadata in API responses

### Step 6: Correlate Findings and Confirm Version

**CLI Actions:**
1. Use `curl` to review all collected evidence
2. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified the application or its version
3. Cross-reference multiple version indicators to confirm accuracy:
   - HTML meta tags vs static asset versions vs API responses
   - If indicators conflict, the most specific indicator (API version endpoint, changelog) is most reliable
4. For confirmed applications, use `curl` to check for default credential paths:
   ``
   GET /admin HTTP/1.1
   Host: target.com
   ``
5. Use `curl --data-urlencode` or `base64` as needed when crafting requests to application-specific endpoints that expect encoded parameters

## Payloads

Not applicable -- this test involves fingerprinting through observation and probing known paths rather than injecting payloads.

## Detection Criteria

A finding should be logged when:
- A specific web application is identified with its exact version number
- The identified version has known security vulnerabilities (CVEs)
- Default or version-disclosure files are publicly accessible
- Default credentials are present on the identified application
- Installed plugins or extensions have known vulnerabilities
- Application version is significantly outdated

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Application version with known critical/high CVEs actively exploited | Low |
| Default credentials accessible on identified application | Low |
| Vulnerable plugins or extensions identified | Low |
| Exact application version disclosed via API or files | Low |
| Application identified but version unknown | Informational |
| Application type identified through visual indicators only | Informational |

Note: The severity of the fingerprinting finding itself is Low or Informational. The actual exploitation of discovered vulnerabilities would be assessed separately at their own severity level.

## Remediation

- Remove or restrict access to version disclosure files (VERSION, CHANGELOG, README)
- Disable version information in API health and status endpoints for unauthenticated users
- Remove version query strings from static assets in production
- Customize default login pages to remove application branding if security through obscurity is desired
- Keep the application updated to the latest stable version
- Regularly audit and update installed plugins, themes, and extensions
- Remove unused plugins and extensions
- Restrict access to plugin and extension readme/changelog files
- Monitor CVE databases for vulnerabilities affecting deployed applications and their versions

## References

- [OWASP Testing Guide - Fingerprint Web Application](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [Wappalyzer - Technology Lookup](https://www.wappalyzer.com/)
- [WPScan Vulnerability Database](https://wpscan.com/wordpresses)

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

