---
id: WSTG-INFO-08
title: Fingerprint Web Application Framework
category: Information Gathering
severity_range: Informational - Low
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
---

# WSTG-INFO-08: Fingerprint Web Application Framework

## Summary

Web applications are built on frameworks and content management systems (CMS) that have characteristic signatures. Identifying the framework (e.g., Django, Ruby on Rails, Spring Boot, Laravel, Express.js) or CMS (e.g., WordPress, Drupal, Joomla) allows testers to leverage framework-specific vulnerability databases, default configurations, and known attack patterns. Frameworks leave fingerprints in HTTP headers, cookies, HTML source, URL patterns, file structures, and error pages.

## Test Objectives

- Identify the web application framework or CMS in use
- Determine the specific version of the framework if possible
- Discover framework-specific default files, paths, and configurations
- Map identified framework versions to known vulnerabilities

## Prerequisites

- Target application is accessible through Docker pentest container
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Analyze HTTP Response Headers for Framework Signatures

**CLI Actions:**
1. Use `curl` to send a GET request to the application root:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to review headers across multiple responses
3. Use `curl` with pattern `X-Powered-By|X-Generator|X-Drupal|X-Redirect-By` to find framework-identifying headers

**Framework-Specific Headers:**

| Header | Framework |
|--------|-----------|
| `X-Powered-By: PHP/x.x` | PHP-based (Laravel, Symfony, WordPress) |
| `X-Powered-By: Express` | Express.js (Node.js) |
| `X-Powered-By: ASP.NET` | ASP.NET |
| `X-Drupal-Cache` or `X-Drupal-Dynamic-Cache` | Drupal |
| `X-Generator: Drupal` | Drupal |
| `X-Redirect-By: WordPress` | WordPress |
| `X-Powered-By: Next.js` | Next.js |
| `X-Turbo-Charged-By: LiteSpeed` | LiteSpeed/WordPress hosting |
| `X-Powered-CMS: *` | Various CMS platforms |

### Step 2: Examine Cookies for Framework Indicators

**CLI Actions:**
1. Use `curl` with pattern `Set-Cookie:` to find all cookies set by the application
2. Use `curl` to send a fresh request with no cookies and examine the `Set-Cookie` headers in the response

**Framework-Specific Cookie Names:**

| Cookie Name | Framework |
|-------------|-----------|
| `JSESSIONID` | Java (Spring, Struts, JSF) |
| `PHPSESSID` | PHP |
| `ASP.NET_SessionId` | ASP.NET |
| `csrftoken` + `sessionid` | Django |
| `_rails_session` or `_appname_session` | Ruby on Rails |
| `laravel_session` + `XSRF-TOKEN` | Laravel |
| `connect.sid` | Express.js with express-session |
| `wp-settings-*` or `wordpress_*` | WordPress |
| `__cfduid` or `cf_clearance` | Cloudflare (infrastructure, not framework) |
| `PLAY_SESSION` | Play Framework |

### Step 3: Review HTML Source for Framework Fingerprints

**CLI Actions:**
1. Use `curl` to fetch the main page and examine the HTML source
2. Use `curl` with pattern `<meta name="generator"` to find CMS identification
3. Use `curl` with pattern `wp-content|wp-includes` to detect WordPress
4. Use `curl` with pattern `/sites/default/files|/core/misc/drupal` to detect Drupal
5. Use `curl` with pattern `/media/jui/|/components/com_` to detect Joomla
6. Use `curl` with pattern `csrf-token|csrf-param|data-turbo` to detect Rails
7. Use `curl` with pattern `__next|_next/static` to detect Next.js
8. Use `curl` with pattern `ng-app|ng-controller|_ngcontent` to detect Angular

**HTML Fingerprints:**

| Pattern | Framework |
|---------|-----------|
| `<meta name="generator" content="WordPress x.x">` | WordPress |
| `<meta name="generator" content="Drupal x">` | Drupal |
| `<meta name="generator" content="Joomla!">` | Joomla |
| `/wp-content/`, `/wp-includes/` | WordPress |
| `/sites/default/files/`, `/core/misc/drupal.js` | Drupal |
| `csrfmiddlewaretoken` in forms | Django |
| `authenticity_token` in forms | Ruby on Rails |
| `__VIEWSTATE`, `__EVENTVALIDATION` | ASP.NET Web Forms |
| `data-reactroot`, `__NEXT_DATA__` | React/Next.js |
| `ng-app`, `ng-version` | Angular |
| `data-turbo-track`, `data-turbo` | Rails (Hotwire/Turbo) |

### Step 4: Probe for Framework-Specific Default Files

**CLI Actions:**
1. Use `curl` to check for CMS-specific files:

   **WordPress:**
   ``
   GET /wp-login.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-json/wp/v2/users HTTP/1.1
   Host: target.com
   ``
   ``
   GET /xmlrpc.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /readme.html HTTP/1.1
   Host: target.com
   ``

   **Drupal:**
   ``
   GET /CHANGELOG.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /core/CHANGELOG.txt HTTP/1.1
   Host: target.com
   ``
   ``
   GET /user/login HTTP/1.1
   Host: target.com
   ``
   ``
   GET /core/install.php HTTP/1.1
   Host: target.com
   ``

   **Joomla:**
   ``
   GET /administrator/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /configuration.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /language/en-GB/en-GB.xml HTTP/1.1
   Host: target.com
   ``

   **Django:**
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /static/admin/css/base.css HTTP/1.1
   Host: target.com
   ``

   **Laravel:**
   ``
   GET /telescope HTTP/1.1
   Host: target.com
   ``
   ``
   GET /horizon HTTP/1.1
   Host: target.com
   ``
   ``
   GET /_ignition/health-check HTTP/1.1
   Host: target.com
   ``

   **Spring Boot:**
   ``
   GET /actuator HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator/health HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator/info HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator/env HTTP/1.1
   Host: target.com
   ``

   **Ruby on Rails:**
   ``
   GET /rails/info HTTP/1.1
   Host: target.com
   ``
   ``
   GET /rails/info/properties HTTP/1.1
   Host: target.com
   ``

2. Use `save to manual-review file` for any default files or admin pages that return a 200 response

### Step 5: Analyze URL Patterns and Routing Conventions

**CLI Actions:**
1. Use `curl` to review all captured URLs and identify routing patterns
2. Use `curl` with pattern `\.php($|\?)` to find PHP-based applications
3. Use `curl` with pattern `\.aspx($|\?)|\.ashx($|\?)` to find ASP.NET applications
4. Use `curl` with pattern `\.jsp($|\?)|\.do($|\?)` to find Java-based applications

**URL Pattern Indicators:**

| URL Pattern | Framework |
|-------------|-----------|
| `*.php` | PHP (generic) |
| `*.aspx`, `*.ashx`, `*.asmx` | ASP.NET |
| `*.jsp`, `*.do`, `*.action` | Java (Struts, Spring MVC) |
| `*.cfm` | ColdFusion |
| RESTful paths with no extensions | Modern frameworks (Rails, Django, Spring Boot, Express) |
| `?q=node/` | Drupal (clean URLs disabled) |
| `/index.php?option=com_*` | Joomla |

### Step 6: Trigger Error Pages for Framework Identification

**CLI Actions:**
1. Use `curl` to trigger a 404 error:
   ``
   GET /nonexistent-path-for-fingerprinting HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to trigger a 500 error with malformed input:
   ``
   GET /%00 HTTP/1.1
   Host: target.com
   ``
3. Use `curl` to trigger validation errors on known form endpoints
4. Use `rynix_plugin_run('template-scan')` to check for any framework-related findings already identified by the template-scan plugin

**Error Page Characteristics:**
- Django: Yellow debug page with "You're seeing this error because you have `DEBUG = True`"
- Rails: "Routing Error" page or Puma/Unicorn error page
- Laravel: Ignition error page with stack trace
- Spring Boot: "Whitelabel Error Page"
- ASP.NET: Yellow Screen of Death (YSOD)
- Express.js: "Cannot GET /path" default response

## Payloads

Not applicable -- this test involves fingerprinting through observation of existing responses and probing for known default files.

## Detection Criteria

A finding should be logged when:
- The web application framework or CMS is positively identified with version information
- Framework-specific default files or admin interfaces are accessible
- Debug or development mode is enabled in production
- The identified framework version has known security vulnerabilities
- Framework-specific administrative tools are exposed (Spring Boot Actuator, Laravel Telescope, Rails info)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Debug/development mode enabled in production (Django DEBUG, Laravel debug) | Low |
| Framework admin tools exposed (Actuator, Telescope, Rails info) | Low |
| Framework version identified with known CVEs | Low |
| CMS version identified via default files (readme.html, CHANGELOG.txt) | Low |
| Framework identified without specific version | Informational |
| Cookie or header-based framework identification only | Informational |

## Remediation

- Remove or restrict access to framework-specific default files (`readme.html`, `CHANGELOG.txt`, `license.txt`)
- Disable debug and development mode in production environments
- Remove or restrict access to administrative tools (Spring Boot Actuator endpoints, Laravel Telescope, Rails info routes)
- Suppress framework-identifying HTTP headers (`X-Powered-By`, `X-Generator`)
- Customize default error pages to not reveal framework identity
- Rename default cookie names where possible to reduce fingerprinting surface
- Keep frameworks and CMS platforms updated to the latest stable versions
- Remove installation scripts and setup wizards after deployment

## References

- [OWASP Testing Guide - Fingerprint Web Application Framework](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [Wappalyzer - Technology Lookup](https://www.wappalyzer.com/)

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

