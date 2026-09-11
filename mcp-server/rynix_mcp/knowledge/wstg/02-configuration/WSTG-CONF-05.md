---
id: WSTG-CONF-05
title: Enumerate Infrastructure and Application Admin Interfaces
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces
---

# WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces

## Summary

Administrative interfaces provide privileged access to manage applications, servers, databases, and infrastructure components. These interfaces are high-value targets because they typically allow configuration changes, user management, data access, and code execution. If admin interfaces are publicly accessible, protected only by weak credentials, or discoverable through predictable URLs, attackers can gain full control of the application or its underlying infrastructure.

## Test Objectives

- Identify all administrative and management interfaces for the application and its infrastructure
- Determine if admin interfaces are accessible from the public internet
- Assess authentication and access control mechanisms protecting admin interfaces
- Check for default or well-known admin interface paths

## Prerequisites

- Target URL is accessible via `http_probe`
- Target hostname and common subdomains are known

## Test Steps

### Step 1: Discover Application Admin Panels via Common Paths

**CLI Actions:**
1. Use `curl` to probe for standard admin panel paths:
   ``
   GET /admin HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /administrator/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/login HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-login.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /admin/dashboard HTTP/1.1
   Host: target.com
   ``
   ``
   GET /controlpanel/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /cpanel HTTP/1.1
   Host: target.com
   ``
   ``
   GET /manage HTTP/1.1
   Host: target.com
   ``
   ``
   GET /management HTTP/1.1
   Host: target.com
   ``
   ``
   GET /console HTTP/1.1
   Host: target.com
   ``
2. Use `fuzz-cli` with a comprehensive wordlist of admin paths to automate discovery
3. Note response codes: 200 (accessible), 301/302 (redirect, possibly to login), 403 (forbidden but exists), 404 (not found)

### Step 2: Discover CMS-Specific Admin Interfaces

**CLI Actions:**
1. Based on identified technology stack, use `curl` to test CMS-specific admin URLs:

   WordPress:
   ``
   GET /wp-admin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /wp-login.php HTTP/1.1
   Host: target.com
   ``

   Joomla:
   ``
   GET /administrator/ HTTP/1.1
   Host: target.com
   ``

   Drupal:
   ``
   GET /admin HTTP/1.1
   Host: target.com
   ``
   ``
   GET /user/login HTTP/1.1
   Host: target.com
   ``

   Django:
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   ``

   Laravel:
   ``
   GET /nova HTTP/1.1
   Host: target.com
   ``
   ``
   GET /telescope HTTP/1.1
   Host: target.com
   ``
   ``
   GET /horizon HTTP/1.1
   Host: target.com
   ``

### Step 3: Discover Infrastructure Management Interfaces

**CLI Actions:**
1. Use `curl` to probe for server management tools on alternate ports and paths:
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
   Host: target.com:2082
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:2083
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:2086
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:2087
   ``
   ``
   GET / HTTP/1.1
   Host: target.com:10000
   ``
2. Check for database management interfaces:
   ``
   GET /phpmyadmin/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /pma/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /adminer.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /pgadmin/ HTTP/1.1
   Host: target.com
   ``

### Step 4: Discover Admin Interfaces via Subdomains

**CLI Actions:**
1. Use `curl` to probe common admin subdomains:
   ``
   GET / HTTP/1.1
   Host: admin.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: manage.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: panel.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: portal.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: dashboard.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: backend.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: cms.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: api.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: staging.target.com
   ``
   ``
   GET / HTTP/1.1
   Host: internal.target.com
   ``
2. Compare responses to the main site - a different response indicates a separate application or admin interface

### Step 5: Search for Admin Interface References in Application Content

**CLI Actions:**
1. Use `curl` to search for admin references in browsed content:
   - Pattern: `(admin|manage|dashboard|console|panel|backend)` in URLs and response bodies
   - Pattern: `href=["'][^"']*admin[^"']*["']` to find admin links in HTML
2. Use `curl` to review JavaScript files for API endpoint references that may reveal admin functionality
3. Check HTML source for hidden links, comments referencing admin paths, or `robots.txt` disallowed entries

### Step 6: Check Admin Interface Protection

**CLI Actions:**
1. For each discovered admin interface, use `curl` to assess protections:
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   ``
2. Check if:
   - The interface redirects to a login page (good)
   - The interface is directly accessible without authentication (critical)
   - The login page reveals the admin panel software and version
   - The interface returns 403 only based on IP (can potentially be bypassed)
3. Use `rynix_plugin_run('template-scan')` to check for any admin interface findings from the template-scan plugin

## Payloads

### Common Admin Paths
```
/admin
/admin/
/admin/login
/admin/dashboard
/administrator/
/admin.php
/login
/backend/
/manage/
/management/
/manager/
/console/
/controlpanel/
/cp/
/panel/
/portal/
/webadmin/
/siteadmin/
/moderator/
/supervisor/
/wp-admin/
/wp-login.php
/user/login
/dashboard/
```

### Database Management Paths
```
/phpmyadmin/
/pma/
/mysql/
/adminer.php
/pgadmin/
/dbadmin/
/myadmin/
/phpMyAdmin/
/sql/
```

### Infrastructure Management Ports
```
2082 (cPanel HTTP)
2083 (cPanel HTTPS)
2086 (WHM HTTP)
2087 (WHM HTTPS)
8080 (Alternate HTTP / Tomcat)
8443 (Alternate HTTPS)
9090 (Various admin tools)
10000 (Webmin)
3000 (Grafana, dev servers)
5601 (Kibana)
8888 (Various admin tools)
9200 (Elasticsearch)
15672 (RabbitMQ Management)
```

## Detection Criteria

A finding should be logged when:
- Admin interfaces are accessible from the public internet without IP restrictions
- Admin login pages are discoverable at predictable URLs
- Admin interfaces are accessible without authentication
- Database management tools (phpMyAdmin, Adminer) are publicly accessible
- Infrastructure management panels are accessible on public-facing ports
- Admin interface reveals software name and version on the login page
- Admin interfaces exist on predictable subdomains without additional protection

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Admin interface accessible without authentication | High |
| Database management tool publicly accessible | High |
| Admin interface with default credentials | High |
| Admin login page publicly accessible without IP restriction | Medium |
| Infrastructure management ports open to the internet | Medium |
| Admin interface on predictable subdomain with login required | Low |
| Admin path discoverable but returns 403 with no bypass | Low |

## Remediation

- Restrict admin interfaces to trusted IP addresses or VPN-only access
- Use multi-factor authentication (MFA) for all admin accounts
- Place admin interfaces on separate, non-public domains or network segments
- Remove or disable unused management tools (phpMyAdmin, Adminer) from production
- Change default admin paths to non-predictable URLs where possible
- Implement account lockout and rate limiting on admin login pages
- Ensure admin login pages do not reveal software versions
- Monitor and alert on failed admin login attempts
- Use strong, unique passwords and disable default accounts

## References

- [OWASP Testing Guide - Enumerate Infrastructure and Application Admin Interfaces](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces)
- [CWE-419: Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
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

