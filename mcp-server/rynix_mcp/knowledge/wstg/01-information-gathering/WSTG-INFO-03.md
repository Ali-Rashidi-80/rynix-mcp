---
id: WSTG-INFO-03
title: Review Webserver Metafiles for Information Leakage
category: Information Gathering
severity_range: Informational - Medium
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage
---

# WSTG-INFO-03: Review Webserver Metafiles for Information Leakage

## Summary

Web servers host several metafiles that can disclose sensitive information about the application, its structure, and its configuration. Files such as `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, and resources under the `/.well-known/` directory are often publicly accessible and may reveal internal paths, hidden functionality, technology choices, or organizational details that assist an attacker in planning further attacks.

## Test Objectives

- Identify information leakage through webserver metafiles (`robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`)
- Discover hidden or sensitive paths disclosed in metafiles
- Enumerate resources under the `/.well-known/` directory
- Determine if disallowed or unlisted paths are still accessible

## Prerequisites

- Target URL is accessible via `http_probe`
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Retrieve and Analyze robots.txt

**CLI Actions:**
1. Use `curl` to fetch the robots.txt file:
   ``
   GET /robots.txt HTTP/1.1
   Host: target.com
   ``
2. Use `save to manual-review file` with the robots.txt request for easy reference during subsequent testing
3. For each `Disallow` path found in robots.txt, use `curl` to verify if the path is accessible:
   ``
   GET /disallowed-path/ HTTP/1.1
   Host: target.com
   ``
4. Check for `Sitemap` directives within robots.txt that point to sitemap file locations

**What to Look For:**
- `Disallow` entries revealing admin panels, backup directories, internal tools, or staging paths
- `Allow` entries that expose specific files within otherwise disallowed directories
- User-Agent-specific rules that indicate different content for different crawlers
- Comments in the file that disclose developer notes or internal information

### Step 2: Retrieve and Analyze sitemap.xml

**CLI Actions:**
1. Use `curl` to fetch common sitemap locations:
   ``
   GET /sitemap.xml HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to check for sitemap index files:
   ``
   GET /sitemap_index.xml HTTP/1.1
   Host: target.com
   ``
3. Use `curl` to check alternate sitemap locations:
   ``
   GET /sitemap.xml.gz HTTP/1.1
   Host: target.com
   ``
   ``
   GET /sitemaps/sitemap.xml HTTP/1.1
   Host: target.com
   ``
4. For each URL found in the sitemap that looks sensitive or internal, use `curl` to verify accessibility
5. Use `curl` with pattern `sitemap` to find any sitemap references encountered during browsing

**What to Look For:**
- URLs referencing admin interfaces, internal tools, or staging environments
- URLs with query parameters revealing application structure
- URLs containing user IDs, document IDs, or sequential identifiers
- Last modification dates that reveal development activity timelines

### Step 3: Retrieve and Analyze security.txt

**CLI Actions:**
1. Use `curl` to fetch security.txt from the standard location:
   ``
   GET /.well-known/security.txt HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to check the legacy location:
   ``
   GET /security.txt HTTP/1.1
   Host: target.com
   ``

**What to Look For:**
- `Contact` fields revealing internal email addresses or security team names
- `Hiring` links that may disclose technology stack through job descriptions
- `Policy` links pointing to vulnerability disclosure programs
- `Encryption` links to PGP keys
- `Canonical` URLs revealing alternate domain names
- Expiry dates that indicate maintenance schedules

### Step 4: Retrieve and Analyze humans.txt

**CLI Actions:**
1. Use `curl` to fetch humans.txt:
   ``
   GET /humans.txt HTTP/1.1
   Host: target.com
   ``

**What to Look For:**
- Developer names, roles, and contact information
- Technology stack details (languages, frameworks, CMS, tools used)
- Third-party service providers and vendors
- Geographic locations of development teams

### Step 5: Enumerate .well-known Directory Resources

**CLI Actions:**
1. Use `curl` to probe common `.well-known` resources:
   ``
   GET /.well-known/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/openid-configuration HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/assetlinks.json HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/apple-app-site-association HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/change-password HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/jwks.json HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/oauth-authorization-server HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.well-known/openapi.json HTTP/1.1
   Host: target.com
   ``
2. Use `save to manual-review file` for any responses that return 200 OK for deeper investigation
3. Use `curl` with pattern `\.well-known` to find any references encountered during browsing

**What to Look For:**
- `openid-configuration` exposing OAuth/OIDC endpoints, supported scopes, and issuer details
- `assetlinks.json` revealing associated mobile applications and package names
- `apple-app-site-association` disclosing iOS app bundle identifiers and associated paths
- Directory listing enabled on `/.well-known/` exposing all registered resources
- `jwks.json` exposing public keys used for JWT validation

### Step 6: Verify Accessibility of Disclosed Paths

**CLI Actions:**
1. Compile all unique paths discovered from Steps 1-5
2. For each path, use `curl` to send a GET request and check:
   - HTTP status code (200, 301, 302, 403, 404)
   - Response body size and content
3. For paths returning 403 Forbidden, use `curl` to test bypass techniques:
   ``
   GET /admin/ HTTP/1.1
   Host: target.com
   X-Original-URL: /admin/
   ``
4. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has already identified any information disclosure issues related to these metafiles

## Payloads

Not applicable -- this test involves fetching and analyzing existing metafiles rather than injecting payloads.

## Detection Criteria

A finding should be logged when:
- `robots.txt` disallows paths that are still accessible and contain sensitive content
- Sitemaps reference admin panels, internal tools, or staging environments
- `security.txt` reveals internal organizational details or security contacts
- `humans.txt` discloses technology stack or developer information
- `.well-known` resources expose authentication infrastructure details (OIDC config, JWK sets)
- Directory listing is enabled on `/.well-known/`

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Accessible admin or internal paths disclosed in robots.txt | Medium |
| OIDC/OAuth configuration exposing sensitive endpoints or scopes | Medium |
| Sitemap revealing internal or staging URLs with live access | Low |
| Technology stack or developer details in humans.txt | Informational |
| security.txt revealing internal email addresses or team info | Informational |
| robots.txt disclosing directory structure without live access | Informational |

## Remediation

- Avoid listing sensitive paths in `robots.txt`; enforce access controls instead of relying on crawl directives
- Restrict sitemap content to only publicly intended pages
- Review `security.txt` content to ensure no excessive internal details are disclosed
- Remove `humans.txt` if it contains sensitive technical or personnel details
- Restrict directory listing on `/.well-known/` and serve only required resources
- Implement proper authentication and authorization for all sensitive paths regardless of discoverability

## References

- [OWASP Testing Guide - Review Webserver Metafiles for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [RFC 9116 - A File Format to Aid in Security Vulnerability Disclosure (security.txt)](https://www.rfc-editor.org/rfc/rfc9116)
- [IANA Well-Known URIs Registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)
- [Google Robots.txt Specification](https://developers.google.com/search/docs/advanced/robots/robots_txt)

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

