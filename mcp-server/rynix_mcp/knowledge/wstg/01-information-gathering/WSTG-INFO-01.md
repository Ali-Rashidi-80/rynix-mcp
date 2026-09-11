---
id: WSTG-INFO-01
title: Conduct Search Engine Discovery and Reconnaissance
category: Information Gathering
severity_range: Informational
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage
---

# WSTG-INFO-01: Conduct Search Engine Discovery and Reconnaissance

## Summary

Search engines index publicly available content. Sensitive pages, error messages, configuration files, and internal resources may be inadvertently exposed and discoverable through search engine queries (Google Dorking).

## Test Objectives

- Identify what sensitive design and configuration information of the application, system, or organization is exposed directly or indirectly through search engines
- Discover exposed files, directories, login portals, error pages, and other sensitive resources

## Prerequisites

- Target domain is known
- Docker pentest container (`rynix-tools`) is running

## Test Steps

### Step 1: Identify the Target Domain and Subdomains

**CLI Actions:**
1. Use `curl` to send a request to the target domain and observe the response headers
2. Check `curl` for any redirects or alternate domains referenced in responses

**Manual Checks:**
- Note all domains and subdomains observed in responses (e.g., from `Location` headers, `Content-Security-Policy`, links in HTML)

### Step 2: Search Engine Dorking

Construct and test search queries to find exposed resources. Use the following dork patterns against the target domain:

**CLI Actions:**
1. For each discovered URL from dorking, use `curl` to verify accessibility
2. Use `save to manual-review file` for interesting endpoints that need further investigation

**Google Dork Queries to Test:**
```
site:target.com
site:target.com filetype:pdf
site:target.com filetype:xml
site:target.com filetype:conf
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:config
site:target.com inurl:api
site:target.com intitle:"index of"
site:target.com ext:php intitle:"phpinfo()"
site:target.com "error" OR "warning" OR "stack trace"
site:target.com "password" OR "username" OR "credentials"
```

### Step 3: Check robots.txt and sitemap.xml

**CLI Actions:**
1. Use `curl` to fetch `https://target.com/robots.txt`
2. Use `curl` to fetch `https://target.com/sitemap.xml`
3. Use `curl` to fetch `https://target.com/sitemap_index.xml`
4. For each disallowed path in robots.txt, use `curl` to check if it's accessible

**What to Look For:**
- Disallowed paths in robots.txt that reveal internal structure
- Sitemaps listing non-public or admin pages
- Sensitive file paths or backup directories

### Step 4: Check Cached Versions and Web Archives

**Manual Checks:**
- Check Google Cache for older versions of pages
- Check the Wayback Machine (web.archive.org) for historical content
- Look for removed pages that may still reveal information

## Payloads

Not applicable for this test - this is a passive reconnaissance test.

## Detection Criteria

A finding should be logged when:
- Sensitive files are accessible via URLs found through search engine queries (config files, backups, logs, SQL dumps)
- Admin interfaces or internal pages are publicly accessible
- robots.txt reveals sensitive directory structures
- Error pages or debug information are indexed by search engines
- Credentials, API keys, or tokens are exposed in cached pages

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Credentials, API keys, or tokens found in indexed pages | High |
| Admin interfaces discoverable and accessible | Medium |
| Internal directory structure revealed via robots.txt | Low |
| Generic information disclosure (software versions, paths) | Informational |

## Remediation

- Remove sensitive files from web-accessible directories
- Use proper robots.txt directives but don't rely on them for security
- Implement access controls for admin and internal pages
- Use `noindex` meta tags or `X-Robots-Tag` headers for sensitive pages
- Regularly audit search engine results for exposed content
- Request removal of sensitive cached content from search engines

## References

- [OWASP Testing Guide - Search Engine Discovery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)

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

