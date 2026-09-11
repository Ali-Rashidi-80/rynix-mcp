---
id: WSTG-INFO-05
title: Review Webpage Content for Information Leakage
category: Information Gathering
severity_range: Informational - High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage
---

# WSTG-INFO-05: Review Webpage Content for Information Leakage

## Summary

Webpage source code, HTML comments, metadata, JavaScript files, and error messages can inadvertently disclose sensitive information. Developers may leave debugging comments, hardcoded credentials, internal API endpoints, version numbers, or configuration details in client-facing code. This information assists attackers in understanding the application architecture and identifying further attack vectors.

## Test Objectives

- Identify sensitive information disclosed in HTML comments
- Discover metadata and hidden fields that reveal internal details
- Detect hardcoded credentials, API keys, or tokens in client-side code
- Find source code disclosures, stack traces, or debugging information
- Identify internal paths, IP addresses, or infrastructure details exposed in responses

## Prerequisites

- Target application has been browsed through Docker pentest container to build proxy history
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Review HTML Comments

**CLI Actions:**
1. Use `curl` to fetch key pages of the application:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Use `curl` with pattern `<!--` to find all responses containing HTML comments
3. Use `curl` with pattern `TODO|FIXME|HACK|BUG|XXX` to find developer annotations
4. Use `save to manual-review file` for pages with interesting comments for further analysis

**What to Look For:**
- Comments revealing application logic or business rules
- Commented-out code blocks containing credentials or API keys
- Internal URLs, IP addresses, or server names
- Developer names, email addresses, or notes about known issues
- Version numbers or build identifiers
- SQL queries or database schema hints
- References to internal documentation or ticketing systems (e.g., Jira IDs)

### Step 2: Examine HTML Metadata and Hidden Fields

**CLI Actions:**
1. Use `curl` with pattern `<meta\s` to find pages with metadata tags
2. Use `curl` with pattern `type="hidden"` to find hidden form fields
3. Use `curl` with pattern `name="generator"` to find CMS identification tags
4. For pages with hidden fields, use `curl` to submit forms with modified hidden values

**What to Look For:**
- `<meta name="generator">` revealing CMS type and version
- `<meta name="author">` with developer or company details
- `<meta name="description">` or `<meta name="keywords">` with internal terminology
- Hidden form fields containing user IDs, role indicators, pricing values, or debug flags
- Hidden fields with sequential or predictable identifiers
- CSRF tokens in hidden fields (note pattern but not a vulnerability itself)

### Step 3: Analyze JavaScript Files for Sensitive Data

**CLI Actions:**
1. Use `curl` with pattern `\.js($|\?)` to find all loaded JavaScript files
2. For each JavaScript file, use `curl` to retrieve and review its contents
3. Use `curl` with pattern `api[Kk]ey|apiSecret|password|token|secret` to find potential credential leaks
4. Use `curl` with pattern `https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}` in JavaScript responses to find hardcoded URLs

**What to Look For:**
- Hardcoded API keys, tokens, or credentials:
  ``
  var apiKey = "AIzaSy..."
  const AWS_SECRET = "..."
  authorization: "Bearer ey..."
  ``
- Internal API endpoint URLs or microservice addresses
- Debugging or development flags (e.g., `debug: true`, `environment: "staging"`)
- Source map references (`//# sourceMappingURL=`) exposing original source code
- Admin or privileged function endpoints referenced in client-side routing
- Business logic that should be server-side only

### Step 4: Check for Source Map Files

**CLI Actions:**
1. Use `curl` with pattern `sourceMappingURL` to find source map references
2. For each source map reference found, use `curl` to fetch the `.map` file:
   ``
   GET /assets/app.js.map HTTP/1.1
   Host: target.com
   ``
3. If the source map is accessible, it reveals the original unminified source code -- use `save to manual-review file` for thorough review

**What to Look For:**
- Complete original source code including comments and variable names
- Internal module and file structure
- Development dependencies and configurations
- Credentials or tokens that were minified but are readable in source maps

### Step 5: Detect Error Messages and Stack Traces

**CLI Actions:**
1. Use `curl` to trigger error conditions:
   ``
   GET /nonexistent-path-xyz HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to submit invalid data to forms and API endpoints to trigger validation errors
3. Use `curl` with pattern `Exception|Traceback|Stack\s?[Tt]race|error.*at\s` to find error disclosures
4. Use `curl` with pattern `\/home\/|\/var\/|C:\\|\/usr\/` to find file path disclosures
5. Use `curl` with pattern `mysql|postgresql|oracle|mongodb|redis` to find database references

**What to Look For:**
- Full stack traces revealing framework, language, and library versions
- File system paths disclosing server directory structure
- Database connection strings or query errors
- Internal IP addresses or hostnames in error messages
- Debug mode indicators (e.g., Django debug page, Laravel debug mode, Spring Boot error page)

### Step 6: Review HTTP Response Headers for Information Leakage

**CLI Actions:**
1. Use `curl` to review response headers across all captured traffic
2. Use `curl` with pattern `X-Debug|X-Runtime|X-Request-Id` to find debugging headers
3. Use `curl` and examine headers for information disclosure

**Headers to Look For:**
- `X-Powered-By` -- Backend technology
- `X-AspNet-Version` -- .NET framework version
- `X-Debug-Token` -- Symfony debug token
- `X-Runtime` -- Ruby on Rails request processing time
- `X-Request-Id` -- Request tracing identifiers
- `X-Amzn-RequestId` -- AWS infrastructure indicators
- `X-Cloud-Trace-Context` -- GCP infrastructure indicators
- Custom headers revealing internal architecture

## Payloads

Not applicable -- this test involves reviewing existing content rather than injecting payloads. Some error-triggering requests may use malformed input, but these are standard probes, not attack payloads.

## Detection Criteria

A finding should be logged when:
- HTML comments contain credentials, internal URLs, or sensitive business logic
- Hidden form fields contain manipulable values affecting authorization or pricing
- JavaScript files contain hardcoded API keys, tokens, or secrets
- Source map files are publicly accessible, revealing full source code
- Error messages or stack traces disclose technology versions or file paths
- Response headers reveal detailed technology stack information
- Internal IP addresses, server names, or infrastructure details are exposed

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Hardcoded credentials, API keys, or tokens in client-side code | High |
| Accessible source maps exposing complete application source | High |
| Stack traces revealing framework versions with known critical CVEs | Medium |
| Internal API endpoints or microservice URLs disclosed | Medium |
| Hidden form fields controlling authorization or pricing logic | Medium |
| HTML comments revealing application logic or internal URLs | Low |
| Technology version disclosure via headers or meta tags | Low |
| Developer names or internal project references in comments | Informational |

## Remediation

- Implement a build process that strips HTML comments from production code
- Remove all debugging code, console logs, and development flags before deployment
- Never hardcode credentials or API keys in client-side code; use server-side environment variables
- Disable source map generation for production builds or restrict access to `.map` files
- Configure custom error pages that suppress stack traces and internal details
- Remove or obfuscate technology-revealing HTTP headers
- Audit hidden form fields to ensure they do not control server-side authorization or business logic
- Implement server-side validation for all values, including those from hidden fields
- Regularly scan client-side code for accidentally committed secrets

## References

- [OWASP Testing Guide - Review Webpage Content for Information Leakage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)
- [CWE-615: Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
- [CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

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

