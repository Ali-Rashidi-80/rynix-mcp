---
id: WSTG-INFO-07
title: Map Execution Paths Through Application
category: Information Gathering
severity_range: Informational
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application
---

# WSTG-INFO-07: Map Execution Paths Through Application

## Summary

Before testing an application for vulnerabilities, it is essential to understand its structure and map all execution paths. This includes spidering and crawling to discover all accessible pages, understanding multi-step workflows (such as registration, checkout, or password reset flows), and identifying how different user roles navigate through the application. A comprehensive map of execution paths ensures that no functionality is missed during subsequent testing phases.

## Test Objectives

- Discover all accessible pages, endpoints, and resources through crawling
- Map multi-step workflows and business processes
- Identify state-dependent paths and conditional navigation flows
- Document execution paths for different user roles and permission levels
- Understand the application's routing structure and URL patterns

## Prerequisites

- Target application is accessible through Docker pentest container
- Valid user credentials are available for at least one role (if the application requires authentication)
- Rynix http_probe session is capturing all requests and responses

## Test Steps

### Step 1: Crawl the Application from the Entry Point

**CLI Actions:**
1. Use `curl` to fetch the application root and identify the initial entry point:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Parse the response for all links, form actions, and resource references
3. Use `curl` to review all pages captured during manual browsing
4. Use `curl` with pattern `href="|action="|src="` to extract embedded links from captured responses
5. For each discovered link, use `curl` to follow it and discover further links:
   ``
   GET /discovered-path HTTP/1.1
   Host: target.com
   ``
6. Use `save to manual-review file` for key pages that serve as navigation hubs

**What to Look For:**
- All navigable pages and their relationships
- Conditional links that only appear based on authentication state or role
- Dynamic content loaded via AJAX calls (check JavaScript for fetch/XMLHttpRequest URLs)
- URL patterns indicating routing frameworks (e.g., `/users/:id`, `/api/v1/resource`)

### Step 2: Discover JavaScript-Driven Routes and API Endpoints

**CLI Actions:**
1. Use `curl` with pattern `\.js($|\?)` to find all loaded JavaScript files
2. For each JavaScript file, use `curl` to retrieve its content
3. Use `curl` with pattern `fetch\(|axios\.|\.ajax\(|XMLHttpRequest` to find AJAX calls in captured JavaScript
4. Use `curl` with pattern `path:\s*['"]\/|route\(|router\.|navigate\(` to find client-side route definitions
5. For each discovered API endpoint or route, use `curl` to verify accessibility:
   ``
   GET /api/discovered-endpoint HTTP/1.1
   Host: target.com
   ``

**What to Look For:**
- Single Page Application (SPA) route definitions in JavaScript
- API endpoint paths referenced in frontend code
- WebSocket connection URLs
- GraphQL endpoint locations
- Hidden or undocumented endpoints not linked from the UI

### Step 3: Map Multi-Step Workflows

**CLI Actions:**
1. Use `curl` to review captured traffic from manually walking through each workflow
2. For each workflow step, use `save to manual-review file` to preserve the request for replay and modification
3. Use `curl` to test skipping steps in multi-step processes:
   - Attempt to jump directly to a later step (e.g., skip from step 1 to step 3)
   - Attempt to revisit earlier steps after completing later ones
4. Use `curl` with pattern `step|wizard|stage|phase|flow` to find workflow-related parameters

**Common Workflows to Map:**
- User registration and email verification
- Login, MFA, and session establishment
- Password reset and recovery
- Shopping cart, checkout, and payment processing
- Profile creation and update
- File upload and processing
- Account deactivation or deletion
- Administrative approval workflows

**For Each Workflow, Document:**
- The sequence of requests (URLs, methods, parameters)
- State tokens or hidden fields passed between steps
- Required vs optional steps
- Error handling at each step
- Timeout or expiration behavior

### Step 4: Map Role-Based Execution Paths

**CLI Actions:**
1. For each available user role, use `curl` to authenticate and browse the application:
   ``
   POST /login HTTP/1.1
   Host: target.com
   Content-Type: application/x-www-form-urlencoded

   username=role_user&password=password
   ``
2. Use `curl` to capture navigation for each role
3. Compare the navigation structures by using `curl` with patterns specific to admin or privileged content:
   - Pattern: `admin|manage|config|settings|dashboard`
   - Pattern: `delete|approve|reject|moderate`
4. Use `curl` to test accessing role-specific paths with lower-privilege sessions

**Roles to Map:**
- Unauthenticated/anonymous user
- Standard registered user
- Privileged or premium user
- Administrative user
- API consumer (token-based access)

### Step 5: Identify Parameterized and Dynamic Paths

**CLI Actions:**
1. Use `curl` with pattern `\/\d+\/|\/[a-f0-9]{8,}\/` to find paths with numeric or hash-based identifiers
2. Use `curl` with pattern `\?.*=.*&` to find endpoints with multiple query parameters
3. For parameterized paths, use `curl` to test with different identifier values to understand access control:
   ``
   GET /users/1/profile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /users/2/profile HTTP/1.1
   Host: target.com
   ``
4. Use `base64 -d` and `python3 -c "import urllib.parse; ..."` on any encoded parameter values encountered in URLs to understand their structure

### Step 6: Build the Complete Application Map

**CLI Actions:**
1. Use `curl` to retrieve the complete set of discovered endpoints
2. Use `rynix_plugin_run('template-scan')` to check for any findings that reveal additional paths or functionality
3. Compile the final application map organized by:
   - Static content paths
   - Dynamic application endpoints
   - API endpoints
   - Authentication and session management endpoints
   - Administrative functionality
   - File upload/download paths

## Payloads

Not applicable -- this test is focused on discovery and mapping rather than payload injection.

## Detection Criteria

This test primarily produces an application map. However, log a finding when:
- Multi-step workflows can be bypassed by skipping steps
- Privileged paths are accessible to lower-privilege users
- Undocumented or hidden endpoints are discovered that lack proper access controls
- Dead links or orphaned pages are found that may indicate incomplete cleanup of old functionality
- Client-side routes expose functionality that should be server-restricted

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Workflow steps can be bypassed leading to business logic flaws | Medium |
| Undocumented endpoints accessible without authentication | Medium |
| Role-specific pages accessible by unauthorized roles | Medium |
| Hidden API endpoints discovered in JavaScript code | Low |
| Orphaned pages or dead functionality present in production | Low |
| Complete application map documented | Informational |

## Remediation

- Enforce server-side validation for all multi-step workflows; never rely on client-side step sequencing
- Implement consistent authorization checks on every endpoint regardless of discoverability
- Remove orphaned pages, dead code, and unused endpoints from production
- Avoid exposing privileged route definitions in client-side JavaScript
- Implement proper state management for workflow processes using server-side session tracking
- Regularly audit the application map against intended functionality

## References

- [OWASP Testing Guide - Map Execution Paths Through Application](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

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

