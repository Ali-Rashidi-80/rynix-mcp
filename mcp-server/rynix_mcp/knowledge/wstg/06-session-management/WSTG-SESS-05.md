---
id: WSTG-SESS-05
title: Testing for Cross Site Request Forgery
category: Session Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
---

# WSTG-SESS-05: Testing for Cross Site Request Forgery

## Summary

Cross-Site Request Forgery (CSRF) attacks force an authenticated user to execute unwanted actions on a web application by tricking them into visiting a malicious page. The attack exploits the browser's automatic inclusion of cookies with every request to the target domain. This test evaluates whether the application protects state-changing operations with CSRF tokens and verifies the strength and validation of those tokens.

## Test Objectives

- Identify state-changing operations that lack CSRF protection
- Analyze CSRF token generation for randomness and unpredictability
- Test if CSRF tokens are properly validated on the server side
- Verify that SameSite cookie attributes provide adequate CSRF mitigation

## Prerequisites

- An authenticated test account
- Docker pentest container capturing application traffic
- Knowledge of state-changing endpoints (forms, API calls)

## Test Steps

### Step 1: Identify State-Changing Operations

**CLI Actions:**
1. Use `curl` to capture all application traffic during normal usage
2. Use `curl` with pattern `^(POST|PUT|PATCH|DELETE) ` to identify all state-changing requests
3. Catalog all operations that modify data or state:
   - Profile updates
   - Password changes
   - Email address changes
   - Financial transactions
   - Account deletion
   - Settings modifications
   - Administrative actions

### Step 2: Check for CSRF Token Presence

**CLI Actions:**
1. For each state-changing request, use `curl` with pattern `(csrf|_token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|_csrf_token|XSRF-TOKEN|X-CSRF-Token)` to check for CSRF tokens
2. Examine both:
   - Form fields (hidden inputs with CSRF tokens)
   - Request headers (custom headers like `X-CSRF-Token`)
3. If no CSRF token is found on a state-changing endpoint, it may be vulnerable

### Step 3: Test CSRF Token Removal

**CLI Actions:**
1. Capture a state-changing request that includes a CSRF token
2. Use `save to manual-review file` with this request
3. Use `curl` to send the request with the CSRF token completely removed:
   ``
   POST /api/profile/update HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   name=Test+User&email=test@example.com
   ``
   (Note: the csrf_token parameter has been removed)
4. If the request succeeds, CSRF protection is not enforced

### Step 4: Test CSRF Token Validation Strength

**CLI Actions:**
1. Capture a valid CSRF token from a request
2. Use `curl` to test with various invalid token values:
   ``
   POST /api/profile/update HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   name=Test+User&email=test@example.com&csrf_token=INVALID_TOKEN
   ``
3. Test with:
   - An empty token: `csrf_token=`
   - A truncated token: first half of the valid token only
   - A different user's CSRF token (swap tokens between two accounts)
   - A previously used token (from a prior request)
   - A static or predictable value: `csrf_token=1`, `csrf_token=test`

### Step 5: Test CSRF Token Reuse

**CLI Actions:**
1. Capture a valid CSRF token from a form page
2. Use `curl` to submit the form with the token
3. Use the same token again in a second `curl` call to the same endpoint
4. If the token works multiple times, tokens are not being invalidated after use (though this alone is not always a vulnerability if the token is session-bound)

### Step 6: Test CSRF on API Endpoints with JSON Content-Type

**CLI Actions:**
1. Identify JSON API endpoints that perform state-changing actions
2. Use `curl` to test if the endpoint accepts requests without a custom header:
   ``
   POST /api/transfer HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: application/x-www-form-urlencoded

   {"to":"attacker_account","amount":"1000"}
   ``
3. Test if the endpoint accepts `Content-Type: text/plain` (which can be sent cross-origin without preflight):
   ``
   POST /api/transfer HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   Content-Type: text/plain

   {"to":"attacker_account","amount":"1000"}
   ``
4. Check if the server validates the `Origin` or `Referer` header

### Step 7: Check SameSite Cookie Protection

**CLI Actions:**
1. Use `curl` to examine all `Set-Cookie` headers for the session cookie
2. Check the `SameSite` attribute:
   - `SameSite=Strict`: strongest protection
   - `SameSite=Lax`: protects POST but allows GET cross-site
   - `SameSite=None`: no CSRF protection from this attribute
   - Missing: browser defaults vary (most default to `Lax`)
3. If `SameSite=Lax`, check if any state-changing operations use GET requests (which would still be vulnerable):
   ``
   GET /api/delete-account?confirm=true HTTP/1.1
   ``
4. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified any CSRF vulnerabilities

## Payloads

### CSRF HTML Proof of Concept (Form-based)
```html
<html>
<body>
<form action="https://target.com/api/profile/update" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="name" value="Hacked" />
  <input type="submit" value="Click Me" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

### CSRF HTML Proof of Concept (JSON via form)
```html
<html>
<body>
<form action="https://target.com/api/transfer" method="POST" enctype="text/plain">
  <input type="hidden" name='{"to":"attacker","amount":"1000","ignore":"' value='"}' />
  <input type="submit" value="Click Me" />
</form>
</body>
</html>
```

### CSRF Token Bypass Values
```
(remove token entirely)
(empty string)
0
null
undefined
AAAAAAAAAAAAAAAA
<token from a different user session>
<previously used token>
```

## Detection Criteria

A finding should be logged when:
- A state-changing operation succeeds without any CSRF token
- A state-changing operation succeeds with an invalid, empty, or removed CSRF token
- A CSRF token from one user's session is accepted for another user
- JSON API endpoints accept cross-origin requests without custom header validation
- The session cookie lacks `SameSite` attribute and no CSRF token protection exists
- State-changing operations use GET method (vulnerable even with `SameSite=Lax`)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CSRF on password change or email change endpoint | High |
| CSRF on financial transaction endpoint | High |
| CSRF on admin action (create user, change roles) | High |
| CSRF on profile update (non-critical fields) | Medium |
| CSRF on settings change (preferences, notifications) | Medium |
| CSRF token present but not validated (always accepted) | High |
| Missing SameSite attribute but CSRF tokens present and validated | Low |
| State-changing GET request (even with SameSite=Lax) | Medium |

## Remediation

- Implement synchronizer token pattern (unique CSRF token per session or per request)
- Validate CSRF tokens server-side for every state-changing request
- Use the `SameSite=Lax` or `SameSite=Strict` attribute on session cookies
- Do not use GET requests for state-changing operations
- For API endpoints, require custom request headers (e.g., `X-Requested-With`) that cannot be set cross-origin
- Validate the `Origin` and `Referer` headers as a defense-in-depth measure
- Consider using the double-submit cookie pattern as an alternative CSRF defense
- Regenerate CSRF tokens periodically and invalidate old ones

## References

- [OWASP Testing Guide - CSRF](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

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

- V3 Session Management — fixation, timeout, secure cookie flags.
- V2 Authentication — session binding to client fingerprint where applicable.

## CWE references

- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``auth_login``

## Test focus

- Test cookie flags, rotation on login, and concurrent session limits.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

