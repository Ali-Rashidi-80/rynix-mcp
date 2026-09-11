---
id: WSTG-ATHZ-05
title: Testing for OAuth and Authorization Weaknesses
category: Authorization
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
---

# WSTG-ATHZ-05: Testing for OAuth and Authorization Weaknesses

## Summary

OAuth 2.0 is widely used for delegated authorization, but implementation flaws can lead to account takeover, token theft, and unauthorized access. Common vulnerabilities include open redirects in the OAuth flow, insufficient state parameter validation (CSRF), token leakage through referrer headers, insecure token storage, and authorization code interception. This test evaluates the security of OAuth implementations and related authorization mechanisms.

## Test Objectives

- Test for open redirect vulnerabilities in the OAuth redirect_uri parameter
- Verify CSRF protection via the state parameter in OAuth flows
- Check for token leakage through referrer headers, logs, or URL fragments
- Test for authorization code replay and interception attacks
- Evaluate token scope and permissions for over-privileged access

## Prerequisites

- Target application uses OAuth 2.0 for authentication or authorization
- At least one OAuth provider configured (e.g., Google, GitHub, Facebook, or a custom provider)
- Test accounts on both the application and the OAuth provider
- Docker pentest container capturing the full OAuth flow traffic

## Test Steps

### Step 1: Map the OAuth Flow

**CLI Actions:**
1. Initiate the OAuth login flow and use `curl` to capture all requests in the sequence
2. Identify the key OAuth endpoints:
   - Authorization endpoint (e.g., `/oauth/authorize`)
   - Token endpoint (e.g., `/oauth/token`)
   - Callback/redirect URI (e.g., `/callback`, `/oauth/callback`)
3. Use `curl` with pattern `(client_id|redirect_uri|response_type|scope|state|code|access_token|id_token)` to find all OAuth parameters
4. Document the grant type used (authorization code, implicit, etc.)

### Step 1b: Cross-Domain OAuth Flow Mapping

**Applies when:** The OAuth provider is on a different domain from the application.

**CLI Actions:**
1. Create the cookie jar for tracking cookies across domains:
   ```
   rynix_plugin_run('wstg') touch ./engagements/<eid>/cookies.txt
   ```
2. Follow the complete redirect chain with verbose output to map every hop:
   ```
   http_probe -sk -v -L \
     -b ./engagements/<eid>/cookies.txt \
     -c ./engagements/<eid>/cookies.txt \
     https://app.example.com/login 2>&1 | grep -E '(> GET|> POST|< HTTP|< Location|< Set-Cookie)'
   ```
3. Document each redirect hop:
   - Which domain sets which cookies
   - Where the authorization code is issued
   - Where the token exchange happens
   - Whether tokens appear in URL parameters (leakable via Referer)
4. Register both domains with `register_scope()` — tag the app domain as `app` and the auth provider as `auth_provider`
5. Check the OIDC well-known configuration for the auth provider:
   ```
   http_probe -sk https://auth.example.com/.well-known/openid-configuration | jq .
   ```
6. Note all `grant_types_supported` — each one is an attack surface. Test alternative grants (password, client_credentials, device_code) against the token endpoint.

### Step 2: Test Open Redirect in redirect_uri

**CLI Actions:**
1. Capture the authorization request and note the `redirect_uri` parameter
2. Use `save to manual-review file` with the authorization request
3. Use `curl` to test modified redirect_uri values:
   ``
   GET /oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://evil.com/callback&response_type=code&scope=openid&state=xyz HTTP/1.1
   Host: oauth-provider.com
   ``
4. Test redirect_uri bypass techniques with `curl --data-urlencode` for encoding:
   ``
   redirect_uri=https://legitimate.com.evil.com/callback
   redirect_uri=https://legitimate.com@evil.com/callback
   redirect_uri=https://legitimate.com%40evil.com/callback
   redirect_uri=https://evil.com/legitimate.com/callback
   redirect_uri=https://legitimate.com/callback/../../../evil-path
   redirect_uri=https://legitimate.com/callback?next=https://evil.com
   redirect_uri=https://legitimate.com/callback#@evil.com
   ``
5. Check if the authorization server redirects to the attacker-controlled URI with the authorization code or token

### Step 3: Test CSRF via Missing or Weak State Parameter

**CLI Actions:**
1. Capture the OAuth authorization request and note the `state` parameter
2. Use `curl` to test the callback without a state parameter:
   ``
   GET /oauth/callback?code=AUTH_CODE HTTP/1.1
   Host: target.com
   Cookie: session=<user_session>
   ``
3. Test with an empty state: `state=`
4. Test with an arbitrary state value: `state=attacker_controlled_value`
5. If the application accepts the callback without proper state validation, it is vulnerable to OAuth CSRF (an attacker can force-link their OAuth account to a victim's session)

### Step 4: Test Token Leakage

**CLI Actions:**
1. Use `curl` with pattern `(access_token|id_token|code)=` to find tokens in URLs
2. Check if the implicit flow is used (tokens in URL fragments):
   ``
   https://target.com/callback#access_token=TOKEN&token_type=bearer
   ``
3. After receiving a token in a URL, navigate to an external page and use `curl` to check if the `Referer` header leaks the token
4. Use `curl` with pattern `[Rr]eferer:.*access_token` to detect referrer-based token leakage
5. Check if authorization codes appear in browser history or server logs by examining URL parameters

### Step 5: Test Authorization Code Replay

**CLI Actions:**
1. Complete an OAuth flow and capture the authorization code from the callback
2. Exchange the code for a token via the token endpoint
3. Use `curl` to attempt exchanging the same code again:
   ``
   POST /oauth/token HTTP/1.1
   Host: oauth-provider.com
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=ALREADY_USED_CODE&redirect_uri=https://target.com/callback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
   ``
4. If the code is accepted a second time, the authorization server does not properly invalidate used codes

### Step 6: Test Scope Manipulation

**CLI Actions:**
1. Capture the initial authorization request with its scope parameter
2. Use `curl` to request elevated scopes:
   ``
   GET /oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://target.com/callback&response_type=code&scope=openid+profile+email+admin&state=xyz HTTP/1.1
   Host: oauth-provider.com
   ``
3. Test adding scopes: `admin`, `write`, `delete`, `user:admin`, `*`
4. After obtaining a token, check if the token has the elevated scope by calling protected API endpoints

### Step 7: Test Token Theft via Subdomain Takeover or Open Redirect Chain

**CLI Actions:**
1. If the `redirect_uri` validation allows subdomains (e.g., `*.target.com`), check if any subdomain is vulnerable to takeover
2. Use `curl` to test redirect_uri with various subdomains:
   ``
   redirect_uri=https://abandoned-app.target.com/callback
   redirect_uri=https://dev.target.com/callback
   redirect_uri=https://staging.target.com/callback
   ``
3. Test redirect_uri path traversal to an open redirect on the legitimate domain:
   ``
   redirect_uri=https://target.com/redirect?url=https://evil.com
   ``
4. Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any open redirect issues on the target domain

### Step 8: Test Cross-Domain Token Leakage

**Applies when:** The OAuth provider is on a different domain from the application.

**CLI Actions:**
1. After completing the OAuth flow, inspect the cookie jar for tokens set on the wrong domain:
   ```
   rynix_plugin_run('wstg') cat ./engagements/<eid>/cookies.txt
   ```
2. Check if the application domain receives cookies originally set by the auth provider (cookie scope misconfiguration — e.g., cookies scoped to `.example.com` when they should be scoped to `auth.example.com`)
3. Check if tokens are passed in URL parameters during cross-domain redirects (leakable via Referer header):
   ```
   http_probe -sk -D- -o /dev/null \
     -b ./engagements/<eid>/cookies.txt \
     -c ./engagements/<eid>/cookies.txt \
     https://app.example.com/callback?code=AUTH_CODE
   ```
   Look for `Referer` headers in subsequent requests that contain the auth code.
4. Test if the callback endpoint validates the `state` parameter when the request originates from a different domain than expected
5. Check if the app's session token is valid on the auth provider domain (and vice versa) — session confusion vulnerability:
   ```
   http_probe -sk \
     -b ./engagements/<eid>/cookies.txt \
     https://auth.example.com/admin/
   ```
6. Test JWT audience (`aud`) claim: if the token's `aud` is for `app.example.com`, can it be used against `api.example.com` or another service?

## Payloads

### redirect_uri Bypass Payloads
```
https://evil.com
https://target.com.evil.com
https://target.com@evil.com
https://evil.com/target.com
https://target.com/callback?redirect=https://evil.com
https://target.com/callback/../../../evil
https://target.com%40evil.com
https://target.com%2F%2Fevil.com
http://target.com/callback
https://TARGET.COM/callback
https://target.com/callback/..%2f..%2f
```

### State Parameter Test Values
```
(empty)
(omit entirely)
attacker_value
predictable_value_123
aaaaaaaaaaaaaaaaaaaaaa
```

### Scope Escalation Values
```
openid profile email admin
read write delete
user:admin
*
all
admin:full
```

## Detection Criteria

A finding should be logged when:
- The redirect_uri accepts an attacker-controlled domain, leaking the authorization code or token
- The OAuth flow works without a state parameter or accepts arbitrary state values (CSRF)
- Access tokens or authorization codes appear in URL parameters and leak via Referer headers
- Authorization codes can be replayed after initial use
- The application accepts tokens with escalated scopes beyond what was originally authorized
- The implicit flow is used, exposing tokens in URL fragments
- Cross-domain: auth provider cookies are accessible from the application domain (cookie scope misconfiguration)
- Cross-domain: tokens appear in URL parameters during redirect chain and leak via Referer headers
- Cross-domain: a JWT token issued for one audience is accepted by a different service
- Cross-domain: session confusion allows an app session to be used on the auth provider (or vice versa)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Open redirect in redirect_uri leaks authorization code to attacker domain | Critical |
| Missing state parameter allows OAuth CSRF (account linking attack) | High |
| Token leakage via Referer header to third-party sites | High |
| Authorization code replay is possible | Medium |
| Implicit flow used instead of authorization code flow | Medium |
| Scope escalation grants admin-level access | Critical |
| Scope escalation grants read access to additional non-sensitive data | Low |
| State parameter is present but predictable | Medium |
| Cross-domain cookie scope misconfiguration leaks auth tokens to app domain | High |
| Cross-domain token leakage via Referer during redirect chain | High |
| JWT accepted with wrong audience claim (cross-service token confusion) | High |
| Cross-domain session confusion (app session valid on auth provider) | Medium |

## Remediation

- Strictly validate redirect_uri using exact string matching (no wildcards or partial matching)
- Always use and validate the state parameter with a cryptographically random value tied to the user session
- Use the authorization code flow with PKCE instead of the implicit flow
- Invalidate authorization codes after first use
- Set short expiration times for authorization codes (e.g., 10 minutes)
- Do not include tokens in URL parameters; use the fragment or POST response body
- Validate token scopes on the resource server for every request
- Implement token binding to prevent stolen tokens from being used on different clients
- Use referrer-policy headers (`Referrer-Policy: no-referrer`) to prevent token leakage

## References

- [OWASP Testing Guide - OAuth Weaknesses](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://tools.ietf.org/html/rfc7636)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
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

- V4 Access Control — horizontal and vertical privilege checks.
- V13 API — object-level authorization on every endpoint.

## CWE references

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control

## Rynix tooling

- Primary tools: ``run_idor_matrix``, ``compare_role_response``, ``rbac_matrix``, ``check_access``

## Test focus

- Mandatory cross-role comparison on every object ID parameter.
- Document 403 vs 404 behavior — both can indicate IDOR signals.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

