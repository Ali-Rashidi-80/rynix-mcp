# Reproducibility Mandates

## Every Finding Must Be Reproducible

A finding that cannot be independently reproduced is worthless. Every logged finding MUST include step-by-step reproduction instructions that a different tester could follow.

## Required Evidence Format

### For Each Finding (`log_finding()`)

The `evidence` field MUST contain ALL of these:

```
## Reproduction Steps

1. [Prerequisite state — authenticated as user X, on page Y]
2. [Exact HTTP request — full curl command or request details]
3. [What to observe in the response]
4. [How to confirm exploitation succeeded]

## Request
[Full HTTP request — method, URL, headers, body]

## Response
[Relevant portion of HTTP response — status, headers, body excerpt]

## Proof of Exploitation
[Screenshot description, extracted data, or observable outcome]
```

### Minimum Evidence by Vuln Class

| Class | Must Show | Insufficient Evidence |
|-------|-----------|----------------------|
| XSS | Full request + response showing JS execution or DOM change | "Payload was reflected" |
| SQLi | Full request + response showing extracted data or error | "sql-injection-cli found injection" |
| CMDi | Full request + response showing command output | "Timing difference observed" |
| SSTI | Full request + response showing template evaluation result | "{{7*7}} was sent" |
| SSRF | Full request + response showing internal resource access | "Request was sent to internal URL" |
| Path Traversal | Full request + response showing file contents | "Different error messages observed" |
| IDOR | Both requests (own ID + other ID) showing data difference | "Response was different" |
| Auth Bypass | Request without credentials + response with protected data | "Access was possible" |

## Curl Command Reproduction

Every finding should include a curl command that reproduces the vulnerability:

```bash
# Reproduction command
http_probe -sk \
  -X POST \
  -H "Cookie: session=<SESSION>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=<PAYLOAD>" \
  "https://target.com/endpoint"
```

## Anti-Patterns

- "See sql-injection-cli output" — NOT sufficient. Extract the specific finding with request/response.
- "template-scan detected CVE-XXXX" — Include the template-scan output AND a manual reproduction.
- "Dalfox confirmed XSS" — Include the specific payload and the response showing execution.
- "Tool found vulnerability" — Always verify tool findings manually and include manual reproduction steps.
