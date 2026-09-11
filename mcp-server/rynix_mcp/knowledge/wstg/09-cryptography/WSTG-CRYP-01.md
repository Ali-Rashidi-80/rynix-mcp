---
id: WSTG-CRYP-01
title: Testing for Weak Transport Layer Security
category: Cryptography
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security
---

# WSTG-CRYP-01: Testing for Weak Transport Layer Security

## Summary

Transport Layer Security (TLS) protects data in transit between clients and servers. Weak TLS configurations (outdated protocols, weak cipher suites, invalid certificates) can allow interception, decryption, or manipulation of sensitive data.

## Test Objectives

- Verify TLS/SSL protocol versions supported
- Identify weak cipher suites
- Check certificate validity and configuration
- Assess overall TLS security posture

## Prerequisites

- Target is accessible over HTTPS
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Check TLS Protocol Support

**CLI Actions:**
1. Use `curl` to connect to the target over HTTPS and observe the TLS handshake details via http_probe
2. Note which TLS versions are negotiated

**What to Check:**
- SSLv2 - Must NOT be supported (critically insecure)
- SSLv3 - Must NOT be supported (POODLE vulnerability)
- TLS 1.0 - Should NOT be supported (deprecated)
- TLS 1.1 - Should NOT be supported (deprecated)
- TLS 1.2 - Acceptable with strong cipher suites
- TLS 1.3 - Best, should be supported

### Step 2: Analyze Response Headers

**CLI Actions:**
1. Use `curl` to request the target over HTTPS:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check for security headers:
   - `Strict-Transport-Security` (HSTS)
   - `Public-Key-Pins` (HPKP) - deprecated but check if present
   - `Expect-CT` - Certificate Transparency

### Step 3: Check Certificate Details

**CLI Actions:**
1. Use `curl` to connect to the target
2. http_probe will capture certificate details

**What to Check:**
- Certificate is not expired
- Certificate is issued by a trusted CA
- Subject/SAN matches the domain name
- Key size is adequate (RSA >= 2048 bits, ECDSA >= 256 bits)
- Signature algorithm is not SHA-1

### Step 4: Test for Mixed Content

**CLI Actions:**
1. Use `curl` to check for HTTP (non-HTTPS) requests being made from HTTPS pages
2. Look for resources loaded over HTTP (scripts, stylesheets, images, iframes)
3. Active mixed content (scripts, iframes) is especially dangerous

### Step 5: Check HTTP to HTTPS Redirect

**CLI Actions:**
1. Use `curl` to request the target over HTTP:
   ``
   GET / HTTP/1.0
   Host: target.com
   ``
2. Check if a redirect to HTTPS occurs
3. Check if HSTS is set with adequate max-age (at least 6 months / 15768000)

### Step 6: Test HSTS Configuration

**CLI Actions:**
If HSTS header is present, verify:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age` should be at least 15768000 (6 months), ideally 31536000 (1 year)
- `includeSubDomains` should be present
- `preload` is recommended for maximum protection

## Payloads

Not applicable - this is a configuration analysis test.

## Detection Criteria

A finding should be logged when:
- SSLv3, TLS 1.0, or TLS 1.1 are supported
- Weak cipher suites are offered (RC4, DES, 3DES, NULL, EXPORT)
- Certificate is self-signed, expired, or has wrong hostname
- HSTS header is missing
- Mixed content is present (HTTP resources on HTTPS pages)
- No HTTP to HTTPS redirect
- Certificate key size < 2048 bits (RSA) or uses SHA-1 signatures

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| SSLv2 or SSLv3 supported | High |
| TLS 1.0 or TLS 1.1 supported | Medium |
| Weak cipher suites (NULL, EXPORT, RC4, DES) | Medium |
| Missing HSTS header | Medium |
| Expired or invalid certificate | Medium |
| Active mixed content (scripts over HTTP) | Medium |
| Self-signed certificate (non-internal) | Medium |
| HSTS with short max-age (<6 months) | Low |
| Passive mixed content (images over HTTP) | Low |
| SHA-1 certificate signatures | Low |
| TLS 1.3 not supported (but TLS 1.2 available) | Informational |

## Remediation

- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
- Enable TLS 1.2 and TLS 1.3 only
- Use strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- Implement HSTS with max-age >= 31536000 and includeSubDomains
- Ensure valid certificates from trusted CAs
- Fix all mixed content issues
- Redirect all HTTP traffic to HTTPS with 301
- Use certificates with RSA >= 2048 bits or ECDSA >= 256 bits
- Consider HSTS preloading

## References

- [OWASP Testing Guide - Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

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

- V6 Stored Cryptography — algorithms, keys, and randomness.
- V9 Communications — TLS configuration and HSTS.

## CWE references

- CWE-326: Inadequate Encryption Strength
- CWE-327: Broken Crypto Algorithm

## Rynix tooling

- Primary tools: ``http_probe``, ``record_finding``

## Test focus

- Verify TLS versions, cipher suites, and sensitive data not in cleartext.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

