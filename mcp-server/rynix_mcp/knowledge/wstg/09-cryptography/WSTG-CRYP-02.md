---
id: WSTG-CRYP-02
title: Testing for Padding Oracle
category: Cryptography
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle
---

# WSTG-CRYP-02: Testing for Padding Oracle

## Summary

A padding oracle vulnerability exists when an application leaks information about whether the padding of an encrypted message is valid. In CBC (Cipher Block Chaining) mode encryption, each plaintext block must be padded to the block size before encryption. If an attacker can determine whether decrypted ciphertext has valid padding (through distinct error messages, response timing, or HTTP status codes), they can iteratively decrypt ciphertext without knowing the key, or forge valid ciphertext for arbitrary plaintext.

## Test Objectives

- Identify encrypted values in cookies, URL parameters, hidden fields, or API tokens
- Determine if the application reveals padding validity through error responses
- Test whether ciphertext can be manipulated to cause different application behaviors
- Assess exploitability for decryption or ciphertext forgery

## Prerequisites

- Target application uses encrypted tokens, cookies, or parameters (typically Base64-encoded or hex-encoded blocks)
- Docker pentest container capturing traffic
- Understanding of CBC mode and PKCS#5/PKCS#7 padding

## Test Steps

### Step 1: Identify Encrypted Values

**CLI Actions:**
Use `curl` to browse all captured requests and responses. Look for values that appear to be encrypted:

- Cookie values that are Base64-encoded and whose decoded length is a multiple of 8 or 16 bytes (common block sizes)
- URL parameters with long hex or Base64 strings
- Hidden form fields with opaque encrypted data

Use `base64 -d` to decode suspected Base64 values and check if the decoded length is a multiple of 8 or 16.

### Step 2: Establish Baseline Responses

**CLI Actions:**
Use `save to manual-review file` with a valid request containing the encrypted value. Send the unmodified request and document:

- HTTP status code
- Response body content and length
- Any error messages
- Response time

This establishes the baseline for a valid, properly padded ciphertext.

### Step 3: Test with Modified Ciphertext

**CLI Actions:**
Use `base64 -d` to decode the encrypted value. Modify the last byte of the second-to-last block (this alters the padding of the last block after decryption). Use `base64` to re-encode the modified value.

Use `curl` to send the request with the modified encrypted value:

```
GET /account HTTP/1.1
Host: target.com
Cookie: session=MODIFIED_BASE64_VALUE
```

Observe the response. Then modify the last byte to every possible value (0x00-0xFF) and look for response differences.

### Step 4: Detect the Oracle

**CLI Actions:**
Use `fuzz-cli` to automate testing all 256 possible byte values for the last byte of the penultimate block:

1. Set the payload position on the byte being modified
2. Use a list of all 256 hex values as payloads
3. Monitor for three distinct response categories:
   - **Valid padding + valid data** (normal application response)
   - **Valid padding + invalid data** (application error, different from padding error)
   - **Invalid padding** (crypto/padding error)

The oracle exists if responses for invalid padding differ from responses for valid padding with invalid data. Differences may appear in:
- HTTP status codes (e.g., 200 vs. 500 vs. 403)
- Response body content or length
- Specific error messages ("padding error", "MAC validation failed", "decryption error")
- Response timing (padding check may fail faster)

### Step 5: Verify with Known Padding Patterns

**CLI Actions:**
Use `base64 -d` to decode the token. Craft specific modifications:

1. Modify the last byte to produce `0x01` padding (valid single-byte pad) - XOR the current last byte with `(current_padding_byte XOR 0x01)`
2. Modify the last two bytes to produce `0x02 0x02` padding
3. Send each with `curl` and compare responses

If these produce consistently different responses from random modifications, the padding oracle is confirmed.

### Step 6: Assess Impact

**CLI Actions:**
If the oracle is confirmed:

1. Use `curl` to test if decrypted plaintext controls application behavior (e.g., user identity, permissions)
2. Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has flagged related issues
3. Document the encrypted parameter, the oracle behavior, and the potential for full decryption or ciphertext forgery

## Payloads

### Ciphertext Manipulation Patterns
```
# Flip last byte of penultimate block
Original:  AABBCCDD EEFFAABB
Modified:  AABBCCDE EEFFAABB  (last byte of first block changed)

# All-zeros replacement of one block
Original:  AABBCCDD EEFFAABB
Modified:  00000000 EEFFAABB

# Duplicate blocks
Original:  BLOCK1 BLOCK2 BLOCK3
Modified:  BLOCK1 BLOCK2 BLOCK2

# Truncate last block
Original:  BLOCK1 BLOCK2 BLOCK3
Modified:  BLOCK1 BLOCK2
```

### Error Message Indicators
```
PaddingException
BadPaddingException
InvalidPaddingException
MAC validation failed
Padding is invalid and cannot be removed
Decryption failed
Cryptographic exception
javax.crypto.BadPaddingException
System.Security.Cryptography.CryptographicException
OpenSSL::Cipher::CipherError
```

### Common Encrypted Parameter Names
```
viewstate
__VIEWSTATE
session
token
auth
ticket
data
enc
encrypted
cipher
payload
state
```

## Detection Criteria

A finding should be logged when:
- The application returns distinguishable responses for valid vs. invalid padding
- Error messages explicitly mention padding, decryption, or MAC validation
- Response status codes differ based on padding validity (e.g., 500 for bad padding, 403 for invalid data)
- Response timing differs measurably between valid and invalid padding
- Encrypted tokens use CBC mode without authenticated encryption (no HMAC/AEAD)

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Padding oracle allows full decryption of session tokens or auth cookies | High |
| Padding oracle allows ciphertext forgery to impersonate other users | High |
| Padding oracle confirmed but encrypted data has limited sensitivity | Medium |
| Oracle exists but exploitation requires many requests and may be rate-limited | Medium |
| Encrypted values use CBC mode without authentication but no clear oracle response | Low |
| Application uses authenticated encryption (AES-GCM, AES-CCM) | Not a finding |

## Remediation

- Use authenticated encryption modes (AES-GCM, AES-CCM, ChaCha20-Poly1305) instead of CBC
- If CBC must be used, apply HMAC-then-Encrypt or Encrypt-then-MAC and validate the MAC before decryption
- Return identical, generic error responses for all decryption failures regardless of cause
- Implement rate limiting on endpoints that process encrypted values
- Ensure constant-time comparison for MAC validation
- Consider migrating to modern token formats (JWTs with proper signing, Fernet tokens)
- Do not expose raw cryptographic errors to end users

## References

- [OWASP Testing Guide - Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [Vaudenay, S. - Security Flaws Induced by CBC Padding](https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf)

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

