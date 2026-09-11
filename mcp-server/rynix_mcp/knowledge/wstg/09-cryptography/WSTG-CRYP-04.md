---
id: WSTG-CRYP-04
title: Testing for Weak Encryption
category: Cryptography
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption
---

# WSTG-CRYP-04: Testing for Weak Encryption

## Summary

Weak encryption encompasses the use of deprecated cryptographic algorithms, insufficient key lengths, improper key management, predictable initialization vectors, and flawed cryptographic implementations. Even when an application uses encryption, employing weak algorithms (DES, RC4, MD5 for integrity) or short key lengths (RSA-1024, 64-bit symmetric keys) provides a false sense of security and can be broken by attackers with moderate resources.

## Test Objectives

- Identify cryptographic algorithms used by the application
- Detect use of deprecated or weak algorithms
- Assess key lengths and key management practices
- Identify predictable or static initialization vectors (IVs) and nonces
- Check for improper use of cryptographic primitives (e.g., ECB mode, MD5 for passwords)

## Prerequisites

- Target application is accessible through Docker pentest container
- Application uses encryption for tokens, cookies, stored data, or API communications
- Access to application responses containing encrypted or hashed values

## Test Steps

### Step 1: Identify Encrypted and Hashed Values

**CLI Actions:**
Use `curl` to review all captured traffic for cryptographic artifacts:

- Cookies with Base64-encoded or hex-encoded values
- Tokens in headers or URL parameters
- Password hashes in API responses
- Encrypted payloads in request/response bodies

Use `base64 -d` to decode suspected Base64 values and analyze the output:
- 8-byte aligned blocks suggest DES or 3DES (64-bit block size)
- 16-byte aligned blocks suggest AES (128-bit block size)
- Short fixed-length hashes: 16 bytes = MD5, 20 bytes = SHA-1, 32 bytes = SHA-256

### Step 2: Detect ECB Mode Encryption

**CLI Actions:**
Use `curl` to submit requests with repeated data patterns:

```
POST /api/encrypt HTTP/1.1
Host: target.com
Content-Type: application/json

{"data": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

Use `base64 -d` on the encrypted response. In ECB mode, identical plaintext blocks produce identical ciphertext blocks. Look for repeating 8-byte or 16-byte patterns in the ciphertext.

### Step 3: Detect Weak Hashing Algorithms

**CLI Actions:**
Use `curl` to search for hash patterns in responses:

- Pattern: `[a-f0-9]{32}` (potential MD5 hashes - 32 hex chars)
- Pattern: `[a-f0-9]{40}` (potential SHA-1 hashes - 40 hex chars)
- Pattern: `\$1\$` (MD5 crypt)
- Pattern: `\$2[aby]\$` (bcrypt - this is strong)
- Pattern: `\$5\$` (SHA-256 crypt)
- Pattern: `\$6\$` (SHA-512 crypt)

Use `curl` to query user profile or administrative APIs that may return password hashes:

```
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer <token>
```

### Step 4: Analyze Token Predictability

**CLI Actions:**
Use `curl` to generate multiple tokens in rapid succession:

```
POST /api/auth/token HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "testuser", "password": "testpassword"}
```

Send this request 10-20 times using `save to manual-review file`. Use `base64 -d` on each token and compare:

- Do tokens share common prefixes or suffixes? (static IV or key)
- Are tokens sequential or predictable?
- Do tokens generated at the same time have similar patterns? (weak PRNG)

### Step 5: Check for Weak TLS Cipher Suites

**CLI Actions:**
Use `curl` to connect to the target and note the negotiated cipher suite:

```
GET / HTTP/1.1
Host: target.com
```

Look for weak cipher indicators in response headers or via TLS connection details from http_probe:
- `RC4` - broken stream cipher
- `DES` / `3DES` - deprecated block ciphers
- `NULL` - no encryption
- `EXPORT` - intentionally weakened
- `MD5` - weak MAC algorithm
- Key exchange without forward secrecy (RSA key exchange instead of ECDHE/DHE)

### Step 6: Test for Insecure Cryptographic Storage Indicators

**CLI Actions:**
Use `curl` to find evidence of weak crypto in application responses:

- Pattern: `DES|3DES|RC4|RC2|Blowfish` (algorithm names in errors or configs)
- Pattern: `MD5|SHA-1|SHA1` (weak hash algorithm references)
- Pattern: `ECB` (ECB mode reference)
- Pattern: `PKCS1v1.5` (vulnerable padding scheme)

Use `rynix_plugin_run('template-scan')` to check if the template-scan plugin has identified weak cryptography issues.

### Step 7: Test for Hardcoded or Exposed Keys

**CLI Actions:**
Use `curl` to search for exposed cryptographic keys:

- Pattern: `-----BEGIN.*PRIVATE KEY-----`
- Pattern: `-----BEGIN.*KEY-----`
- Pattern: `AKIA[0-9A-Z]{16}` (AWS access keys)
- Pattern: `['\"][a-f0-9]{64}['\"]` (potential 256-bit hex keys)

Use `curl` to check common key exposure paths:

```
GET /.env HTTP/1.1
Host: target.com
```

```
GET /config.json HTTP/1.1
Host: target.com
```

```
GET /api/config HTTP/1.1
Host: target.com
```

## Payloads

### ECB Detection Payloads
```
AAAAAAAAAAAAAAAA  (16 identical bytes for AES)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  (32+ identical bytes)
0000000000000000  (null bytes, 16 for AES)
```

### Algorithm Identification Patterns
```
# Hash lengths (hex-encoded)
MD5:     32 hex characters (128 bits)
SHA-1:   40 hex characters (160 bits)
SHA-256: 64 hex characters (256 bits)
SHA-512: 128 hex characters (512 bits)

# Block sizes (encrypted, decoded from Base64)
DES/3DES: 8-byte blocks
AES:      16-byte blocks

# Weak cipher names in configs/errors
DES, 3DES, RC4, RC2, Blowfish
MD5, SHA-1
ECB mode
PKCS1v1.5
RSA-1024
```

### Common Weak Key Patterns
```
0000000000000000  (null key)
FFFFFFFFFFFFFFFF  (all-ones key)
0123456789ABCDEF  (sequential key)
password
secret
changeme
```

## Detection Criteria

A finding should be logged when:
- Application uses DES, 3DES, RC4, RC2, or other deprecated algorithms
- Password hashes use MD5 or unsalted SHA-1
- ECB mode is used for encryption of structured data
- RSA key size is less than 2048 bits
- Static or predictable initialization vectors are used
- Cryptographic keys are hardcoded or exposed in responses
- The application uses custom or non-standard cryptographic implementations
- TLS connections negotiate weak cipher suites

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Passwords stored with unsalted MD5 or SHA-1 | High |
| Private keys or symmetric keys exposed in responses | High |
| DES or RC4 used to encrypt sensitive data | High |
| ECB mode used for encrypting structured/sensitive data | Medium |
| RSA-1024 or smaller key sizes in use | Medium |
| 3DES used (deprecated but not immediately broken) | Medium |
| Static or predictable IVs with CBC mode | Medium |
| SHA-1 used for digital signatures | Medium |
| MD5 used for non-security purposes (checksums, caching) | Low |
| TLS cipher suite preference allows weak ciphers but prefers strong ones | Low |
| Application uses HMAC-MD5 or HMAC-SHA1 (not immediately vulnerable) | Informational |

## Remediation

- Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption
- Use RSA >= 2048 bits or ECDSA >= 256 bits for asymmetric operations
- Use bcrypt, scrypt, or Argon2 for password hashing
- Use SHA-256 or SHA-3 for integrity checks and digital signatures
- Generate cryptographically random IVs/nonces for each encryption operation
- Use authenticated encryption (AEAD) to prevent ciphertext tampering
- Implement proper key management: rotate keys regularly, store securely, never hardcode
- Disable all weak cipher suites on TLS configurations
- Use well-tested cryptographic libraries rather than custom implementations
- Enable perfect forward secrecy (ECDHE/DHE key exchange)

## References

- [OWASP Testing Guide - Weak Encryption](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [NIST SP 800-131A: Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)

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

