---
id: WSTG-BUSL-03
title: Test Integrity Checks
category: Business Logic
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks
---

# WSTG-BUSL-03: Test Integrity Checks

## Summary

Integrity checks ensure that data has not been tampered with during transit or storage. Applications may use checksums, HMACs, digital signatures, or hashing to validate data integrity. When these mechanisms are missing, improperly implemented, or bypassable, attackers can modify data in transit (prices, quantities, user roles) without detection, leading to fraud, unauthorized access, or data corruption.

## Test Objectives

- Identify integrity protection mechanisms used by the application
- Test if data can be modified in transit without detection
- Assess the strength and correctness of checksum and HMAC implementations
- Determine if integrity checks can be bypassed or forged

## Prerequisites

- Target application is accessible through Docker pentest container
- Application workflows involving data transmission have been mapped
- Understanding of common integrity mechanisms (HMAC, checksums, signatures)

## Test Steps

### Step 1: Identify Integrity Mechanisms

**CLI Actions:**
Use `curl` to review captured requests and responses for integrity-related patterns:

- Request parameters named `hash`, `checksum`, `signature`, `sig`, `mac`, `hmac`, `digest`, `token`
- Headers like `X-Signature`, `X-Checksum`, `X-HMAC`, `Content-MD5`
- Hidden form fields containing hash values
- JWT tokens (which include a signature component)

Use `base64 -d` to decode any suspected integrity values and determine their length:
- 16 bytes / 32 hex chars = likely MD5
- 20 bytes / 40 hex chars = likely SHA-1
- 32 bytes / 64 hex chars = likely SHA-256

### Step 2: Test Data Modification Without Updating Integrity Value

**CLI Actions:**
Use `save to manual-review file` with a request that includes an integrity value. Modify the data but leave the integrity value unchanged:

```
POST /payment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=100.00&currency=USD&recipient=user2&checksum=a1b2c3d4e5f6
```

Modify to:

```
POST /payment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=0.01&currency=USD&recipient=attacker&checksum=a1b2c3d4e5f6
```

If the server accepts the modified request without rejecting the stale checksum, the integrity check is not enforced.

### Step 3: Test Integrity Value Removal

**CLI Actions:**
Use `curl` to send requests with the integrity parameter removed entirely:

```
POST /payment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=100.00&currency=USD&recipient=user2
```

Check if the application processes the request without the integrity field.

### Step 4: Test Weak Integrity Algorithms

**CLI Actions:**
If the integrity mechanism appears to be a simple hash (no key/secret involved), attempt to forge it:

1. Identify the algorithm from the hash length (MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex)
2. Compute the hash of modified data using the same apparent algorithm
3. Use `curl` with the modified data and recomputed hash

```
POST /payment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=0.01&currency=USD&recipient=attacker&checksum=<recomputed_md5>
```

If the hash does not include a secret key (plain MD5/SHA of the data), an attacker can trivially forge it.

### Step 5: Test JWT Integrity

**CLI Actions:**
If the application uses JWTs, use `base64 -d` to decode each JWT section (header.payload.signature):

1. Decode the header to check the algorithm (`alg` field)
2. Modify the payload (change `role`, `sub`, `exp`)
3. Test the `alg: none` attack by setting algorithm to `none` and removing the signature:

Use `curl` with the modified JWT:

```
GET /api/protected HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

Test algorithm confusion: change `RS256` to `HS256` and sign with the public key.

### Step 6: Test HMAC Key Strength

**CLI Actions:**
If HMAC is used, use `fuzz-cli` to test common weak HMAC keys:

1. Set the HMAC value as the payload position
2. For each candidate key, compute HMAC of the request data and compare with the expected HMAC
3. Test keys like: `secret`, `password`, `key`, `hmac_key`, empty string

Use `rynix_plugin_run('template-scan')` to check for related findings from the template-scan plugin.

### Step 7: Test Content-MD5 Header

**CLI Actions:**
If the application uses `Content-MD5` header:

Use `curl` to send a modified body with the original `Content-MD5`:

```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json
Content-MD5: <original_md5_base64>

{"modified": "data", "amount": 0}
```

Check if the server validates the `Content-MD5` header against the actual body.

## Payloads

### Integrity Bypass Values
```
# Remove integrity parameter entirely
# Set to empty string
checksum=
hash=
signature=
mac=

# Set to common placeholder values
checksum=0
checksum=null
checksum=undefined
checksum=test
checksum=0000000000000000

# Truncated valid checksum
checksum=<first_half_of_valid_checksum>
```

### JWT Algorithm Manipulation
```
# alg: none attack
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}

# Algorithm confusion
{"alg": "HS256", "typ": "JWT"}  (when RS256 expected)

# Remove alg field
{"typ": "JWT"}
```

### Weak HMAC Keys to Test
```
secret
password
key
hmac_key
changeme
test
admin
(empty string)
application_name
123456
```

## Detection Criteria

A finding should be logged when:
- Data can be modified in transit and the application processes it without integrity check failure
- Integrity parameters can be removed and requests still succeed
- Simple (non-keyed) hashes are used for integrity, allowing forgery
- JWTs accept `alg: none` or are vulnerable to algorithm confusion
- HMAC uses a weak or guessable key
- Content-MD5 header is not validated against the request body
- Checksums are computed client-side with visible logic, allowing recomputation

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| No integrity checks on financial transactions, data modified freely | High |
| JWT accepts alg:none, allowing forged tokens | High |
| HMAC key is guessable, allowing signature forgery | High |
| Integrity parameter can be removed and request still processed | Medium |
| Non-keyed hash used for integrity (e.g., plain MD5 of data) | Medium |
| JWT algorithm confusion allows signature bypass | Medium |
| Content-MD5 header present but not validated | Low |
| Integrity checks exist but use MD5 (collision risk, not immediately exploitable) | Low |
| Strong HMAC-SHA256 with secret key properly validated | Not a finding |

## Remediation

- Use HMAC (keyed hash) rather than plain hash for integrity verification
- Use strong HMAC keys (256+ bits of entropy, securely generated and stored)
- Always validate integrity checks server-side before processing any data
- Reject requests with missing integrity parameters
- For JWTs: explicitly validate the algorithm header against expected values, reject `none`
- Use asymmetric signatures (RS256, ES256) for JWTs when the signing and verification parties differ
- Implement request signing with timestamps to prevent replay attacks
- Use authenticated encryption (AEAD) for encrypted data rather than separate encrypt + hash
- Log integrity check failures as potential tampering attempts

## References

- [OWASP Testing Guide - Test Integrity Checks](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks)
- [CWE-354: Improper Validation of Integrity Check Value](https://cwe.mitre.org/data/definitions/354.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

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

- V11 Business Logic — workflow integrity and limit enforcement.
- V4 Access Control — state transitions require proper authorization.

## CWE references

- CWE-840: Business Logic Errors
- CWE-362: Race Condition

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test price/quantity manipulation and workflow step skipping.
- Parallel requests for race windows on limits and balances.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

