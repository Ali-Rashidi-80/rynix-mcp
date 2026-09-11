---
id: WSTG-SESS-10
title: Testing JSON Web Tokens
category: Session Management
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
---

# WSTG-SESS-10: Testing JSON Web Tokens

## Summary

JSON Web Tokens (JWTs) are widely used for authentication and session management in modern web applications and APIs. JWTs consist of three base64url-encoded parts: header, payload, and signature. Vulnerabilities arise from algorithm confusion attacks (switching from RS256 to HS256), the "none" algorithm bypass, weak signing keys, claim manipulation, and acceptance of expired tokens. This test evaluates the security of JWT implementations.

## Test Objectives

- Test for algorithm confusion attacks (RS256 to HS256)
- Test if the "none" algorithm is accepted, bypassing signature verification
- Evaluate signing key strength and test for weak or default keys
- Test for claim manipulation (role, user ID, permissions)
- Verify that expired tokens are properly rejected

## Prerequisites

- Target application uses JWTs for authentication or session management
- A valid authenticated JWT for testing
- Docker pentest container capturing JWT traffic
- Knowledge of JWT structure (header.payload.signature)

## Test Steps

### Step 1: Capture and Decode the JWT

**CLI Actions:**
1. Authenticate to the application and use `curl` to capture the JWT
2. Use `curl` with pattern `(Authorization: Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)` to find JWTs in requests and responses
3. Split the JWT into its three parts (separated by dots)
4. Use `base64 -d` on the header (first part) to reveal the algorithm and token type:
   ``json
   {"alg":"RS256","typ":"JWT"}
   ``
5. Use `base64 -d` on the payload (second part) to reveal the claims:
   ``json
   {"sub":"user123","role":"user","iat":1700000000,"exp":1700003600}
   ``
6. Document the algorithm, claims, and expiration time

### Step 2: Test the "none" Algorithm Bypass

**CLI Actions:**
1. Decode the JWT header and modify the algorithm to `none`:
   ``json
   {"alg":"none","typ":"JWT"}
   ``
2. Use `base64` to encode the modified header (use base64url encoding: replace `+` with `-`, `/` with `_`, remove `=` padding)
3. Construct a new JWT with the modified header, original payload, and empty signature:
   ``
   <base64url_modified_header>.<base64url_original_payload>.
   ``
4. Use `curl` to send the modified token:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <modified_jwt_with_none_alg>
   ``
5. Also test algorithm variations: `None`, `NONE`, `nOnE`
6. If the server accepts the token, it does not properly validate the algorithm

### Step 3: Test Algorithm Confusion (RS256 to HS256)

**CLI Actions:**
1. If the original JWT uses an asymmetric algorithm (RS256, RS384, RS512, ES256):
   - The server verifies with a public key
   - In an algorithm confusion attack, the attacker changes the algorithm to HS256
   - The server may then use the public key as the HMAC secret
2. Obtain the server's public key (often available at `/.well-known/jwks.json` or `/oauth/jwks`):
   ``
   GET /.well-known/jwks.json HTTP/1.1
   Host: target.com
   ``
3. Use `curl` to fetch the JWKS endpoint and note the public key
4. Create a modified JWT:
   - Change header to `{"alg":"HS256","typ":"JWT"}`
   - Keep or modify the payload as needed
   - Sign with HMAC-SHA256 using the public key as the secret
5. Use `curl` to test the modified token:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <jwt_signed_with_public_key_as_hmac_secret>
   ``

### Step 4: Test Weak Signing Keys

**CLI Actions:**
1. If the JWT uses HMAC (HS256, HS384, HS512), the signing key may be weak or a common password
2. Use `curl` to capture several JWTs from the application
3. Common weak signing keys to test against:
   - `secret`, `password`, `123456`, `key`, `jwt_secret`, `changeme`
   - The application name, domain name, or company name
   - Default framework secrets
4. For each candidate key, compute the HMAC signature of the `header.payload` portion
5. If the computed signature matches the JWT's signature, the key has been found
6. With the known key, forge arbitrary JWTs with modified claims and test with `curl`:
   ``
   GET /api/admin/users HTTP/1.1
   Host: target.com
   Authorization: Bearer <forged_jwt_with_admin_role>
   ``

### Step 5: Test Claim Manipulation

**CLI Actions:**
1. Decode the JWT payload with `base64 -d` and identify modifiable claims:
   - `sub` (subject/user ID)
   - `role` or `roles`
   - `admin` or `is_admin`
   - `scope` or `permissions`
   - `email`
   - `group` or `groups`
2. If a signing key weakness was found (Steps 2-4), create JWTs with modified claims:
   - Change `role` from `user` to `admin`
   - Change `sub` from your user ID to another user's ID
   - Add new claims like `"admin": true`
3. Use `curl` to test each modified token:
   ``
   GET /api/admin/dashboard HTTP/1.1
   Host: target.com
   Authorization: Bearer <jwt_with_modified_role_claim>
   ``
4. Test if the server trusts claims without server-side validation (e.g., does it check the `role` claim against a database?)

### Step 6: Test Expired Token Acceptance

**CLI Actions:**
1. Decode the JWT payload and note the `exp` (expiration) claim
2. Wait until after the expiration time has passed
3. Use `curl` to send the expired token:
   ``
   GET /api/user/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <expired_jwt>
   ``
4. If the server accepts the expired token, expiration validation is not enforced
5. If a signing key weakness was found, create a token with a past `exp` value and test:
   ``json
   {"sub":"user123","role":"user","exp":1000000000}
   ``
6. Also test with:
   - Missing `exp` claim entirely
   - `exp` set to `0`
   - `exp` set to a very far future date (e.g., year 2100)
   - `nbf` (not before) set to a future date

### Step 7: Test JWT Header Injection (jwk, jku, kid)

**CLI Actions:**
1. Check if the JWT header contains `kid` (key ID), `jku` (JWK Set URL), or `jwk` (embedded key) parameters
2. Test `jku` header injection - point to an attacker-controlled JWKS:
   - Modify the header: `{"alg":"RS256","jku":"https://evil.com/jwks.json"}`
   - Use `base64` to encode the modified header
   - Sign the JWT with a key pair you control
   - Host the public key at the attacker URL
3. Test `kid` parameter injection for path traversal or SQL injection:
   - `{"alg":"HS256","kid":"../../dev/null"}` (sign with empty string)
   - `{"alg":"HS256","kid":"' UNION SELECT 'known_secret' --"}`
4. Test embedded `jwk` header:
   - Include your own public key in the JWT header
   - Sign with the corresponding private key
5. Use `curl` to test each modified token against a protected endpoint

## Payloads

### Algorithm Bypass Values
```
none
None
NONE
nOnE
```

### Weak Signing Keys
```
secret
password
123456
jwt_secret
changeme
key
private
default
test
```

### Claim Manipulation Values
```json
{"role":"admin"}
{"admin":true}
{"is_admin":true}
{"scope":"admin read write"}
{"groups":["admin","users"]}
{"sub":"admin"}
{"permissions":["*"]}
```

### Header Injection Values
```json
{"alg":"none","typ":"JWT"}
{"alg":"HS256","typ":"JWT"}
{"alg":"RS256","jku":"https://evil.com/jwks.json"}
{"alg":"HS256","kid":"../../dev/null"}
{"alg":"HS256","kid":"' OR 1=1 --"}
```

## Detection Criteria

A finding should be logged when:
- The "none" algorithm is accepted, allowing unsigned tokens
- Algorithm confusion (RS256 to HS256) is possible, allowing token forgery
- The signing key is weak or a common/default value
- Modified claims (role, user ID, admin) are accepted and grant elevated access
- Expired tokens are accepted by the server
- JWT header parameters (jku, kid, jwk) can be injected to bypass signature verification
- Tokens with missing `exp` claims are accepted indefinitely

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| "none" algorithm accepted (complete signature bypass) | Critical |
| Algorithm confusion allows forging tokens with public key | Critical |
| Weak signing key discovered (arbitrary token forgery) | Critical |
| Claim manipulation grants admin access | Critical |
| jku/kid injection allows signature bypass | Critical |
| Expired tokens accepted by the server | Medium |
| Missing exp claim accepted (tokens never expire) | Medium |
| Token claims not validated against server-side data | Medium |
| JWT used without HttpOnly cookie (stored in localStorage) | Medium |
| Signing key is strong but token lifetime is excessively long | Low |

## Remediation

- Use strong, randomly generated signing keys (at least 256 bits for HMAC)
- Explicitly validate the `alg` header against an allowlist of expected algorithms
- Reject the "none" algorithm and any unexpected algorithm values
- For asymmetric algorithms, never use the public key as an HMAC secret
- Validate `exp`, `nbf`, and `iat` claims on every request
- Set short token lifetimes (15-60 minutes for access tokens)
- Use refresh tokens for long-lived sessions (and store them securely)
- Validate token claims (role, user ID) against server-side data, not just the token
- Do not trust `jku`, `jwk`, or `kid` header parameters from the token; use server-configured keys
- Store JWTs in HttpOnly cookies rather than localStorage when possible
- Implement token revocation (blocklist) for logout and compromised tokens

## References

- [OWASP Testing Guide - JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

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

- V3 Session Management — fixation, timeout, secure cookie flags.
- V2 Authentication — session binding to client fingerprint where applicable.

## CWE references

- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``auth_login``

## Test focus

- Test cookie flags, rotation on login, and concurrent session limits.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

