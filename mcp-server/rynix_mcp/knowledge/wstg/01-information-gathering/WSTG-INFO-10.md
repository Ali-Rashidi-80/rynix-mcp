---
id: WSTG-INFO-10
title: Map Application Architecture
category: Information Gathering
severity_range: Informational - Low
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture
---

# WSTG-INFO-10: Map Application Architecture

## Summary

Modern web applications are deployed behind multiple layers of infrastructure including content delivery networks (CDNs), web application firewalls (WAFs), load balancers, reverse proxies, application servers, caching layers, and backend services. Understanding the full architecture helps testers identify components that may introduce vulnerabilities, bypass security controls, or reveal additional attack surface. Each infrastructure component may have its own configuration weaknesses and known vulnerabilities.

## Test Objectives

- Identify all infrastructure components between the client and the application (CDN, WAF, load balancer, reverse proxy)
- Determine if a web application firewall is in place and identify its type
- Detect load balancing and session persistence mechanisms
- Map backend services and third-party integrations
- Understand the caching architecture and its security implications

## Prerequisites

- Target application is accessible through Docker pentest container
- Rynix http_probe session is capturing all requests and responses
- DNS resolution is available for the target domain

## Test Steps

### Step 1: Detect Content Delivery Networks (CDNs)

**CLI Actions:**
1. Use `curl` to send a GET request and examine response headers:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Use `curl` with pattern `CF-RAY|cf-cache-status|cf-request-id` to detect Cloudflare
3. Use `curl` with pattern `X-Cache|X-Amz-Cf-Id|X-Amz-Cf-Pop` to detect AWS CloudFront
4. Use `curl` with pattern `X-Akamai|Akamai|X-True-Cache-Key` to detect Akamai
5. Use `curl` with pattern `X-Fastly|Fastly-Debug|X-Served-By.*cache-` to detect Fastly
6. Use `curl` with pattern `X-Azure-Ref|X-MSEdge-Ref` to detect Azure CDN
7. Use `curl` with pattern `X-CDN|CDN-Cache` to detect generic CDN indicators

**CDN Detection Indicators:**

| Header / Pattern | CDN Provider |
|------------------|-------------|
| `CF-RAY`, `cf-cache-status`, `Server: cloudflare` | Cloudflare |
| `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, `X-Cache` from `*.cloudfront.net` | AWS CloudFront |
| `X-Akamai-Transformed`, `X-True-Cache-Key`, `Server: AkamaiGHost` | Akamai |
| `X-Served-By: cache-*`, `X-Fastly-Request-ID` | Fastly |
| `X-Azure-Ref`, `X-MSEdge-Ref` | Azure CDN / Front Door |
| `X-GUploader-UploadID`, `Server: UploadServer` | Google Cloud CDN |
| `X-Cache: HIT from *` | Various / Varnish |

### Step 2: Detect Web Application Firewalls (WAFs)

**CLI Actions:**
1. Use `curl` to send a benign request and record the baseline response
2. Use `curl` to send requests with common attack signatures to trigger WAF responses:
   ``
   GET /?test=<script>alert(1)</script> HTTP/1.1
   Host: target.com
   ``
   ``
   GET /?test=' OR 1=1-- HTTP/1.1
   Host: target.com
   ``
   ``
   GET /?test=../../etc/passwd HTTP/1.1
   Host: target.com
   ``
3. Use `curl --data-urlencode` to encode attack payloads when testing WAF bypass behavior:
   - Encode `<script>alert(1)</script>` and resend
4. Compare responses -- WAF-blocked requests typically return different status codes (403, 406, 429), custom error pages, or CAPTCHA challenges
5. Use `curl` with pattern `Server: AkamaiGHost|Server: cloudflare|Server: BIG-IP|Server: Imperva` to detect WAF server headers
6. Use `save to manual-review file` for WAF-triggering requests to test bypass techniques

**WAF Detection Indicators:**

| Indicator | WAF |
|-----------|-----|
| `Server: cloudflare`, CAPTCHA on blocked requests | Cloudflare WAF |
| `Server: AkamaiGHost`, custom block page referencing Akamai | Akamai Kona Site Defender |
| `X-WAAS-Info`, `X-SL-CompState` | Imperva/Incapsula |
| `Server: BIG-IP`, `TS` cookies | F5 BIG-IP ASM |
| `X-Sucuri-ID`, `X-Sucuri-Cache` | Sucuri WAF |
| `AWSALB` cookie + 403 with generic block page | AWS WAF |
| `X-Denied-Reason`, `X-dotDefender-denied` | dotDefender |
| `X-ModSecurity-*` headers or ModSecurity error messages | ModSecurity |
| Custom 403 page with "Access Denied" or "Request Blocked" | Generic WAF presence |

### Step 3: Detect Load Balancers and Reverse Proxies

**CLI Actions:**
1. Use `curl` to send multiple identical requests and compare response headers:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
   (Send 5-10 times and compare)
2. Use `curl` with pattern `X-Forwarded-For|X-Real-IP|X-Forwarded-Proto|Via` to detect proxy headers
3. Use `curl` with pattern `AWSALB|AWSELB|SERVERID|BIGipServer|ROUTEID|HAProxy` to detect load balancer cookies
4. Use `curl` with pattern `X-Backend-Server|X-Upstream|X-Served-By` to detect backend server identification

**What to Look For Across Multiple Responses:**
- Changing `Server` header values (different backend servers)
- Changing `X-Served-By` or `X-Backend-Server` values
- Different `Date` header times suggesting different backend clocks
- Different response sizes for identical requests (different backend versions)
- Load balancer session cookies:

| Cookie Pattern | Load Balancer |
|----------------|--------------|
| `AWSALB`, `AWSALBCORS` | AWS Application Load Balancer |
| `AWSELB` | AWS Elastic Load Balancer (Classic) |
| `BIGipServer*` | F5 BIG-IP |
| `SERVERID` | HAProxy |
| `ROUTEID` | Apache mod_proxy_balancer |
| `incap_ses_*` | Imperva/Incapsula |
| `__cflb` | Cloudflare Load Balancer |

### Step 4: Identify Caching Layers

**CLI Actions:**
1. Use `curl` with pattern `X-Cache|X-Cache-Status|X-Varnish|Age:|X-Cache-Hits` to detect caching headers
2. Use `curl` to send the same request twice and check for caching indicators:
   ``
   GET /some-page HTTP/1.1
   Host: target.com
   ``
   First request: expect `X-Cache: MISS`
   Second request: expect `X-Cache: HIT`
3. Use `curl` with cache-busting to compare cached vs uncached responses:
   ``
   GET /some-page HTTP/1.1
   Host: target.com
   Cache-Control: no-cache
   Pragma: no-cache
   ``
4. Use `GenerateRandomString` to create unique query parameters for cache-busting tests

**Caching Indicators:**

| Header | Meaning |
|--------|---------|
| `X-Cache: HIT` | Response served from cache |
| `X-Cache: MISS` | Response fetched from origin |
| `Age: N` | Cached response age in seconds |
| `X-Varnish: ID1 ID2` | Varnish cache (two IDs = cache hit) |
| `X-Cache-Status: HIT/MISS/STALE/BYPASS` | Nginx FastCGI cache or similar |
| `CF-Cache-Status: HIT/MISS/DYNAMIC` | Cloudflare caching |
| `X-Cache-Hits: N` | Number of times response served from cache |
| `Via: 1.1 varnish` | Varnish proxy in request path |

### Step 5: Map Backend Services and Third-Party Integrations

**CLI Actions:**
1. Use `curl` with pattern `https?://[a-zA-Z0-9\.\-]+\.(amazonaws\.com|azure\.|googleapis\.com|cloudfront\.net)` to find cloud service references
2. Use `curl` with pattern `Content-Security-Policy` to extract whitelisted domains from CSP headers -- these reveal third-party services
3. Use `curl` with pattern `Access-Control-Allow-Origin` to find CORS-allowed origins
4. Use `curl` to review all captured traffic and identify external service calls:
   - Analytics services (Google Analytics, Mixpanel, Segment)
   - Payment processors (Stripe, PayPal, Braintree)
   - Authentication providers (Auth0, Okta, Firebase Auth)
   - Storage services (S3, Azure Blob, GCS)
   - Email services (SendGrid, Mailgun, SES)
5. Use `curl` with pattern `\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net` to find cloud storage references
6. Use `curl` to probe any discovered S3 buckets or storage endpoints for misconfigured access:
   ``
   GET / HTTP/1.1
   Host: discovered-bucket.s3.amazonaws.com
   ``

### Step 6: Detect Application Server and Runtime Environment

**CLI Actions:**
1. Use `curl` with pattern `Server:|X-Powered-By:|X-Runtime:|X-AspNet-Version` to collect all server technology headers
2. Use `curl` to trigger error responses that may reveal the application server:
   ``
   GET /%00 HTTP/1.1
   Host: target.com
   ``
3. Use `curl` with pattern `Tomcat|Jetty|Puma|Unicorn|Gunicorn|uWSGI|Kestrel|WEBrick` to identify application servers

**Application Server Indicators:**

| Indicator | Application Server |
|-----------|--------------------|
| `Server: Apache-Coyote` or Tomcat error pages | Apache Tomcat |
| `Server: Jetty` | Jetty |
| `X-Powered-By: Servlet` | Java Servlet Container |
| `Server: gunicorn` | Gunicorn (Python) |
| `Server: uvicorn` | Uvicorn (Python ASGI) |
| `Server: Puma`, `X-Runtime` header | Puma (Ruby) |
| `Server: Unicorn` | Unicorn (Ruby) |
| `Server: Kestrel` | Kestrel (ASP.NET Core) |
| `Server: nginx` with proxy indicators | Nginx as reverse proxy |
| `Server: openresty` | OpenResty (Nginx + Lua) |

### Step 7: Compile Architecture Map

**CLI Actions:**
1. Use `curl` to review all collected evidence
2. Use `rynix_plugin_run('template-scan')` to incorporate any infrastructure-related findings from the template-scan plugin
3. Use `base64 -d` and `python3 -c "import urllib.parse; ..."` on any encoded values in headers or cookies that may contain infrastructure information (e.g., F5 BIG-IP cookies encode backend server IP addresses)

**Document the architecture in layers:**
1. **Client Layer**: Browser, mobile app, API client
2. **CDN Layer**: Provider, caching behavior, edge locations
3. **WAF Layer**: WAF type, ruleset indicators
4. **Load Balancer Layer**: Type, session persistence mechanism, number of backends detected
5. **Reverse Proxy Layer**: Type (Nginx, Apache, HAProxy), configuration indicators
6. **Application Server Layer**: Runtime, framework, language
7. **Backend Services**: Databases (inferred), APIs, storage services, third-party integrations
8. **Cloud Infrastructure**: Provider (AWS, Azure, GCP), specific services identified

## Payloads

Not applicable -- this test involves architectural mapping through observation and standard probing rather than attack payload injection. WAF detection uses minimal trigger payloads only to observe blocking behavior.

## Detection Criteria

A finding should be logged when:
- Infrastructure components are identified that could be targeted directly (e.g., misconfigured CDN allowing cache poisoning)
- WAF presence is confirmed, enabling targeted bypass research
- Load balancer cookies expose internal IP addresses or backend server names
- Cloud storage buckets or services are discovered with misconfigured access
- Third-party services are identified with known security issues
- Internal architecture details are disclosed through headers or error messages

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Cloud storage buckets accessible without authentication | Low |
| Internal IP addresses disclosed via load balancer cookies or headers | Low |
| Backend server names or internal hostnames exposed in headers | Low |
| WAF identified (useful for scope but not itself a vulnerability) | Informational |
| CDN and caching infrastructure identified | Informational |
| Load balancer type and configuration identified | Informational |
| Application server and runtime environment identified | Informational |
| Complete architecture map documented | Informational |

## Remediation

- Configure load balancers to not expose internal IP addresses or server names in cookies and headers (e.g., encrypt F5 BIG-IP cookies)
- Remove or sanitize headers that reveal infrastructure details (`X-Backend-Server`, `X-Upstream`, `Via`)
- Ensure cloud storage buckets and services have properly restrictive access policies
- Configure CDN caching rules to prevent caching of sensitive content
- Enable WAF logging and monitoring for tuning and incident response
- Restrict access to application server status and health endpoints
- Implement consistent security configurations across all backend servers behind load balancers
- Review and minimize domains listed in Content-Security-Policy and CORS headers

## References

- [OWASP Testing Guide - Map Application Architecture](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [WAF Fingerprinting and Bypass Techniques](https://owasp.org/www-community/Web_Application_Firewall)
- [F5 BIG-IP Cookie Decoding](https://support.f5.com/csp/article/K6917)

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

- V1 Architecture — document exposed surfaces found via recon.
- V14 Configuration — verify no sensitive paths in robots/sitemap.

## CWE references

- CWE-200: Exposure of Sensitive Information

## Rynix tooling

- Primary tools: ``scope_check``, ``http_probe``, ``analyze_repo``, ``get_wstg_test``

## Test focus

- Passive recon only — no destructive probes.
- Correlate search-engine findings with live `http_probe` status.
- Save interesting URLs to engagement context for later phases.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

