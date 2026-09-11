---
id: WSTG-ATHN-10
title: Testing for Weaker Authentication in Alternative Channel
category: Authentication
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel
---

# WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel

## Summary

Applications often expose multiple channels for user interaction: web application, mobile API, legacy endpoints, partner APIs, administrative interfaces, or internal services. Each channel may implement authentication differently, and weaker authentication in any alternative channel can be exploited to bypass stronger controls on the primary channel. If a mobile API accepts simple API keys while the web application requires MFA, an attacker can target the weaker mobile API to gain access.

## Test Objectives

- Identify all alternative channels and endpoints that provide access to the application
- Compare authentication mechanisms across each channel
- Test if weaker authentication in alternative channels grants equivalent access
- Check for legacy or deprecated endpoints that bypass current security controls
- Verify consistent security policy enforcement across all channels

## Prerequisites

- Understanding of the application architecture and available channels
- Access to mobile application, API documentation, or partner API specifications
- Docker pentest container is capturing traffic
- Ability to route mobile application traffic through HTTP proxy

## Test Steps

### Step 1: Enumerate Alternative Channels and Endpoints

**CLI Actions:**
1. Use `curl` to review all captured traffic for different API paths and endpoints
2. Use `curl` with pattern `/api/v[0-9]|/mobile/|/m/|/legacy/|/internal/|/partner/|/soap/|/graphql|/rest/` to identify alternative API versions and channels
3. Use `curl` to probe for common alternative endpoints:
   ``
   GET /api/v1/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>

   GET /api/v2/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>

   GET /mobile/api/user/profile HTTP/1.1
   Host: target.com
   Cookie: session=<valid_session>
   ``
4. Check for different subdomains:
   ``
   GET /api/user/profile HTTP/1.1
   Host: api.target.com

   GET /api/user/profile HTTP/1.1
   Host: m.target.com

   GET /api/user/profile HTTP/1.1
   Host: legacy.target.com
   ``
5. Use `rynix_plugin_run('template-scan')` to check for any findings related to alternative endpoints

### Step 2: Compare Authentication Requirements

**CLI Actions:**
1. For each identified channel, test what authentication is required
2. Use `curl` to access the same resource via different channels and compare:
   ``
   GET /api/v1/account HTTP/1.1
   Host: target.com
   Authorization: Bearer <jwt_token>
   ``
   vs.
   ``
   GET /api/v2/account HTTP/1.1
   Host: target.com
   X-API-Key: <simple_api_key>
   ``
3. Test if older API versions accept weaker authentication:
   ``
   GET /api/v1/account HTTP/1.1
   Host: target.com
   Authorization: Basic dGVzdDp0ZXN0MTIz
   ``
4. Use `base64` to create Basic auth headers for testing:
   - Encode `username:password` to Base64
5. Check if any channel accepts unauthenticated requests for data that requires auth on the primary channel

### Step 3: Test Mobile API Authentication

**CLI Actions:**
1. Use `curl` with pattern `X-App-Version|X-Device-Id|X-Mobile|X-Platform|User-Agent.*Mobile` to identify mobile-specific requests
2. Use `curl` to replay mobile API requests without the mobile-specific tokens:
   ``
   GET /mobile/api/profile HTTP/1.1
   Host: target.com
   X-API-Key: <mobile_api_key>
   ``
3. Test if the mobile API bypasses MFA requirements:
   ``
   POST /mobile/api/login HTTP/1.1
   Host: target.com
   Content-Type: application/json

   {"username":"testuser","password":"validpass"}
   ``
4. Check if the mobile API returns more data than the web application for the same endpoint
5. Test if mobile API tokens have longer expiration or different privilege scoping

### Step 4: Test Legacy Endpoint Authentication

**CLI Actions:**
1. Probe for common legacy endpoint patterns:
   ``
   GET /api/v0/users HTTP/1.1
   Host: target.com

   GET /old/api/users HTTP/1.1
   Host: target.com

   GET /service/users HTTP/1.1
   Host: target.com
   ``
2. Use `curl` to test if legacy endpoints use deprecated authentication:
   ``
   GET /api/v1/users HTTP/1.1
   Host: target.com
   Authorization: Basic YWRtaW46YWRtaW4=
   ``
3. Test SOAP endpoints if the application originally used SOAP:
   ``
   POST /ws/UserService HTTP/1.1
   Host: target.com
   Content-Type: text/xml
   SOAPAction: "getUser"

   <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
     <soapenv:Body>
       <getUser><userId>1</userId></getUser>
     </soapenv:Body>
   </soapenv:Envelope>
   ``
4. Use `base64 -d` to decode any legacy authentication tokens found in traffic

### Step 5: Test Cross-Channel Session Validity

**CLI Actions:**
1. Authenticate on the web channel and capture the session token
2. Use `curl` to test if the web session works on alternative channels:
   ``
   GET /mobile/api/profile HTTP/1.1
   Host: target.com
   Cookie: session=<web_session>
   ``
3. Test if a mobile API token works on the web application:
   ``
   GET /account/profile HTTP/1.1
   Host: target.com
   Authorization: Bearer <mobile_api_token>
   ``
4. Test if revoking access on one channel affects all channels:
   - Change password on the web interface
   - Use `curl` to test if the mobile API token still works:
     ``
     GET /mobile/api/profile HTTP/1.1
     Host: target.com
     Authorization: Bearer <old_mobile_token>
     ``
5. Use `save to manual-review file` to set up requests for each channel for easy comparison

### Step 6: Test Administrative and Internal Endpoints

**CLI Actions:**
1. Use `curl` to probe for internal/admin API endpoints:
   ``
   GET /internal/api/users HTTP/1.1
   Host: target.com

   GET /admin/api/users HTTP/1.1
   Host: target.com

   GET /management/api/health HTTP/1.1
   Host: target.com

   GET /actuator/env HTTP/1.1
   Host: target.com
   ``
2. Test if internal endpoints trust specific headers for authentication:
   ``
   GET /internal/api/users HTTP/1.1
   Host: target.com
   X-Forwarded-For: 127.0.0.1
   X-Real-IP: 10.0.0.1
   X-Internal: true
   ``
3. Use `curl` with pattern `internal|actuator|management|health|metrics|debug` to find any internal endpoints exposed in proxy history
4. Test if debug or diagnostic endpoints expose authentication tokens or user data

## Payloads

### Alternative API Path Patterns
```
/api/v0/
/api/v1/
/api/v2/
/api/v3/
/mobile/api/
/m/api/
/app/api/
/legacy/
/old/
/internal/
/partner/
/external/
/public/
/soap/
/ws/
/graphql
/rest/
```

### Alternative Subdomain Patterns
```
api.target.com
m.target.com
mobile.target.com
legacy.target.com
old.target.com
internal.target.com
staging.target.com
dev.target.com
test.target.com
partner.target.com
```

### Internal Trust Header Payloads
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /internal/admin
X-Internal-Auth: true
X-Bypass-Auth: true
X-Custom-IP-Authorization: 127.0.0.1
```

## Detection Criteria

A finding should be logged when:
- Alternative channels use weaker authentication than the primary channel
- Legacy API endpoints bypass MFA or modern authentication requirements
- Mobile APIs accept simple API keys instead of full authentication
- Internal endpoints are accessible from external networks
- Cross-channel session management is inconsistent
- Trust-based authentication headers can be spoofed
- Deprecated authentication methods (Basic auth) are still accepted
- Token revocation on one channel does not affect other channels

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Internal endpoints accessible externally without authentication | High |
| Legacy API allows full access with deprecated weak authentication | High |
| Mobile API bypasses MFA requirements | High |
| Alternative channel provides broader data access than primary | Medium |
| Trust headers (X-Forwarded-For) bypass authentication | High |
| Cross-channel token revocation is inconsistent | Medium |
| Deprecated Basic auth accepted on alternative endpoints | Medium |
| Version-less API endpoints not enforcing latest auth requirements | Medium |
| Debug/health endpoints expose sensitive information | Low |

## Remediation

- Enforce consistent authentication policies across all channels and API versions
- Deprecate and remove legacy API versions that use weaker authentication
- Require MFA on all channels that access sensitive operations
- Use a centralized authentication service (IdP) shared across all channels
- Do not trust client-supplied headers (X-Forwarded-For) for authentication
- Ensure token revocation propagates to all channels immediately
- Restrict internal endpoints to internal networks using network-level controls
- Monitor and audit access to alternative channels
- Implement API gateway policies that enforce uniform authentication requirements
- Regularly scan for and decommission undocumented or deprecated endpoints

## References

- [OWASP Testing Guide - Weaker Authentication in Alternative Channel](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel)
- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

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

- V2 Authentication — credential storage, lockout, MFA.
- V3 Session Management — session binding and rotation.

## CWE references

- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-798: Use of Hard-coded Credentials

## Rynix tooling

- Primary tools: ``auth_login``, ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test password policy, lockout, and MFA bypass paths.
- Verify tokens/sessions invalidated on logout and password change.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

