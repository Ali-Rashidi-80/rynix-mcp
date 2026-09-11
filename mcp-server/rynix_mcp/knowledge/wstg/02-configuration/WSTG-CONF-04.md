---
id: WSTG-CONF-04
title: Review Old Backup and Unreferenced Files
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files
---

# WSTG-CONF-04: Review Old Backup and Unreferenced Files

## Summary

Web servers and applications often contain old, backup, or unreferenced files that were not intended to be publicly accessible. These may include backup copies of source code, database dumps, configuration archives, temporary files created by editors, and administrative scripts. These files can disclose sensitive information such as source code, credentials, database contents, and internal application logic.

## Test Objectives

- Discover backup files, temporary files, and old versions of application files
- Identify unreferenced pages, scripts, and administrative utilities
- Determine if version control metadata or deployment artifacts are accessible
- Assess the sensitivity of any discovered files

## Prerequisites

- Target URL is accessible via `http_probe`
- Application has been browsed to build a baseline sitemap

## Test Steps

### Step 1: Check for Version Control Metadata

**CLI Actions:**
1. Use `curl` to probe for exposed version control directories:
   ``
   GET /.git/HEAD HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.git/config HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.svn/entries HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.svn/wc.db HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.hg/store/00manifest.i HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.bzr/README HTTP/1.1
   Host: target.com
   ``
   ``
   GET /CVS/Root HTTP/1.1
   Host: target.com
   ``
2. A 200 response to `.git/HEAD` typically contains `ref: refs/heads/main` or similar, confirming exposed Git repository
3. Use `save to manual-review file` to further explore any exposed VCS directories

### Step 2: Discover Backup Files for Known Resources

**CLI Actions:**
1. Use `curl` to identify existing application files from the browsing history
2. For each known file (e.g., `index.php`, `login.php`, `config.php`), use `curl` to check for backup variants:
   ``
   GET /index.php.bak HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.old HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php~ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.orig HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.save HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.swp HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.index.php.swp HTTP/1.1
   Host: target.com
   ``
   ``
   GET /index.php.tmp HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Copy%20of%20index.php HTTP/1.1
   Host: target.com
   ``
3. Use `fuzz-cli` with a known file list and backup suffix list to automate this process across all discovered pages

### Step 3: Search for Archive and Database Dump Files

**CLI Actions:**
1. Use `curl` to probe for common backup archive files:
   ``
   GET /backup.zip HTTP/1.1
   Host: target.com
   ``
   ``
   GET /backup.tar.gz HTTP/1.1
   Host: target.com
   ``
   ``
   GET /site.zip HTTP/1.1
   Host: target.com
   ``
   ``
   GET /www.zip HTTP/1.1
   Host: target.com
   ``
   ``
   GET /htdocs.tar.gz HTTP/1.1
   Host: target.com
   ``
   ``
   GET /dump.sql HTTP/1.1
   Host: target.com
   ``
   ``
   GET /database.sql HTTP/1.1
   Host: target.com
   ``
   ``
   GET /db.sql HTTP/1.1
   Host: target.com
   ``
   ``
   GET /backup.sql HTTP/1.1
   Host: target.com
   ``
   ``
   GET /data.sql HTTP/1.1
   Host: target.com
   ``
2. Also test with the hostname or domain as the filename:
   ``
   GET /target.com.zip HTTP/1.1
   Host: target.com
   ``
   ``
   GET /target.zip HTTP/1.1
   Host: target.com
   ``
3. Check `Content-Length` and `Content-Type` headers - a large response or `application/zip` type indicates a real file

### Step 4: Probe for Unreferenced Administrative and Utility Files

**CLI Actions:**
1. Use `curl` to check for common unreferenced files:
   ``
   GET /admin.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /test.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /install.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /setup.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /upgrade.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /readme.html HTTP/1.1
   Host: target.com
   ``
   ``
   GET /CHANGELOG.md HTTP/1.1
   Host: target.com
   ``
   ``
   GET /TODO HTTP/1.1
   Host: target.com
   ``
   ``
   GET /LICENSE HTTP/1.1
   Host: target.com
   ``
2. Use `fuzz-cli` to automate testing with a comprehensive list of common filenames

### Step 5: Check for Deployment Artifacts

**CLI Actions:**
1. Use `curl` to check for CI/CD and deployment files:
   ``
   GET /.env HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.env.production HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.env.local HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Dockerfile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /docker-compose.yml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.dockerignore HTTP/1.1
   Host: target.com
   ``
   ``
   GET /Jenkinsfile HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.gitlab-ci.yml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.github/workflows/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /deploy.sh HTTP/1.1
   Host: target.com
   ``
2. Use `rynix_plugin_run('template-scan')` to check for any backup or unreferenced file findings from the template-scan plugin

### Step 6: Mine Proxy History for Clues

**CLI Actions:**
1. Use `curl` to search for references to backup or old files in HTML comments, JavaScript, or response bodies:
   - Pattern: `(backup|bak|old|copy|temp|tmp|archive)` in response bodies
   - Pattern: `<!--.*-->` to find HTML comments that may reference hidden files
2. Use `curl` to review the sitemap for any directories that might contain backup files (e.g., `/backup/`, `/old/`, `/archive/`, `/temp/`)

## Payloads

### Backup File Suffixes
```
.bak
.backup
.old
.orig
.save
.tmp
.temp
.swp
.sav
~
.copy
.1
.2
_backup
_old
_bak
.zip
.tar
.tar.gz
.gz
.rar
.7z
```

### Common Archive Filenames
```
backup.zip
backup.tar.gz
site.zip
www.zip
htdocs.zip
public_html.zip
html.zip
web.zip
source.zip
src.zip
dump.sql
database.sql
db.sql
backup.sql
export.sql
data.csv
```

### Common Unreferenced Filenames
```
test.php
phpinfo.php
info.php
admin.php
install.php
setup.php
upgrade.php
debug.php
shell.php
cmd.php
console.php
config.php.bak
wp-config.php.bak
```

## Detection Criteria

A finding should be logged when:
- Version control metadata (`.git`, `.svn`) is accessible
- Backup copies of source code files are downloadable
- Database dump files are accessible
- Archive files containing application source are downloadable
- Deployment configuration files (`.env`, `Dockerfile`) are accessible
- Installation or setup scripts remain accessible in production
- Editor temporary files (`.swp`, `~`) are accessible

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Database dump accessible containing user data or credentials | High |
| .git directory fully accessible allowing repository reconstruction | High |
| .env file with credentials or API keys accessible | High |
| Application source code archive downloadable | High |
| Backup of config files with credentials accessible | High |
| Installation/setup scripts accessible in production | Medium |
| Source code of individual files disclosed via backup extensions | Medium |
| Deployment files (Dockerfile, CI configs) accessible | Medium |
| Changelog or readme revealing version information | Low |
| Editor temp files accessible but with no sensitive content | Low |

## Remediation

- Implement a deployment process that excludes backup files, temp files, and VCS metadata
- Add server-level rules to block access to common backup extensions (`.bak`, `.old`, `.swp`, `~`)
- Block access to hidden directories and dot-files (`.git`, `.svn`, `.env`)
- Remove installation and setup scripts after deployment
- Regularly audit web-accessible directories for unintended files
- Use `.gitignore` and equivalent to prevent committing sensitive files
- Store database backups and archives outside the web root
- Implement a build pipeline that produces clean deployment artifacts

## References

- [OWASP Testing Guide - Review Old Backup and Unreferenced Files](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files)
- [CWE-530: Exposure of Backup File to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/530.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

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

- V14 Configuration — secure defaults for headers, TLS, methods.
- V13 API and Web Service — admin interfaces not exposed.

## CWE references

- CWE-16: Configuration
- CWE-319: Cleartext Transmission

## Rynix tooling

- Primary tools: ``http_probe``, ``compare_role_response``, ``record_finding``

## Test focus

- Test HTTP methods, security headers, and TLS cipher suites.
- Verify admin/debug interfaces return 404 or require auth in production.

## GenAI / LLM 2026 notes

- Cross-reference `knowledge/custom/genai_llm_security_2026.md` (OWASP LLM Top 10 mapping).
- Probe AI endpoints with `http_probe` only — no external LLM API keys in Rynix runtime.
- Use `compare_role_response` to detect cross-tenant prompt/response leakage.
- Map findings to LLM01–LLM10 categories in `export_report`.

