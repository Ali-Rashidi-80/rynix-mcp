---
id: WSTG-CONF-11
title: Test Cloud Storage
category: Configuration and Deployment Management
severity_range: Medium-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage
---

# WSTG-CONF-11: Test Cloud Storage

## Summary

Cloud storage services such as Amazon S3, Azure Blob Storage, and Google Cloud Storage are widely used to host static assets, backups, logs, and application data. Misconfigured cloud storage buckets can allow unauthorized read access (exposing sensitive data), write access (enabling defacement or malware hosting), or listing permissions (revealing the full contents of the bucket). These misconfigurations are among the most common causes of data breaches in cloud-hosted applications.

## Test Objectives

- Identify cloud storage buckets and containers associated with the target
- Test for unauthorized read access to cloud storage objects
- Test for unauthorized write or list permissions on cloud storage
- Assess the sensitivity of data exposed in misconfigured storage

## Prerequisites

- Target URL is accessible via `http_probe`
- Target domain name and any associated cloud infrastructure are known

## Test Steps

### Step 1: Identify Cloud Storage References in the Application

**CLI Actions:**
1. Use `curl` to review all browsed traffic for references to cloud storage URLs
2. Use `curl` to search for cloud storage URL patterns:
   - Pattern: `s3\.amazonaws\.com` (AWS S3)
   - Pattern: `s3[-.][\w-]+\.amazonaws\.com` (regional S3)
   - Pattern: `[\w.-]+\.s3\.amazonaws\.com` (bucket-style S3)
   - Pattern: `blob\.core\.windows\.net` (Azure Blob)
   - Pattern: `storage\.googleapis\.com` (Google Cloud Storage)
   - Pattern: `[\w.-]+\.storage\.googleapis\.com` (GCS bucket-style)
   - Pattern: `firebasestorage\.googleapis\.com` (Firebase Storage)
   - Pattern: `digitaloceanspaces\.com` (DigitalOcean Spaces)
3. Note all discovered bucket names and URLs

### Step 2: Test AWS S3 Bucket Permissions

**CLI Actions:**
1. For each discovered S3 bucket, use `curl` to test listing permission:
   ``
   GET / HTTP/1.1
   Host: BUCKETNAME.s3.amazonaws.com
   ``
   Or the path-style URL:
   ``
   GET /BUCKETNAME HTTP/1.1
   Host: s3.amazonaws.com
   ``
2. A 200 response with XML listing `<ListBucketResult>` indicates public listing is enabled
3. Test read access to known objects:
   ``
   GET /known-file.jpg HTTP/1.1
   Host: BUCKETNAME.s3.amazonaws.com
   ``
4. Test write access by attempting a PUT:
   ``
   PUT /test-write-permission.txt HTTP/1.1
   Host: BUCKETNAME.s3.amazonaws.com
   Content-Type: text/plain
   Content-Length: 24

   Write permission test file
   ``
5. Test for public ACL information:
   ``
   GET /?acl HTTP/1.1
   Host: BUCKETNAME.s3.amazonaws.com
   ``
6. Use `save to manual-review file` to set up requests for systematic testing of each bucket

### Step 3: Test Azure Blob Storage Permissions

**CLI Actions:**
1. For each Azure storage account, use `curl` to test container listing:
   ``
   GET /CONTAINERNAME?restype=container&comp=list HTTP/1.1
   Host: ACCOUNTNAME.blob.core.windows.net
   ``
2. A 200 response with XML listing `<EnumerationResults>` indicates public listing is enabled
3. Test read access to a known blob:
   ``
   GET /CONTAINERNAME/known-file.jpg HTTP/1.1
   Host: ACCOUNTNAME.blob.core.windows.net
   ``
4. Check for anonymous access to the root:
   ``
   GET /?comp=list HTTP/1.1
   Host: ACCOUNTNAME.blob.core.windows.net
   ``
5. Test if the container allows public blob access vs public container access

### Step 4: Test Google Cloud Storage Permissions

**CLI Actions:**
1. For each GCS bucket, use `curl` to test listing:
   ``
   GET /storage/v1/b/BUCKETNAME/o HTTP/1.1
   Host: www.googleapis.com
   ``
2. Alternatively, test using the bucket-style URL:
   ``
   GET / HTTP/1.1
   Host: storage.googleapis.com/BUCKETNAME
   ``
3. A 200 response with JSON listing objects indicates public listing is enabled
4. Test read access:
   ``
   GET /BUCKETNAME/known-file.jpg HTTP/1.1
   Host: storage.googleapis.com
   ``
5. Test IAM policy access:
   ``
   GET /storage/v1/b/BUCKETNAME/iam HTTP/1.1
   Host: www.googleapis.com
   ``

### Step 5: Enumerate Bucket Names by Convention

**CLI Actions:**
1. Use `curl` to test common bucket naming patterns based on the target name:
   ``
   GET / HTTP/1.1
   Host: target.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-com.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-assets.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-backup.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-dev.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-staging.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-prod.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-uploads.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-media.s3.amazonaws.com
   ``
   ``
   GET / HTTP/1.1
   Host: target-logs.s3.amazonaws.com
   ``
2. Use `fuzz-cli` to automate testing with a list of common bucket name suffixes
3. Repeat for Azure (`ACCOUNTNAME.blob.core.windows.net/CONTAINERNAME`) and GCS (`storage.googleapis.com/BUCKETNAME`)

### Step 6: Check for Sensitive Data in Accessible Buckets

**CLI Actions:**
1. If a bucket listing is accessible, use `curl` to examine the listing for sensitive file types:
   - `.sql`, `.bak`, `.dump` - Database backups
   - `.env`, `.config`, `.key`, `.pem` - Configuration and credentials
   - `.csv`, `.xlsx`, `.json` - Data exports
   - `.log` - Log files
   - `.zip`, `.tar.gz` - Archives
2. Use `rynix_plugin_run('template-scan')` to check for any cloud storage findings from the template-scan plugin

## Payloads

### Common S3 Bucket Name Patterns
```
{company}
{company}-assets
{company}-backup
{company}-backups
{company}-data
{company}-dev
{company}-development
{company}-staging
{company}-prod
{company}-production
{company}-uploads
{company}-media
{company}-static
{company}-logs
{company}-archive
{company}-public
{company}-private
{company}-internal
{company}-cdn
{company}-images
{company}-files
{company}-docs
{company}-web
{company}-www
{company}-app
{company}-api
```

### Cloud Storage URL Formats
```
# AWS S3
https://BUCKET.s3.amazonaws.com/
https://s3.amazonaws.com/BUCKET/
https://BUCKET.s3-REGION.amazonaws.com/
https://s3.REGION.amazonaws.com/BUCKET/

# Azure Blob
https://ACCOUNT.blob.core.windows.net/CONTAINER/
https://ACCOUNT.blob.core.windows.net/?comp=list

# Google Cloud Storage
https://storage.googleapis.com/BUCKET/
https://BUCKET.storage.googleapis.com/
https://www.googleapis.com/storage/v1/b/BUCKET/o

# DigitalOcean Spaces
https://SPACE.REGION.digitaloceanspaces.com/
```

## Detection Criteria

A finding should be logged when:
- Cloud storage bucket allows public listing (enumerate all objects)
- Sensitive files are publicly readable without authentication
- Bucket allows public write access (anyone can upload or overwrite files)
- Bucket ACL or IAM policy is publicly readable
- Backup files, database dumps, or credentials are exposed in public buckets
- Application references cloud storage URLs with embedded access keys in the URL

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Public write access to a bucket used by the application | High |
| Sensitive data (credentials, PII, backups) in public bucket | High |
| Public listing of a bucket containing non-public data | High |
| Public read access to a bucket with non-sensitive assets only | Medium |
| Bucket exists and is accessible but empty | Medium |
| Access keys embedded in client-side code referencing buckets | Medium |
| Public bucket used intentionally for public assets (properly scoped) | Low |

## Remediation

- Apply the principle of least privilege to all cloud storage permissions
- Disable public access at the account level where possible:
  - AWS: Enable S3 Block Public Access at the account level
  - Azure: Set the storage account to disallow public blob access
  - GCP: Use uniform bucket-level access and remove `allUsers`/`allAuthenticatedUsers`
- Use IAM policies and bucket policies to control access, not ACLs
- Enable server-side encryption for all stored data
- Enable access logging to monitor who accesses storage resources
- Use signed URLs or presigned URLs for temporary access to private objects
- Regularly audit cloud storage permissions using cloud security tools
- Avoid predictable bucket names that can be enumerated
- Never embed cloud storage access keys in client-side code
- Implement data classification and ensure sensitive data is stored in appropriately restricted buckets

## References

- [OWASP Testing Guide - Test Cloud Storage](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

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

