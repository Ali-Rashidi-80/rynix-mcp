---
name: template-scan
title: Rynix template scanner
---

# Template scan usage

Configure `RYNIX_TEMPLATE_SCAN_BIN` or place `bin/template-scan` on PATH.

```text
rynix_plugin_run("template-scan", target_url="https://target.tld", options='{"tags":"cve"}')
```

Output is JSONL merged into session findings via `record_finding`.

## Scope

Run only against in-scope hosts after `scope_check` and `register_scope`.

## Evidence

Include scanner output in finding evidence before `export_report`.
