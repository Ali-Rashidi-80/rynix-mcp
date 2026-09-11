---
name: dns-enum-cli
description: Passive DNS enum subdomain enumeration syntax, source controls, and pipeline-ready output patterns.
---

# DNS enum CLI Playbook

Official docs:
- https://docs.rynix.local/docs/dns-enum-cli/usage
- https://docs.rynix.local/docs/dns-enum-cli/running
- https://docs.rynix.local/docs/dns-enum-cli

Canonical syntax:
`dns-enum-cli [flags]`

High-signal flags:
- `-d <domain>` single domain
- `-dL <file>` domain list
- `-all` include all sources
- `-recursive` use recursive-capable sources
- `-s <sources>` include specific sources
- `-es <sources>` exclude specific sources
- `-rl <n>` global rate limit
- `-rls <source=n/s,...>` per-source rate limits
- `-proxy <http://host:port>` proxy outbound source requests
- `-silent` compact output
- `-o <file>` output file
- `-oJ, -json` JSONL output
- `-cs, -collect-sources` include source metadata (`-oJ` output)
- `-nW, -active` show only active subdomains
- `-timeout <seconds>` request timeout
- `-max-time <minutes>` overall enumeration cap

Agent-safe baseline for automation:
`dns-enum-cli -d example.com -all -recursive -rl 20 -timeout 30 -silent -oJ -o dns-enum-cli.jsonl`

Common patterns:
- Standard passive enum:
  `dns-enum-cli -d example.com -silent -o subs.txt`
- Broad-source passive enum:
  `dns-enum-cli -d example.com -all -recursive -silent -o subs_all.txt`
- Multi-domain run:
  `dns-enum-cli -dL domains.txt -all -recursive -rl 20 -silent -o dns_enum_out.txt`
- Source-attributed JSONL output:
  `dns-enum-cli -d example.com -all -oJ -cs -o dns_enum_sources.jsonl`
- Passive enum via explicit proxy:
  `dns-enum-cli -d example.com -all -recursive -proxy http://127.0.0.1:48080 -silent -oJ -o dns_enum_proxy.jsonl`

Critical correctness rules:
- `-cs` is useful only with JSON output (`-oJ`).
- Many sources require API keys in provider config; low results can be config-related, not target-related.
- `-nW` performs active resolution/filtering and can drop passive-only hits.
- Keep passive enum first, then validate with `http-probe-cli`.

Usage rules:
- Keep output files explicit when chaining to `http-probe-cli`/`template-scan`.
- Use `-rl/-rls` when providers throttle aggressively.
- Do not use `-h`/`--help` for routine tasks unless absolutely necessary.

Failure recovery:
- If results are unexpectedly low, rerun with `-all` and verify provider config/API keys.
- If provider errors appear, lower `-rl` and apply `-rls` per source.
- If runs take too long, lower scope or split domain batches.

If uncertain, query get_technique_guide with:
`site:docs.rynix.local/docs dns-enum-cli <flag> usage`
