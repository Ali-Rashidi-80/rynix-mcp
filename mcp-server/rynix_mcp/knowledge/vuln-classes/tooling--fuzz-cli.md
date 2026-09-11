---
name: fuzz-cli
description: fuzz-cli fuzzing syntax with matcher/filter strategy and non-interactive defaults.
---

# fuzz-cli CLI Playbook

Official docs:
- https://github.com/fuzz-cli/fuzz-cli

Canonical syntax:
`fuzz-cli -w <wordlist> -u <url_with_FUZZ> [flags]`

High-signal flags:
- `-u <url>` target URL containing `FUZZ`
- `-w <wordlist>` wordlist input (supports `KEYWORD` mapping via `-w file:KEYWORD`)
- `-mc <codes>` match status codes
- `-fc <codes>` filter status codes
- `-fs <size>` filter by body size
- `-ac` auto-calibration
- `-t <n>` threads
- `-rate <n>` request rate
- `-timeout <seconds>` HTTP timeout
- `-x <proxy_url>` upstream proxy (HTTP/SOCKS)
- `-ignore-body` skip downloading response body
- `-noninteractive` disable interactive console mode
- `-recursion` and `-recursion-depth <n>` recursive discovery
- `-H <header>` custom headers
- `-X <method>` and `-d <body>` for non-GET fuzzing
- `-o <file> -of <json|ejson|md|html|csv|ecsv>` structured output

Agent-safe baseline for automation:
`fuzz-cli -w wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o fuzz-cli.json`

Common patterns:
- Basic path fuzzing:
  `fuzz-cli -w /path/wordlist.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive`
- Vhost fuzzing:
  `fuzz-cli -w vhosts.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -noninteractive`
- Parameter value fuzzing:
  `fuzz-cli -w values.txt -u 'https://target.tld/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive`
- POST body fuzzing:
  `fuzz-cli -w payloads.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -noninteractive`
- Recursive discovery:
  `fuzz-cli -w dirs.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive`
- Proxy-instrumented run:
  `fuzz-cli -w wordlist.txt -u https://target.tld/FUZZ -x http://127.0.0.1:48080 -mc 200,301,302,403 -ac -noninteractive`

Critical correctness rules:
- `FUZZ` must appear exactly at the mutation point in URL/header/body.
- If using `-w file:KEYWORD`, that same `KEYWORD` must be present in URL/header/body.
- Always include `-noninteractive` in agent/script execution to prevent fuzz-cli console mode from swallowing subsequent shell commands.
- Save structured output with `-of json -o <file>` for deterministic parsing.

Usage rules:
- Prefer explicit matcher/filter strategy (`-mc`/`-fc`/`-fs`) over default-only output.
- Start conservative (`-rate`, `-t`) and scale only if target tolerance is known.
- Do not use `-h`/`--help` during normal execution unless absolutely necessary.

Failure recovery:
- If fuzz-cli drops into interactive mode, send `C-c` and rerun with `-noninteractive`.
- If response noise is too high, tighten `-mc/-fc/-fs` instead of increasing load.
- If runtime is too long, lower `-rate/-t` and tighten scope.

If uncertain, query get_technique_guide with:
`site:github.com/fuzz-cli/fuzz-cli <flag> README`

Alternate tool for path/file enumeration: `dirsearch -u <url> -e php,html,js,json`
ships with curated wordlists, sane defaults, and built-in recursion. Reach
for fuzz-cli when you need surgical fuzzing of any input position (header,
body, vhost) or precise filter control; reach for dirsearch for a quick
broad sweep with no setup.
