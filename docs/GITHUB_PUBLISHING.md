# Publishing Rynix MCP on GitHub

## What is safe to commit

- All source under `mcp-server/`, `rynix-core/`, `profiles/`, `plugins/`, `schemas/`
- Example MCP configs: `cursor-mcp.example.json`, `cursor.posix.json`, `cursor.windows.json` (use `${workspaceFolder}` — no absolute paths)
- Knowledge base (WSTG, technique excerpts)
- Golden tests with **relative** repo paths (`examples/example-law-firm`)

## Never commit

- `pentest_output/` — live probe evidence may include response bodies
- Real passwords, JWTs, `RYNIX_PROBE_PASSWORD*`, production DB dumps
- Per-developer `mcp.json` or `cursor.local.json` with secrets or machine paths
- `bin/template-scan` (users run `scripts/install-template-scan.ps1`)

## Pre-publish verification

```bash
python scripts/scrub_publish_leaks.py
python scripts/verify_github_publish_ready.py
python scripts/final_verify.py
```

## Environment variables (operators only)

| Variable | Purpose |
|----------|---------|
| `RYNIX_TARGET_REPO` | Path to the application repo for scope/live gates |
| `RYNIX_PROFILE` | Optional default profile name (else `generic-fastapi-react` or `.pentest/profile.toml`) |
| `RYNIX_PROBE_PASSWORD` | Mirror/staging test user password |
| `RYNIX_PROBE_PASSWORD_CEO` | CEO test password (if different) |
| `RYNIX_PROBE_USER_*` | Per-role probe usernames |
| `RYNIX_PROBE_ACCOUNTS_FILE` | Optional JSON (see `examples/probe-accounts.example.json`) |
| `RYNIX_PROBE_BASE_URL` | Target base URL |
| `RYNIX_TEMPLATE_SCAN_BIN` | Optional template-scan binary path |
| `RYNIX_STEALTH_GATE_SECRET` | Only when profile defines `[stealth.gate]` |

Credentials are read from the **environment** or MCP `env` block — never from repo source.

## Target app coupling

Rynix ships **bundled profiles** (`generic-fastapi-react`, `example-law-firm` example). Your app keeps:

- `rynix.scope.toml` — `live_probe = false` by default
- `.pentest/profile.toml` — scope/brief overrides (may set `name = "example-law-firm"` or your own profile)
- `.pentest/probe-accounts.json` — gitignored copy of `probe-accounts.example.json`

Optional profile blocks:

- `[auth.captcha]` — enable captcha solving on login probes
- `[stealth.gate]` — production API gate unlock (query param + cookie + secret env)

## Quick public install

```bash
git clone https://github.com/YOUR_ORG/rynix-mcp.git
cd rynix-mcp
./scripts/build.ps1   # or build.sh on Linux
./scripts/verify.ps1
```

Cursor: copy `cursor-mcp.example.json` → `~/.cursor/mcp.json` and adjust paths.

## Stealth / production

When `[stealth.gate]` is configured, external probes may need the gate secret in env before data routes respond. Prefer **local mirror** or an allowlisted staging host for live IDOR matrices.
