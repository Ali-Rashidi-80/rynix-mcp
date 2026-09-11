# FAQ — Rynix MCP

[Persian / فارسی](FAQ.fa.md)

---

## General

**What does "Rynix" mean?**  
**Rāy** (رای) = judgment / reasoning (host IDE agent). **Nix** = execution (MCP tools, probes, evidence).

**Does Rynix replace my IDE agent?**  
No. Rynix is the **tool layer**. Cursor (or another MCP client) provides LLM reasoning.

**Does Rynix need an OpenAI / Anthropic API key?**  
No external LLM keys. Your IDE agent uses its own model; Rynix runs locally.

---

## Setup

**Which Python version?**  
3.12+ (see `mcp-server/pyproject.toml`).

**Why not `uv run` for MCP on Windows?**  
Cursor reconnect can break `uv run` stdio. Use the dedicated `.venv` interpreter path in `cursor.windows.json`.

**Where is the scanner binary?**  
After `.\scripts\build.ps1`: `rynix-core/target/release/rynix-scan.exe` (or `rynix-scan` on Linux).

---

## Engagement

**How do I enable live probes?**  
1. Set `RYNIX_TARGET_REPO` to your app repo.  
2. Add `rynix.scope.toml` with `live_probe = true` (or pass `allow_live=true` on tool calls).  
3. Pass `scope_check` before probing.

**Where do reports go?**  
`pentest_output/<session_id>/` — gitignored. Contains `findings.json`, `pentest_report.md`, optional SARIF.

**What is `run_idor_matrix`?**  
Automated dual-token HTTP comparisons across profile-defined role pairs, with IDOR signal detection.

---

## Security & publishing

**What must never be committed?**  
`pentest_output/`, real passwords, JWTs, `cursor.local.json`, machine-specific absolute paths.

**How do I verify publish readiness?**  
```powershell
python scripts\verify_github_publish_ready.py
python scripts\final_verify.py
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| MCP tools not listed | Restart MCP; verify `build.ps1` + venv path in config |
| `scope_check` denies | Check `rynix.scope.toml` and `allow_hosts` in profile |
| Scanner not found | Run `cargo build --release` in `rynix-core/` |
| pytest fails on README | Tool count in README must match `@mcp.tool()` in `server.py` |

More: [docs/ONBOARDING.md](docs/ONBOARDING.md) · [docs/GITHUB_PUBLISHING.md](docs/GITHUB_PUBLISHING.md)
