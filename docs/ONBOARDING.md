# Rynix MCP Onboarding

## 1. Build

```powershell
cd rynix-mcp
.\scripts\build.ps1
```

## 2. Configure Cursor MCP

Copy `cursor.windows.json` or `cursor.posix.json` into your MCP settings.

## 3. Target application

In your app repo:

- `rynix.scope.toml` — scope and `allow_live`
- `.pentest/profile.toml` — `name = "example-law-firm"` or stack profile

## 4. Engagement flow

```text
health_check → analyze_repo → register_scope → agent_engagement_playbook
→ http_probe / run_idor_matrix → record_finding(verified=True) → export_report
```

## 5. Runtime parity plugins

Nine plugins map to scanner, WSTG, guides, engagement, whitebox, pipeline, range, orchestrator, browser-debug.
See `parity_matrix.toml` and `docs/HOST_AGENT_RUNTIME.md`.

## 6. Verify

```powershell
python scripts/final_verify.py
```

## Multi-stack

`stack_detect.py` + `stacks/manifest.toml` — 51 frameworks with Tier 1 dedicated extractors.
