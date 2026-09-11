# Install Playwright browser probes for Rynix MCP
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location "$Root\mcp-server"
uv sync --group browser
uv run playwright install chromium
Write-Host "Playwright ready. Re-run full_suite_engagement.py to include DOM XSS probes."
