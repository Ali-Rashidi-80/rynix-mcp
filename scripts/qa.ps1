$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "QA: syncing dev dependencies..."
Set-Location mcp-server
uv sync --group dev
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Location ..

Write-Host "QA: running gateway..."
& .\mcp-server\.venv\Scripts\python.exe .\scripts\run_qa.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "QA: running final_verify..."
& .\mcp-server\.venv\Scripts\python.exe .\scripts\final_verify.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "QA complete."
