$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "G1: cargo test"
Set-Location rynix-core
cargo test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Location ..

Write-Host "G1b: cargo build --release (scanner for profile --config)"
Set-Location rynix-core
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Location ..

Write-Host "G2: pytest (full suite)"
Set-Location mcp-server
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Location ..

Write-Host "G3: MCP tool gate"
Set-Location mcp-server
& .\.venv\Scripts\python.exe -m pytest tests/test_mcp_tools.py tests/test_mcp_list_profiles.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Location ..

Write-Host "G4: MCP self-audit"
& .\mcp-server\.venv\Scripts\python.exe .\scripts\mcp_self_audit.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "G9: contract evidence"
& .\mcp-server\.venv\Scripts\python.exe .\scripts\run_contract.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Verify complete."
