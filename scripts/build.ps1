$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Building rynix-core (release)..."
Set-Location rynix-core
cargo build --release
Set-Location ..

Write-Host "Syncing Python mcp-server..."
Set-Location mcp-server
uv sync
Set-Location ..

Write-Host "Done. Scanner: rynix-core/target/release/rynix-scan.exe"
