# Install template-scan CLI for Rynix plugin
# Rynix does not download third-party scanner binaries from external vendors.
# Build or obtain template-scan separately, then point RYNIX_TEMPLATE_SCAN_BIN at it.
$ErrorActionPreference = "Stop"

$binDir = Join-Path $PSScriptRoot "..\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$existing = Join-Path $binDir "template-scan.exe"
if (Test-Path $existing) {
    Write-Host "OK: $existing"
    Write-Host "Set in Cursor MCP env: RYNIX_TEMPLATE_SCAN_BIN=$existing"
    exit 0
}

Write-Host "Place your template-scan binary at:" -ForegroundColor Yellow
Write-Host "  $existing"
Write-Host "Then set: `$env:RYNIX_TEMPLATE_SCAN_BIN = '$existing'"
exit 1
