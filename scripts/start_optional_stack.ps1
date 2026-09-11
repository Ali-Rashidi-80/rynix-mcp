# Start optional agent-orchestrator + browser-debug docker stacks (requires Docker Desktop)
# Plugins agent-orchestrator.toml / browser-debug.toml ship with enabled=false — opt in after stacks are healthy.
#   $env:RYNIX_TOOLS_ROOT = "C:\path\to\pentest-tools"
#   .\scripts\start_optional_stack.ps1
$ErrorActionPreference = "Stop"

$Tools = $env:RYNIX_TOOLS_ROOT
if (-not $Tools) {
    Write-Error "Set RYNIX_TOOLS_ROOT to your Rynix optional tools directory"
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker not found - install Docker Desktop first"
}

$agent-orchestrator = Join-Path $Tools "agent-orchestrator\agent-orchestrator-main\agent-orchestrator-main"
$browser-debug = Join-Path $Tools "browser-debug\browser-debug-master\browser-debug-master"

function Start-Stack($Name, $Dir) {
    if (-not (Test-Path (Join-Path $Dir "docker-compose.yml"))) {
        Write-Warning "$Name compose file missing at $Dir — clone/sync Pentest Tools first"
        return $false
    }
    Write-Host "Starting $Name ..."
    Push-Location $Dir
    docker compose up -d
    Pop-Location
    return $true
}

$started = @()
if (Start-Stack "agent-orchestrator" $agent-orchestrator) { $started += "agent-orchestrator" }
if (Start-Stack "browser-debug" $browser-debug) { $started += "browser-debug" }

if ($started.Count -eq 0) {
    Write-Warning "No optional stacks started. Set RYNIX_TOOLS_ROOT and ensure compose files exist."
    exit 1
}

Write-Host ""
Write-Host "Started: $($started -join ', ')"
Write-Host "Health URLs:"
Write-Host "  agent-orchestrator:   https://127.0.0.1:8443  (RYNIX_AGENT_ORCHESTRATOR_URL)"
Write-Host "  browser-debug: http://127.0.0.1:9222/json/version (RYNIX_browser-debug_URL)"
Write-Host ""
Write-Host "Next: set enabled=true in plugins/agent-orchestrator.toml or plugins/browser-debug.toml if delegates are required."