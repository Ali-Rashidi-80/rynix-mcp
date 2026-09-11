@echo off
REM Stable MCP launcher — avoids uv reinstall locking rynix-mcp.exe on Windows (os error 32).
set "ROOT=%~dp0.."
cd /d "%ROOT%\mcp-server"
if not exist ".venv\Scripts\python.exe" (
  echo rynix-mcp: run scripts\build.ps1 first >&2
  exit /b 1
)
"%ROOT%\mcp-server\.venv\Scripts\python.exe" -m rynix_mcp
