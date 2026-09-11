# Rynix MCP — VPS / streamable HTTP deploy

## Run locally

```powershell
cd rynix-mcp/mcp-server
$env:RYNIX_SERVE_TOKEN = "your-bearer-token"
uv run python -m rynix_mcp.serve --serve --host 0.0.0.0 --port 8090
```

## Docker

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Set `RYNIX_SERVE_TOKEN` in `deploy/.env` before starting.

## Remote MCP client

Point your MCP client at `http://<host>:8090/mcp` with header:

```
Authorization: Bearer <RYNIX_SERVE_TOKEN>
```
