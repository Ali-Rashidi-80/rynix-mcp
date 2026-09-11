"""Streamable HTTP MCP server entrypoint."""

from __future__ import annotations

import argparse
import os

from rynix_mcp.server import mcp

_MIN_TOKEN_LEN = 24


def create_mcp():
    """Factory for MCP instance (stdio or HTTP transport)."""
    return mcp


def _require_http_token() -> str:
    token = os.environ.get("RYNIX_SERVE_TOKEN", "").strip()
    if len(token) < _MIN_TOKEN_LEN:
        raise SystemExit(
            f"RYNIX_SERVE_TOKEN must be set to a secret of at least {_MIN_TOKEN_LEN} "
            "characters for HTTP mode"
        )
    return token


def serve(host: str = "0.0.0.0", port: int = 8090) -> None:
    """Run MCP with streamable-http transport and bearer auth."""
    token = _require_http_token()
    os.environ["FASTMCP_SERVER_AUTH_BEARER_TOKEN"] = token
    mcp.run(transport="streamable-http", host=host, port=port)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rynix MCP HTTP server")
    parser.add_argument("--serve", action="store_true", help="Run streamable-http transport")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    if args.serve:
        serve(host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
