#!/usr/bin/env python3
"""Remote MCP client example — streamable HTTP transport (Phase E)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def call_tool(base_url: str, token: str, tool: str, arguments: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Rynix remote MCP client example")
    parser.add_argument("--url", default=os.environ.get("RYNIX_MCP_URL", "http://127.0.0.1:8090"))
    parser.add_argument("--token", default=os.environ.get("RYNIX_MCP_TOKEN", ""))
    parser.add_argument("--repo", default=os.environ.get("RYNIX_TARGET_REPO", "."))
    args = parser.parse_args()

    if not args.token:
        print("Set RYNIX_MCP_TOKEN or pass --token", file=sys.stderr)
        return 1

    try:
        health = call_tool(args.url, args.token, "health_check", {})
        print("health_check:", json.dumps(health, indent=2)[:500])
        profiles = call_tool(args.url, args.token, "list_profiles", {})
        print("list_profiles:", json.dumps(profiles, indent=2)[:500])
        scan = call_tool(
            args.url,
            args.token,
            "analyze_repo",
            {"repo_path": args.repo, "profile": "example-law-firm"},
        )
        print("analyze_repo modules:", scan.get("result", scan).get("modules_scanned", "?"))
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='ignore')[:400]}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Connection failed: {exc.reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
