#!/usr/bin/env python3
"""Generate generic Rynix-named CLI wrappers for docker/rynix-tools sidecar."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "docker" / "rynix-tools" / "bin"
MANIFEST = ROOT / "docker" / "rynix-tools" / "tools-manifest.toml"

# name -> shell body (uses alpine: curl, jq, python3)
TOOLS: dict[str, str] = {
    "rynix-http-probe": '#!/bin/sh\nexec curl -sS -o /dev/null -w "%{http_code}" "$@"\n',
    "rynix-fuzz": '#!/bin/sh\necho "rynix-fuzz: supply wordlist via MCP http_probe batch" >&2\nexit 0\n',
    "rynix-sqli-probe": '#!/bin/sh\necho "rynix-sqli-probe: use MCP sqli_probe plugin" >&2\nexit 0\n',
    "rynix-cors-probe": '#!/bin/sh\n# CORS preflight probe\nORIGIN="${1:-https://evil.example}"\nURL="${2:?url}"\ncurl -sS -o /dev/null -w "%{http_code}" -X OPTIONS -H "Origin: $ORIGIN" -H "Access-Control-Request-Method: GET" "$URL"\n',
    "rynix-header-probe": '#!/bin/sh\nexec curl -sS -I "$@"\n',
    "rynix-tls-probe": '#!/bin/sh\nexec curl -sS -I --tlsv1.2 "$@" 2>/dev/null || curl -sS -I "$@"\n',
    "rynix-dns-probe": '#!/bin/sh\nexec nslookup "$@" 2>/dev/null || echo "no nslookup"\n',
    "rynix-robots-fetch": '#!/bin/sh\nBASE="${1:?base}"\ncurl -sS "${BASE%/}/robots.txt"\n',
    "rynix-sitemap-fetch": '#!/bin/sh\nBASE="${1:?base}"\ncurl -sS "${BASE%/}/sitemap.xml"\n',
    "rynix-openapi-fetch": '#!/bin/sh\nBASE="${1:?base}"\nfor p in /openapi.json /api/openapi.json /swagger.json /v3/api-docs; do curl -sf "${BASE%/}$p" && exit 0; done\nexit 1\n',
    "rynix-json-probe": '#!/bin/sh\nexec curl -sS -H "Content-Type: application/json" "$@"\n',
    "rynix-jwt-decode": "#!/bin/sh\npython3 -c \"import sys,base64,json; t=sys.argv[1].split('.')[1]; pad='='*(-len(t)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(t+pad)),indent=2))\" \"$1\"\n",
    "rynix-base64": '#!/bin/sh\nexec python3 -c "import sys,base64; d=sys.stdin.read(); print(base64.b64encode(d.encode()).decode())"\n',
    "rynix-url-encode": '#!/bin/sh\nexec python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))" "$1"\n',
    "rynix-graphql-introspect": '#!/bin/sh\nURL="${1:?url}"\ncurl -sS -X POST -H "Content-Type: application/json" -d \'{"query":"{ __schema { queryType { name } } }"}\' "$URL"\n',
    "rynix-websocket-probe": '#!/bin/sh\necho "rynix-websocket-probe: use MCP http_probe + browser-debug plugin" >&2\nexit 0\n',
    "rynix-ssrf-canary": '#!/bin/sh\necho "rynix-ssrf-canary: pass OOB callback URL via MCP record_finding" >&2\nexit 0\n',
    "rynix-dirb-lite": '#!/bin/sh\nBASE="${1:?base}"\nfor p in /admin /api /api/v1 /health /login /docs /swagger /redoc; do printf "%s " "$p"; curl -sS -o /dev/null -w "%{http_code}" "${BASE%/}$p"; echo; done\n',
    "rynix-rate-limit-probe": '#!/bin/sh\nURL="${1:?url}"\nfor i in $(seq 1 15); do curl -sS -o /dev/null -w "%{http_code}\\n" "$URL"; done\n',
    "rynix-response-diff": '#!/bin/sh\nA="${1:?url_a}"; B="${2:?url_b}"\ncurl -sS "$A" | sha256sum; curl -sS "$B" | sha256sum\n',
    "rynix-crawl": '#!/bin/sh\nBASE="${1:?base}"\nfor p in / /api /api/v1 /health /login; do echo "== $p"; curl -sS -o /dev/null -w "%{http_code}" "${BASE%/}$p"; echo; done\n',
    "rynix-semgrep-lite": '#!/bin/sh\necho "rynix-semgrep-lite: use MCP analyze_repo static scan" >&2\nexit 0\n',
    "rynix-subdomain-brute": '#!/bin/sh\necho "rynix-subdomain-brute: use scope_check + passive recon" >&2\nexit 0\n',
    "rynix-file-fuzz": '#!/bin/sh\necho "rynix-file-fuzz: use fuzz-cli via MCP" >&2\nexit 0\n',
    "rynix-jwt-alg-none": '#!/bin/sh\necho "rynix-jwt-alg-none: test via compare_role_response with tampered JWT" >&2\nexit 0\n',
    "rynix-nikto-lite": '#!/bin/sh\nURL="${1:?url}"\ncurl -sS -I "$URL" | grep -iE "server|x-powered|asp|php|nginx|apache" || true\n',
}


def main() -> int:
    BIN.mkdir(parents=True, exist_ok=True)
    lines = ["# Rynix tools sidecar manifest", f"count = {len(TOOLS)}", ""]
    for name in sorted(TOOLS):
        path = BIN / name
        body = TOOLS[name]
        if not body.endswith("\n"):
            body += "\n"
        path.write_text(body, encoding="utf-8")
        lines.append("[[tool]]")
        lines.append(f'name = "{name}"')
        lines.append(f'path = "bin/{name}"')
        lines.append("")
        print(f"wrote {name}")
    MANIFEST.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"manifest {len(TOOLS)} tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
