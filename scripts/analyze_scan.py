#!/usr/bin/env python3
"""Multi-pass analysis of rynix-scan JSON output."""

import json
import sys
from collections import Counter
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/golden/example-law-firm-scan.json")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    print(
        f"modules={data['modules_scanned']} routes={len(data['routes'])} risks={len(data['risk_surfaces'])}"
    )
    print("by_rule", dict(Counter(s["rule_id"] for s in data["risk_surfaces"])))
    high_idor = [r for r in data["routes"] if r.get("idor_risk_score", 0) >= 80]
    print(f"high_idor_routes={len(high_idor)}")
    for r in sorted(high_idor, key=lambda x: -x["idor_risk_score"])[:15]:
        print(
            f"  {r['method']:6} {r['path'][:60]:60} "
            f"score={r['idor_risk_score']} auth={r['auth_required']} {r['file']}"
        )
    no_auth_id = [
        r
        for r in data["routes"]
        if "{" in r.get("path", "")
        and not r.get("auth_required")
        and r.get("method") in ("GET", "PATCH", "PUT", "DELETE")
    ]
    print(f"no_auth_param_routes={len(no_auth_id)}")
    for r in no_auth_id[:10]:
        print(f"  !! {r['method']} {r['path']} {r['file']}:{r['line']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
