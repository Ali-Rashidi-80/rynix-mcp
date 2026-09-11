#!/usr/bin/env python3
"""Phase C — scrub Burp/corscanner and other proxy-tool brands from knowledge."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "mcp-server" / "rynix_mcp" / "knowledge"

# Order matters: longer phrases first.
REPLACEMENTS: list[tuple[str, str]] = [
    ("Burp's active scanner", "the template-scan plugin"),
    ("Burp's scanner", "the template-scan plugin"),
    ("Burp active scanner", "the template-scan plugin"),
    ("Burp Scanner", "the template-scan plugin"),
    ("Burp Suite", "Rynix http_probe session"),
    ("Burp Collaborator", "OOB callback probe"),
    ("Burp Intruder", "fuzz-cli parameter sweep"),
    ("Turbo Intruder", "parallel http_probe batch"),
    ("Burp Repeater", "http_probe replay"),
    ("Burp extension", "Rynix plugin"),
    ("Burp Pro", "template-scan"),
    ("Burp proxy", "HTTP proxy"),
    ("Burp Issues", "record_finding evidence"),
    ("Burp Community", "template-scan"),
    ("Burp >", ""),
    ("in Burp", "via http_probe"),
    ("through Burp", "through HTTP proxy"),
    ("Use Burp", "Use http_probe"),
    ("use Burp", "use http_probe"),
    ("Burp will", "http_probe will"),
    ("Burp has", "template-scan has"),
    ("Burp ", "Rynix "),  # residual single-word refs
    ("corscanner", "cors-probe"),
    ("CORScanner", "cors-probe"),
    ("DOM Invader", "browser-debug plugin"),
    ("Param Miner", "header-fuzz probe"),
    ("InQL (Burp Extension + CLI)", "graphql probe via analyze_repo"),
    ("Burp's", "Rynix's"),
    ("(Burp)", "(http_probe)"),
    ("BURP-COLLABORATOR", "OOB-CALLBACK"),
    ("burpcollaborator", "oob-callback"),
    ("Engine.BURP2", "Engine.HTTP2"),
    ("InQL", "graphql probe"),
]

BANNED_AFTER = re.compile(
    r"\bBurp\b|\bcorscanner\b|\bCORScanner\b|Burp's|portswigger",
    re.IGNORECASE,
)


def scrub_text(text: str) -> tuple[str, int]:
    count = 0
    for old, new in REPLACEMENTS:
        if old in text:
            n = text.count(old)
            text = text.replace(old, new)
            count += n
    return text, count


def main() -> int:
    total = 0
    for path in KNOWLEDGE.rglob("*.md"):
        original = path.read_text(encoding="utf-8")
        updated, n = scrub_text(original)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            print(f"{path.relative_to(ROOT)}: {n}")
            total += n

    # quality-gates checklist
    qg = KNOWLEDGE / "quality" / "quality-gates.md"
    if qg.is_file():
        text = qg.read_text(encoding="utf-8")
        text = text.replace("cors-probe tool run", "cors-probe via http_probe")
        qg.write_text(text, encoding="utf-8")

    remaining: list[str] = []
    for path in KNOWLEDGE.rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if BANNED_AFTER.search(text):
            remaining.append(str(path.relative_to(ROOT)))

    print(f"scrubbed {total} replacements in knowledge")
    if remaining:
        print(f"FAIL {len(remaining)} files still contain banned refs:", file=sys.stderr)
        for line in remaining[:30]:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("PASS knowledge brand scrub")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
