from __future__ import annotations

import re
from pathlib import Path

KNOWLEDGE_ROOT = Path(__file__).resolve().parent
MAX_GUIDE_BYTES = 12_000

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Map common aliases to canonical slug (techniques or flat vuln-class stem).
ALIASES: dict[str, str] = {
    "sqli": "sql-injection",
    "sql": "sql-injection",
    "xss": "cross-site-scripting",
    "cmdi": "os-command-injection",
    "rce": "os-command-injection",
    "ptrav": "path-traversal",
    "lfi": "path-traversal",
    "authn": "authentication",
    "authz": "access-control",
    "bola": "idor",
    "bfla": "broken-function-level-authorization",
    "oauth": "oauth",
    "graphql": "graphql",
}


def _validate_slug(slug: str) -> str:
    """Normalize and validate a knowledge slug."""
    normalized = slug.lower().strip().replace(" ", "-").replace("_", "-")
    canonical = ALIASES.get(normalized, normalized)
    if not _SLUG_RE.match(canonical):
        raise ValueError(f"invalid knowledge slug: {slug!r}")
    return canonical


def _read_md(rel_path: str) -> str | None:
    path = KNOWLEDGE_ROOT / rel_path
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _title_from_md(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
        if stripped.startswith("title:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    return fallback


def list_vuln_classes() -> list[str]:
    stems: set[str] = set()
    vuln_dir = KNOWLEDGE_ROOT / "vuln-classes"
    if vuln_dir.is_dir():
        for path in vuln_dir.glob("*.md"):
            stem = path.stem
            if "--" in stem:
                stems.add(stem.split("--", 1)[1])
            else:
                stems.add(stem)
    for category in (
        "analysis",
        "cloud",
        "coordination",
        "custom",
        "frameworks",
        "reconnaissance",
        "scan_modes",
        "technologies",
        "tooling",
        "protocols",
    ):
        cat_dir = KNOWLEDGE_ROOT / category
        if cat_dir.is_dir():
            for path in cat_dir.glob("*.md"):
                stems.add(path.stem.replace("_", "-"))
    if not stems:
        return ["idor"]
    return sorted(stems)


def get_guide_section(vuln_class: str, heading: str) -> dict:
    """Return a single markdown section from a technique guide (R-48)."""
    guide = get_technique_guide(vuln_class)
    if "error" in guide:
        return guide
    needle = heading.strip().lower()
    if not needle:
        return {
            "error": {
                "code": "INVALID_HEADING",
                "message": "heading is required",
                "retryable": False,
            }
        }
    content = guide.get("content", "")
    lines = content.splitlines()
    section_lines: list[str] = []
    in_section = False
    section_level = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[level:].strip().lower()
            if title == needle or needle in title:
                in_section = True
                section_level = level
                section_lines = [line]
                continue
            if in_section and level <= section_level:
                break
        if in_section:
            section_lines.append(line)
    if not section_lines:
        return {
            "error": {
                "code": "SECTION_NOT_FOUND",
                "message": f"No section matching heading {heading!r}",
                "retryable": False,
            }
        }
    section_text = "\n".join(section_lines).strip()
    raw = section_text.encode("utf-8")
    truncated = len(raw) > MAX_GUIDE_BYTES
    return {
        "vuln_class": vuln_class,
        "heading": heading,
        "content": section_text[:MAX_GUIDE_BYTES],
        "truncated": truncated,
        "total_bytes": len(raw),
        "source": guide.get("source"),
    }


def get_technique_guide(vuln_class: str) -> dict:
    """Load vuln-class guide from knowledge base."""
    try:
        slug = _validate_slug(vuln_class)
    except ValueError as exc:
        return {
            "error": {
                "code": "INVALID_SLUG",
                "message": str(exc),
                "retryable": False,
            }
        }

    candidates = [
        f"techniques/{slug}.md",
        f"vuln-classes/{slug}.md",
        f"vuln-classes/{slug.replace('-', '_')}.md",
    ]
    for category in (
        "analysis",
        "cloud",
        "coordination",
        "custom",
        "frameworks",
        "reconnaissance",
        "scan_modes",
        "technologies",
        "tooling",
        "protocols",
    ):
        candidates.append(f"{category}/{slug}.md")
        candidates.append(f"{category}/{slug.replace('-', '_')}.md")
    if slug in ("template-scan"):
        candidates.append("tools/template-scan/usage.md")
    candidates.extend(
        [
            f"vuln-classes/protocols--{slug}.md",
            f"vuln-classes/technologies--{slug}.md",
            f"vuln-classes/reconnaissance--{slug}.md",
            f"vuln-classes/scan_modes--{slug}.md",
            f"vuln-classes/tooling--{slug}.md",
            f"vuln-classes/analysis--{slug}.md",
            f"vuln-classes/cloud--{slug}.md",
            f"vuln-classes/coordination--{slug}.md",
            f"vuln-classes/custom--{slug}.md",
            f"vuln-classes/frameworks--{slug}.md",
        ]
    )
    for candidate in candidates:
        content = _read_md(candidate)
        if content:
            raw = content.encode("utf-8")
            truncated = len(raw) > MAX_GUIDE_BYTES
            return {
                "vuln_class": vuln_class,
                "title": _title_from_md(content, slug),
                "content": content[:MAX_GUIDE_BYTES],
                "truncated": truncated,
                "total_bytes": len(raw),
                "source": f"knowledge/{candidate}",
            }
    return {
        "error": {
            "code": "NOT_FOUND",
            "message": f"No guide for {vuln_class}. Available: {', '.join(list_vuln_classes()[:20])}",
            "retryable": False,
        }
    }


def search_knowledge(query: str, limit: int = 20) -> dict:
    """Simple title/path-first grep across knowledge markdown files."""
    needle = query.strip().lower()
    if not needle:
        return {"query": query, "matches": [], "count": 0}

    strong: list[dict[str, str]] = []
    weak: list[dict[str, str]] = []
    for path in sorted(KNOWLEDGE_ROOT.rglob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        title = _title_from_md(text, path.stem)
        haystack = f"{title} {path.stem}".lower()
        rel = str(path.relative_to(KNOWLEDGE_ROOT)).replace("\\", "/")
        entry = {"path": rel, "title": title}
        if needle in haystack:
            strong.append(entry)
        elif needle in text[:2000].lower():
            weak.append(entry)

    matches = (strong + weak)[:limit]
    return {"query": query, "matches": matches, "count": len(matches)}


def _find_wstg_file(test_id: str) -> Path | None:
    tid = test_id.upper().strip()
    wstg_dir = KNOWLEDGE_ROOT / "wstg"
    if not wstg_dir.is_dir():
        return None
    direct = list(wstg_dir.rglob(f"{tid}.md"))
    if direct:
        return direct[0]
    for path in wstg_dir.rglob("WSTG-*.md"):
        if path.stem.upper() == tid:
            return path
    return None


def get_wstg_test(test_id: str) -> dict:
    """Load WSTG test doc by ID (e.g. WSTG-APIT-01)."""
    tid = test_id.upper().strip()
    path = _find_wstg_file(tid)
    if path:
        text = path.read_text(encoding="utf-8", errors="ignore")
        raw = text.encode("utf-8")
        truncated = len(raw) > MAX_GUIDE_BYTES
        return {
            "test_id": tid,
            "file": str(path.relative_to(KNOWLEDGE_ROOT)),
            "content": text[:MAX_GUIDE_BYTES],
            "truncated": truncated,
            "total_bytes": len(raw),
        }
    index = _read_md("wstg/README.md")
    if index:
        return {
            "test_id": tid,
            "content": index[:8000],
            "note": f"Test {tid} not found; returning index",
        }
    return {
        "error": {
            "code": "NOT_FOUND",
            "message": f"WSTG test {test_id} not found",
            "retryable": False,
        }
    }


def wstg_test_count() -> int:
    wstg_dir = KNOWLEDGE_ROOT / "wstg"
    if not wstg_dir.is_dir():
        return 0
    return len(list(wstg_dir.rglob("WSTG-*.md")))


def techniques_topic_count() -> int:
    ps = KNOWLEDGE_ROOT / "techniques"
    if not ps.is_dir():
        return 0
    return len([p for p in ps.glob("*.md") if p.name.lower() != "readme.md"])