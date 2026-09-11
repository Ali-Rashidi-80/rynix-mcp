from __future__ import annotations

import os
import re
from pathlib import Path

from rynix_mcp.config import ROOT

_PENTEST_OUTPUT = ROOT / "pentest_output"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


_MAX_SARIF_BYTES = 5 * 1024 * 1024
_SARIF_INPUT_DIRS_ENV = "RYNIX_SARIF_INPUT_DIRS"


def safe_sarif_input_path(raw: str) -> Path:
    """Resolve SARIF import path under allowed directories (default: pentest_output)."""
    if not raw or not str(raw).strip():
        raise ValueError("sarif_path is required")
    if "\x00" in raw:
        raise ValueError("sarif_path contains null byte")

    candidate = Path(raw.strip())
    allowed_roots: list[Path] = [_PENTEST_OUTPUT.resolve()]
    extra = os.environ.get(_SARIF_INPUT_DIRS_ENV, "").strip()
    if extra:
        for part in extra.split(os.pathsep):
            part = part.strip()
            if part:
                allowed_roots.append(Path(part).resolve())

    resolved = candidate.resolve() if candidate.is_absolute() else None
    if resolved is None:
        for root in allowed_roots:
            try:
                resolved = (root / candidate).resolve()
                resolved.relative_to(root)
                break
            except ValueError:
                resolved = None
                continue
    if resolved is None or not resolved.is_file():
        raise ValueError("sarif_path must be an existing file under allowed import dirs")

    if resolved.stat().st_size > _MAX_SARIF_BYTES:
        raise ValueError(f"sarif file exceeds {_MAX_SARIF_BYTES} bytes")

    for root in allowed_roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise ValueError("sarif_path escapes allowed import directories")


def safe_evidence_name(name: str) -> str:
    """Sanitize evidence filenames; blocks path traversal on all platforms."""
    cleaned = _SAFE_NAME.sub("_", name.replace("\\", "_").replace("/", "_")).strip("._")
    return (cleaned or "evidence")[:80]


def resolve_export_output_dir(output_dir: str) -> Path:
    """Resolve export path; must stay under repo pentest_output/."""
    if not output_dir or not output_dir.strip():
        raise ValueError("output_dir is required")
    if "\x00" in output_dir:
        raise ValueError("output_dir contains null byte")

    raw = Path(output_dir)
    base = _PENTEST_OUTPUT.resolve()
    base.mkdir(parents=True, exist_ok=True)

    resolved = raw.resolve() if raw.is_absolute() else (base / raw).resolve()

    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError(f"output_dir must stay under {base}") from None

    return resolved


def resolve_evidence_path(evidence_dir: Path, name: str) -> Path:
    """Write evidence only inside evidence_dir."""
    safe = safe_evidence_name(name)
    if not safe.endswith(".txt"):
        safe = f"{safe}.txt"
    ev_path = (evidence_dir / safe).resolve()
    base = evidence_dir.resolve()
    if ev_path.parent != base:
        raise ValueError(f"evidence name escapes sandbox: {name!r}")
    return ev_path
