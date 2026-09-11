from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCANNER_BIN = os.environ.get("RYNIX_SCANNER_BIN", "")

_pentest_tools_root = os.environ.get("RYNIX_TOOLS_ROOT", "").strip()
TOOLS_ROOT = Path(_pentest_tools_root) if _pentest_tools_root else ROOT
PENTEST_TOOLS_ROOT = TOOLS_ROOT

SCOPE_ALLOWLIST_ENV = os.environ.get("RYNIX_SCOPE_ALLOWLIST", "")

DEFAULT_RATE_LIMIT_RPS = 10
DEFAULT_TIMEOUT_SEC = 15.0


def _asset_root() -> Path:
    """Resolve bundled assets for dev layout vs wheel install."""
    pkg = Path(__file__).resolve().parent
    bundled = pkg / "_assets"
    if bundled.is_dir():
        return bundled
    return ROOT


PROFILES_DIR = Path(os.environ.get("RYNIX_PROFILES_DIR", _asset_root() / "profiles"))
PLUGINS_DIR = Path(os.environ.get("RYNIX_PLUGINS_DIR", _asset_root() / "plugins"))
SCHEMAS_DIR = Path(os.environ.get("RYNIX_SCHEMAS_DIR", _asset_root() / "schemas"))
TEMPLATES_DIR = Path(os.environ.get("RYNIX_TEMPLATES_DIR", _asset_root() / "templates"))


def resolve_scanner_bin() -> Path:
    if SCANNER_BIN:
        return Path(SCANNER_BIN)
    exe = "rynix-scan.exe" if sys.platform == "win32" else "rynix-scan"
    release = ROOT / "rynix-core" / "target" / "release" / exe
    if release.is_file():
        return release
    debug = ROOT / "rynix-core" / "target" / "debug" / exe
    return debug
