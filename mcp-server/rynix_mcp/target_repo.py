"""Resolve target application repo path from environment (OSS-neutral naming)."""

from __future__ import annotations

import os
from pathlib import Path


def target_repo_env() -> str:
    """Return configured target repo path."""

    return os.environ.get("RYNIX_TARGET_REPO", "").strip()


def target_repo_path(required: bool = True) -> Path | None:

    raw = target_repo_env()

    if not raw:
        if required:
            raise RuntimeError("Set RYNIX_TARGET_REPO to the application repository root.")

        return None

    path = Path(raw).expanduser()

    if not path.is_dir():
        if required:
            raise RuntimeError(f"RYNIX_TARGET_REPO is not a directory: {path}")

        return None

    return path.resolve()


def set_target_repo_env(repo: Path | str) -> None:

    os.environ.setdefault("RYNIX_TARGET_REPO", str(Path(repo).resolve()))


def default_profile_name() -> str | None:
    """Optional default profile from env (None → generic-fastapi-react in load_profile)."""

    name = os.environ.get("RYNIX_PROFILE", "").strip()

    return name or None
