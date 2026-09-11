"""Mint short-lived JWTs for missing mirror roles (local DB only)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from rynix_mcp.target_repo import target_repo_path

PROBE_ROLE_MAP = {
    "admin": "ADMIN",
    "ceo": "CEO",
    "lawyer": "LAWYER",
    "secretary": "SECRETARY",
    "legal_deputy": "LEGAL_DEPUTY",
    "psychologist": "PSYCHOLOGIST",
    "intern": "INTERN",
    "client": "CLIENT",
}


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _load_mirror_db_env(repo: Path) -> None:
    mirror = _read_env_file(repo / ".env.local-mirror")
    for key, value in mirror.items():
        os.environ.setdefault(key, value)


def _backend_python(repo: Path) -> str:
    override = os.environ.get("RYNIX_BACKEND_PYTHON")
    if override:
        return override
    for rel in (
        "backend/.venv/Scripts/python.exe",
        "backend/.venv/bin/python",
    ):
        candidate = repo / rel
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("python") or shutil.which("python3")
    return found or sys.executable


def _mint_via_subprocess(repo: Path, missing_roles: list[str]) -> dict[str, Any]:
    script = repo / "backend" / "scripts" / "mint_ephemeral_probe_tokens.py"
    if not script.is_file():
        raise RuntimeError(f"mint script missing: {script}")
    proc = subprocess.run(
        [_backend_python(repo), str(script), *missing_roles],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=os.environ.copy(),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ephemeral mint failed ({proc.returncode}): {(proc.stderr or proc.stdout)[:500]}"
        )
    return json.loads(proc.stdout)


async def mint_ephemeral_role_tokens(
    roles: tuple[str, ...],
) -> tuple[dict[str, str], list[int]]:
    """Create ephemeral users in mirror DB and return {probe_role: jwt}."""
    repo = target_repo_path(required=True)
    assert repo is not None
    payload = _mint_via_subprocess(repo, list(roles))
    tokens = {k: str(v) for k, v in payload.get("tokens", {}).items()}
    created_ids = [int(x) for x in payload.get("created_ids", [])]
    return tokens, created_ids


async def cleanup_ephemeral_users(user_ids: list[int]) -> None:
    if not user_ids:
        return

    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    repo = target_repo_path(required=True)
    assert repo is not None
    backend = repo / "backend"
    if backend.is_dir() and str(backend) not in sys.path:
        sys.path.insert(0, str(backend))

    from app.models.user import User

    _load_mirror_db_env(repo)
    port = os.getenv("LOCAL_DB_PORT", "5559")
    user = os.getenv("LOCAL_DB_USER", "postgresql")
    password = os.getenv("LOCAL_DB_PASSWORD", "")
    db_name = os.getenv("LOCAL_DB_NAME", os.getenv("POSTGRES_DB", "app"))
    if not password:
        raise RuntimeError("LOCAL_DB_PASSWORD missing — set in target .env.local-mirror")

    url = f"postgresql+asyncpg://{user}:{password}@127.0.0.1:{port}/{db_name}"
    engine = create_async_engine(url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            await session.execute(delete(User).where(User.id.in_(user_ids)))
            await session.commit()
    finally:
        await engine.dispose()


def mint_missing_mirror_tokens(
    missing_roles: list[str],
) -> dict[str, Any]:
    """Sync wrapper — mint JWTs for roles missing from env-based probe accounts."""
    import asyncio

    if not missing_roles:
        return {"tokens": {}, "created_ids": [], "minted_roles": []}
    tokens, created_ids = asyncio.run(mint_ephemeral_role_tokens(tuple(missing_roles)))
    return {"tokens": tokens, "created_ids": created_ids, "minted_roles": list(tokens.keys())}
