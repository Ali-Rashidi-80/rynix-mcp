#!/usr/bin/env python3
"""Bootstrap mirror probe env from DB + .env.local-mirror, then run comprehensive audit."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))
sys.path.insert(0, str(ROOT / "scripts"))

from rynix_mcp.target_repo import set_target_repo_env
from target_env import require_target_repo

REPO = require_target_repo()


def _read_env(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


async def _mirror_usernames() -> dict[str, str]:
    _read_env(REPO / ".env.local-mirror")
    backend = REPO / "backend"
    sys.path.insert(0, str(backend))
    from app.models.user import User, UserRole
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    port = os.getenv("LOCAL_DB_PORT", "5559")
    user = os.getenv("LOCAL_DB_USER", "postgresql")
    pwd = os.getenv("LOCAL_DB_PASSWORD", "")
    db_name = os.getenv("LOCAL_DB_NAME", "local_db")
    url = f"postgresql+asyncpg://{user}:{pwd}@127.0.0.1:{port}/{db_name}"
    engine = create_async_engine(url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    out: dict[str, str] = {}
    async with session_factory() as session:
        for role in UserRole:
            result = await session.execute(
                select(User).where(User.role == role, User.is_active.is_(True)).limit(1)
            )
            row = result.scalar_one_or_none()
            if row and row.username:
                out[role.value.lower()] = row.username
    await engine.dispose()
    return out


def main() -> int:
    set_target_repo_env(REPO)
    os.environ.setdefault("RYNIX_TARGET_REPO", str(REPO))
    os.environ.setdefault("RYNIX_PROBE_BASE_URL", "http://127.0.0.1:8001")
    _read_env(REPO / ".env.local-mirror")

    if not os.environ.get("RYNIX_PROBE_PASSWORD"):
        print("RYNIX_PROBE_PASSWORD is required", file=sys.stderr)
        return 1
    if not os.environ.get("RYNIX_PROBE_PASSWORD_CEO"):
        # CEO password often differs on mirror; try common seed default then env file value.
        os.environ.setdefault(
            "RYNIX_PROBE_PASSWORD_CEO", os.environ.get("RYNIX_PROBE_PASSWORD", "")
        )

    users = asyncio.run(_mirror_usernames())
    env_map = {
        "client": "RYNIX_PROBE_USER_CLIENT",
        "ceo": "RYNIX_PROBE_USER_CEO",
        "lawyer": "RYNIX_PROBE_USER_LAWYER",
        "secretary": "RYNIX_PROBE_USER_SECRETARY",
        "intern": "RYNIX_PROBE_USER_INTERN",
        "admin": "RYNIX_PROBE_USER_ADMIN",
        "legal_deputy": "RYNIX_PROBE_USER_LEGAL_DEPUTY",
        "psychologist": "RYNIX_PROBE_USER_PSYCHOLOGIST",
    }
    for role, env_key in env_map.items():
        if not os.environ.get(env_key) and role in users:
            os.environ[env_key] = users[role]

    accounts_file = REPO / ".pentest" / "probe-accounts.json"
    if accounts_file.is_file():
        os.environ.setdefault("RYNIX_PROBE_ACCOUNTS_FILE", str(accounts_file))

    script = ROOT / "scripts" / "comprehensive_role_audit.py"
    proc = subprocess.run(
        ["uv", "run", "--directory", str(ROOT / "mcp-server"), "python", str(script)],
        cwd=str(ROOT),
        env=os.environ,
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
