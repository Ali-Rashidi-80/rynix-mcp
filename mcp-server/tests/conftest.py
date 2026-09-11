"""Fresh session store for each test."""

from __future__ import annotations

import pytest
from rynix_mcp.session import STORE


@pytest.fixture(autouse=True)
def fresh_store():
    with STORE._lock:
        STORE._sessions.clear()
    yield
    with STORE._lock:
        STORE._sessions.clear()
