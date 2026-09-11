from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from rynix_mcp.path_safety import safe_evidence_name

MAX_SESSIONS = 128
MAX_AUDIT_ENTRIES = 500
MAX_EVIDENCE_ENTRIES = 200
MAX_FINDINGS_ENTRIES = 1000


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    endpoint: str
    evidence: str
    verified: bool = False
    source_plugin: str = "core"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "verified": self.verified,
            "source_plugin": self.source_plugin,
        }


@dataclass
class SessionState:
    session_id: str
    findings: list[Finding] = field(default_factory=list)
    tokens: dict[str, str] = field(default_factory=dict)
    gate_unlocked: dict[str, bool] = field(default_factory=dict)
    gate_cookies: dict[str, dict[str, str]] = field(default_factory=dict)
    gate_cookie_jar: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    gate_fail_ts: dict[str, float] = field(default_factory=dict)
    probe_usernames: dict[str, str] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    scopes: list[dict[str, str]] = field(default_factory=list)
    wstg_coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    probe_steps: list[dict[str, Any]] = field(default_factory=list)
    audit: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=MAX_AUDIT_ENTRIES))
    evidence: deque[dict[str, str]] = field(
        default_factory=lambda: deque(maxlen=MAX_EVIDENCE_ENTRIES)
    )

    def add_finding(self, finding: Finding) -> bool:
        if len(self.findings) >= MAX_FINDINGS_ENTRIES:
            return False
        self.findings.append(finding)
        return True

    def add_evidence(self, name: str, content: str) -> None:
        self.evidence.append({"name": safe_evidence_name(name), "content": content[:8000]})

    def audit_log(self, event: str, detail: dict[str, Any]) -> None:
        self.audit.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                **detail,
            }
        )


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}

    def get(self, session_id: str | None) -> SessionState:
        sid = session_id or "default"
        with self._lock:
            if sid not in self._sessions:
                if len(self._sessions) >= MAX_SESSIONS:
                    oldest = next(iter(self._sessions))
                    del self._sessions[oldest]
                self._sessions[sid] = SessionState(session_id=sid)
            return self._sessions[sid]


STORE = SessionStore()


def body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def json_field_overlap(a: str, b: str) -> float:
    try:
        obj_a = json.loads(a)
        obj_b = json.loads(b)
    except json.JSONDecodeError:
        return 0.0
    if not isinstance(obj_a, dict) or not isinstance(obj_b, dict):
        return 0.0
    keys_a = set(obj_a.keys())
    keys_b = set(obj_b.keys())
    if not keys_a or not keys_b:
        return 0.0
    return len(keys_a & keys_b) / max(len(keys_a), len(keys_b))


def new_finding_id() -> str:
    return str(uuid.uuid4())
