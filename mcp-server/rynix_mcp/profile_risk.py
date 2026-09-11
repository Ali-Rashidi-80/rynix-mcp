"""Profile-driven IDOR/RBAC heuristics (R-69)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_DEFAULT_OBJECT_PATTERN = r"/(cases|clients)/[^/?]+"
_DEFAULT_COLLECTION_MARKERS = ("/cases", "/clients")
_DEFAULT_OFFICE = frozenset({"secretary", "admin", "ceo", "legal_deputy"})
_DEFAULT_ASSIGNED = frozenset({"lawyer", "intern", "psychologist"})
_DEFAULT_AGGREGATES = ("/dashboard/summary", "/finance/cases/summary")
_DEFAULT_ROLE_TRUST = {
    "client": 0,
    "intern": 1,
    "psychologist": 1,
    "lawyer": 2,
    "secretary": 3,
    "legal_deputy": 4,
    "ceo": 5,
    "admin": 6,
}
_DEFAULT_DISCOVERY_ROLES = ("ceo", "admin", "lawyer")
_DEFAULT_LIST_PATHS: list[tuple[str, str]] = [
    ("GET", "/api/v1/cases/"),
    ("GET", "/api/v1/clients/"),
    ("GET", "/api/v1/dashboard/summary"),
    ("GET", "/api/v1/finance/cases/summary"),
]
_DEFAULT_OBJECT_TEMPLATES: list[tuple[str, str]] = [
    ("GET", "/api/v1/cases/{id}"),
    ("GET", "/api/v1/clients/{id}"),
]


@dataclass(frozen=True)
class RiskProfile:
    object_path_re: re.Pattern[str]
    collection_markers: tuple[str, ...]
    office_roles: frozenset[str]
    assigned_roles: frozenset[str]
    shared_aggregates: tuple[str, ...]
    role_trust: dict[str, int]
    discovery_roles: tuple[str, ...]
    list_probe_paths: list[tuple[str, str]]
    object_templates: list[tuple[str, str]]

    def has_object_id_in_path(self, path: str) -> bool:
        normalized = path.split("?", 1)[0]
        return bool(self.object_path_re.search(normalized))

    def is_collection_list_path(self, path: str) -> bool:
        normalized = path.split("?", 1)[0]
        if self.has_object_id_in_path(normalized):
            return False
        return any(marker in normalized for marker in self.collection_markers)

    def is_shared_office_aggregate(self, path: str) -> bool:
        return any(marker in path for marker in self.shared_aggregates)

    def role_trust_level(self, role: str | None) -> int:
        return self.role_trust.get((role or "").lower(), 0)

    def expected_assignment_scoped_rbac(
        self, path: str, role_a: str | None, role_b: str | None
    ) -> bool:
        if not role_a or not role_b:
            return False
        ra = role_a.lower()
        rb = role_b.lower()
        if (
            self.is_collection_list_path(path)
            and ra in self.office_roles
            and rb in self.office_roles
        ):
            return True
        if self.has_object_id_in_path(path) and ra in self.office_roles and rb in self.office_roles:
            return True
        if (
            self.is_shared_office_aggregate(path)
            and ra in self.office_roles
            and rb in self.office_roles
        ):
            return True
        if self.is_collection_list_path(path) and (
            (ra in self.office_roles and rb == "client")
            or (rb in self.office_roles and ra == "client")
        ):
            return True
        if (
            ra in self.office_roles
            and rb in self.assigned_roles
            and self.has_object_id_in_path(path)
        ):
            return True
        return False


def load_risk_profile(prof: dict[str, Any]) -> RiskProfile:
    risk = prof.get("risk") if isinstance(prof.get("risk"), dict) else {}
    pattern = str(risk.get("object_paths_pattern", _DEFAULT_OBJECT_PATTERN))
    collection = tuple(risk.get("collection_markers", list(_DEFAULT_COLLECTION_MARKERS)))
    office = frozenset(str(r).lower() for r in risk.get("office_roles", list(_DEFAULT_OFFICE)))
    assigned = frozenset(
        str(r).lower() for r in risk.get("assigned_roles", list(_DEFAULT_ASSIGNED))
    )
    aggregates = tuple(risk.get("shared_aggregates", list(_DEFAULT_AGGREGATES)))
    trust_raw = risk.get("role_trust", _DEFAULT_ROLE_TRUST)
    role_trust = (
        {str(k).lower(): int(v) for k, v in trust_raw.items()}
        if isinstance(trust_raw, dict)
        else dict(_DEFAULT_ROLE_TRUST)
    )
    discovery = tuple(
        str(r).lower() for r in risk.get("discovery_roles", list(_DEFAULT_DISCOVERY_ROLES))
    )

    list_paths = _DEFAULT_LIST_PATHS
    if isinstance(risk.get("list_probe_paths"), list):
        parsed: list[tuple[str, str]] = []
        for item in risk["list_probe_paths"]:
            if isinstance(item, dict):
                method = str(item.get("method", "GET")).upper()
                path = str(item.get("path", ""))
                if path:
                    parsed.append((method, path))
        if parsed:
            list_paths = parsed

    object_templates = _DEFAULT_OBJECT_TEMPLATES
    if isinstance(risk.get("object_templates"), list):
        parsed_obj: list[tuple[str, str]] = []
        for item in risk["object_templates"]:
            if isinstance(item, dict):
                method = str(item.get("method", "GET")).upper()
                path = str(item.get("path", ""))
                if path:
                    parsed_obj.append((method, path))
        if parsed_obj:
            object_templates = parsed_obj

    return RiskProfile(
        object_path_re=re.compile(pattern),
        collection_markers=collection,
        office_roles=office,
        assigned_roles=assigned,
        shared_aggregates=aggregates,
        role_trust=role_trust,
        discovery_roles=discovery,
        list_probe_paths=list_paths,
        object_templates=object_templates,
    )


_DEFAULT_IDOR_ROLE_PAIRS: list[tuple[str, str]] = [
    ("user", "admin"),
    ("viewer", "editor"),
]


def load_idor_role_pairs(prof: dict[str, Any]) -> list[tuple[str, str]]:
    risk = prof.get("risk") if isinstance(prof.get("risk"), dict) else {}
    raw = risk.get("idor_role_pairs")
    if not isinstance(raw, list):
        return list(_DEFAULT_IDOR_ROLE_PAIRS)
    pairs: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        low = str(item.get("low", "")).strip().lower()
        high = str(item.get("high", "")).strip().lower()
        if low and high and low != high:
            pairs.append((low, high))
    return pairs or list(_DEFAULT_IDOR_ROLE_PAIRS)
