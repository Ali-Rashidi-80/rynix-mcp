"""Design-review artifacts for WSTG tests without live physical/social PoC."""

from __future__ import annotations

from typing import Any

from rynix_mcp.cloud_probe import run_cloud_probe

PHYSICAL_SOCIAL_TESTS = frozenset(
    {
        "WSTG-INFO-09",
        "WSTG-INFO-10",
        "WSTG-BUSL-09",
        "WSTG-BUSL-10",
    }
)

CHECKLIST = {
    "WSTG-INFO-09": [
        "Search engine indexing policy documented",
        "robots.txt / noindex on admin surfaces",
        "No sensitive data in public marketing pages",
    ],
    "WSTG-INFO-10": [
        "Application architecture diagram available",
        "Trust boundaries between client/API/DB documented",
        "Third-party integrations inventoried",
    ],
    "WSTG-BUSL-09": [
        "Upload file type validation server-side",
        "Malware scan or size limits on attachments",
        "Storage path not directly web-accessible",
    ],
    "WSTG-BUSL-10": [
        "Business workflow authorization per role",
        "State transitions require appropriate role",
        "No client-side-only approval gates",
    ],
}


def run_design_review(
    test_id: str, repo_path: str | None, static_scan: dict[str, Any] | None = None
) -> dict[str, Any]:
    tid = test_id.upper()
    cloud = run_cloud_probe(repo_path)
    checklist = CHECKLIST.get(
        tid, ["Manual design review — no automated PoC for physical/social vectors"]
    )
    rbac_rows = len((static_scan or {}).get("rbac_hints", []))
    routes = len((static_scan or {}).get("routes", []))

    return {
        "test_id": tid,
        "status": "executed",
        "probe": "design_review_physical_social",
        "pass": None,
        "manual_review": True,
        "checklist": checklist,
        "evidence": {
            "cloud_posture": cloud,
            "rbac_hints": rbac_rows,
            "api_routes": routes,
            "static_modules": (static_scan or {}).get("modules_scanned"),
        },
        "note": "Automated design review + static evidence; physical/social PoC requires on-site engagement",
    }


def is_physical_social_test(test_id: str) -> bool:
    return test_id.upper() in PHYSICAL_SOCIAL_TESTS
