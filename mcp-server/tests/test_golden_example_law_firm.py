import json

import pytest
from rynix_mcp.config import ROOT, resolve_scanner_bin
from rynix_mcp.scanner import run_scan

FIXTURE_REPO = ROOT / "examples" / "example-law-firm"
GOLDEN_PATH = ROOT / "tests" / "golden" / "example-law-firm-fixture-scan.json"


def _route_keys(scan: dict) -> set[tuple[str, str, str]]:
    return {
        (r.get("method", ""), r.get("path", ""), r.get("file", "")) for r in scan.get("routes", [])
    }


def _risk_keys(scan: dict) -> set[tuple[str, str]]:
    return {
        (s.get("method", ""), s.get("path", ""))
        for s in scan.get("risk_surfaces", [])
        if "purge" in str(s.get("path", "")).lower()
    }


@pytest.mark.skipif(not FIXTURE_REPO.is_dir(), reason="examples/example-law-firm missing")
@pytest.mark.skipif(
    not resolve_scanner_bin().is_file(),
    reason="rynix-scan release binary not built (run: cargo build --release in rynix-core)",
)
def test_example_law_firm_fixture_scan_matches_golden():
    bin_path = resolve_scanner_bin()
    assert bin_path.is_file(), f"scanner missing: {bin_path}"
    scan = run_scan(FIXTURE_REPO, "example-law-firm")
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8-sig"))

    assert scan["schema"] == golden["schema"]
    assert _route_keys(scan) == _route_keys(golden)
    assert _risk_keys(scan) == _risk_keys(golden)
    assert scan["modules_scanned"] >= golden["modules_scanned"]
    assert any("purge" in s.get("path", "").lower() for s in scan.get("risk_surfaces", []))
