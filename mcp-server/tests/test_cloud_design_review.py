from rynix_mcp.cloud_probe import run_cloud_probe
from rynix_mcp.config import ROOT
from rynix_mcp.design_review import run_design_review

FIXTURE_REPO = ROOT / "examples" / "example-law-firm"


def test_cloud_probe_docker_scope():
    result = run_cloud_probe(str(FIXTURE_REPO))
    assert result.get("pass") is True
    assert "scope" in result
    assert "markers" in result


def test_design_review_info_09():
    result = run_design_review("WSTG-INFO-09", str(FIXTURE_REPO))
    assert result.get("probe") == "design_review_physical_social"
    assert result.get("checklist")
