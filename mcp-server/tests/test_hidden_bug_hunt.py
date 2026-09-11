"""Golden test for hidden bug hunt script output."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HUNT_DIR = ROOT / "pentest_output" / "hidden-bug-hunt"


@pytest.mark.skipif(
    not (HUNT_DIR / "pentest_report.md").is_file(),
    reason="run scripts/hidden_bug_hunt.py locally to generate artifacts",
)
def test_hidden_bug_hunt_artifacts_exist():
    assert (HUNT_DIR / "pentest_report.md").is_file()
    assert (HUNT_DIR / "findings.json").is_file()
    assert (HUNT_DIR / "findings.sarif").is_file()
    text = (HUNT_DIR / "pentest_report.md").read_text(encoding="utf-8")
    assert "localStorage" in text
    assert "purge" in text.lower()
