"""CI gate — competitor brands must not appear in tracked source."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_no_competitor_brands():
    script = ROOT / "scripts" / "verify_zero_brands.py"
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
