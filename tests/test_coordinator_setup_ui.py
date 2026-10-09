"""Run the shipped JavaScript against isolated DOM/network fakes, never a user's browser."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_saved_state_gate_resume_and_qr_cleanup():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed to exercise the wizard JavaScript')
    result = subprocess.run([node, str(Path(__file__).with_name('setup_ui.mjs'))],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
