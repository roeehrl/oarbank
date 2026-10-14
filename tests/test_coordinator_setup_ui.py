"""Run the shipped JavaScript against isolated DOM/network fakes, never a user's browser."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_saved_state_gate_resume_and_qr_cleanup():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed to exercise the wizard JavaScript')
    # The script drives fake timers and finishes in well under a second; the deadline only bounds a stuck run. It is
    # generous because a loaded Windows runner (antivirus scanning node.exe, parallel workers) can take tens of
    # seconds just to start Node.
    try:
        result = subprocess.run([node, str(Path(__file__).with_name('setup_ui.mjs'))],
                                capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as e:
        pytest.fail(f'setup_ui.mjs did not finish within {e.timeout} s; output so far:\n'
                    f'{e.stdout or ""}{e.stderr or ""}')
    assert result.returncode == 0, result.stdout + result.stderr
