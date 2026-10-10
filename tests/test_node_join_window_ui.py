"""Run the join window's shipped JavaScript against isolated DOM/network fakes, never a user's browser."""
import base64
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from oarbank.coordinator import joincodes


def fresh(flags):
    return joincodes.encode(urls=["https://coord.example.net:7443"], pins=["ab" * 32],
                            cik=base64.b64encode(bytes(range(32))).decode(), code_id=bytes(range(1, 9)),
                            secret=bytes(range(16, 32)), expires_at=time.time() + 3600, flags=flags)


def test_decoder_vectors_and_screens():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is needed to exercise the join window JavaScript')
    env = {**os.environ,
           "JOIN_UI_CODE": fresh(joincodes.F_APPROVE | joincodes.F_SYSTEM),
           "JOIN_UI_PENDING_CODE": fresh(joincodes.F_MULTI),
           "JOIN_UI_CONTAINERS_CODE": fresh(joincodes.F_APPROVE | joincodes.F_CONTAINERS)}
    result = subprocess.run([node, str(Path(__file__).with_name('node_join_ui.mjs'))], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
