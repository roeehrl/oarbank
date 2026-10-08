"""Native package and installed-directory activation without changing this host."""
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

@pytest.mark.skipif(sys.platform == 'win32', reason='Unix activation helper')
def test_native_build_activation_is_dry_run_and_preserves_payload(tmp_path):
    token = {'Darwin': 'darwin', 'Linux': 'linux'}[platform.system()]
    arch = 'arm64' if platform.machine() in ('arm64', 'aarch64') else 'amd64'
    root = tmp_path / 'Application with spaces' / 'coordinator'
    (root / 'bin').mkdir(parents=True)
    manifest = root / 'oarbank-coordinator.json'
    manifest.write_text(json.dumps({'format': 1, 'version': '2.6.0', 'platform': f'{token}-{arch}'}))
    for name in ('oarbankd', 'oarbank-console', 'oarbank'):
        p = root / 'bin' / name
        p.write_text('#!/bin/sh\nexit 0\n')
        p.chmod(0o755)
    home = tmp_path / 'private-home'
    home.mkdir()
    env = {**os.environ, 'HOME': str(home), 'XDG_DATA_HOME': str(home / 'data'), 'XDG_CONFIG_HOME': str(home / 'config')}
    cmd = ['bash', str(REPO / 'deploy/oarbankd/install-oarbankd.sh'), '--installed', str(root), '--agent-bind', '192.168.1.10', '--dry-run']
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert str(root / 'bin/oarbankd') in result.stdout
    assert '192.168.1.10' in result.stdout
    assert not list(home.iterdir())
    assert manifest.exists()
    manifest.write_text(json.dumps({'format': 1, 'platform': 'windows-amd64'}))
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode != 0 and 'not for' in result.stderr
    assert not list(home.iterdir())

@pytest.mark.skipif(sys.platform != 'darwin', reason='Apple toolchain')
def test_application_launcher_compiles(tmp_path):
    result = subprocess.run(['xcrun', 'swiftc', '-O', '-framework', 'AppKit',
        str(REPO / 'deploy/macos/coordinator/Launcher.swift'), '-o', str(tmp_path / 'launcher')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'launcher').is_file()
