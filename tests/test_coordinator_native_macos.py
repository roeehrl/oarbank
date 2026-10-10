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
    result = subprocess.run(['xcrun', 'swiftc', '-O', '-target', f'{platform.machine()}-apple-macos15.0',
        '-framework', 'AppKit', '-framework', 'ServiceManagement',
        str(REPO / 'deploy/macos/coordinator/Launcher.swift'), '-o', str(tmp_path / 'launcher')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'launcher').is_file()
    build = subprocess.run(['xcrun', 'vtool', '-show-build', str(tmp_path / 'launcher')],
                           capture_output=True, text=True, check=True)
    assert 'minos 15.0' in build.stdout


# The coordinator's interpreter runs module code: it is signed with deploy/macos/python.entitlements (library validation
# off, so the wheels modules install load under the hardened runtime; docs/release-signing.md, "macOS code signatures")
CHECK_SIGNING = REPO / 'scripts/check-macos-signing.py'


def test_coordinator_builds_sign_their_interpreter_with_the_entitlements_and_check_it():
    for name, tree in (('build-coordinator.sh', '"$ROOT"'), ('package-coordinator-macos.sh', '"$APP"')):
        text = (REPO / 'scripts' / name).read_text(encoding='utf-8')
        assert 'source "$REPO/scripts/macos-codesign.sh"' in text, name
        sign = f'macos_sign_tree "$ID" {tree}'
        assert sign in text, name
        check = text.index('scripts/check-macos-signing.py"')
        assert text.index(sign) < check, name
        assert '--canary --work "$WORK/canary" "$ROOT"' in text[check:check + 200], name
        assert '[[ "$ID" == "-" ]] || DEVELOPER_ID=(--developer-id)' in text, name
        assert 'sign_with_timestamp' not in text and '--sign "$ID" "$f"' not in text, name
    pkg = (REPO / 'scripts/package-coordinator-macos.sh').read_text(encoding='utf-8')
    # the app is sealed before the check, and the seal is verified after the canary ran its interpreter
    check = pkg.index('scripts/check-macos-signing.py"')
    assert pkg.index('macos_sign "$ID" "$APP"') < check < pkg.index('codesign --verify --deep --strict "$APP"')
    build = (REPO / 'scripts/build-coordinator.sh').read_text(encoding='utf-8')
    assert build.index('scripts/check-macos-signing.py"') < build.index('pack-tar.py" "$TGZ"')


@pytest.mark.skipif(sys.platform != 'darwin' or not os.environ.get('OARBANK_COORDINATOR_PKG'),
                    reason='set OARBANK_COORDINATOR_PKG to a pkg scripts/package-coordinator-macos.sh built (needs PyPI)')
def test_a_built_coordinator_package_interpreter_loads_a_native_wheel_it_did_not_ship(tmp_path):
    subprocess.run(['pkgutil', '--expand-full', os.environ['OARBANK_COORDINATOR_PKG'], str(tmp_path / 'x')], check=True)
    app = next((tmp_path / 'x').glob('*.pkg')) / 'Payload/Applications/Oarbank Coordinator.app'
    assert subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)]).returncode == 0
    root = app / 'Contents/Resources/coordinator'
    info = subprocess.run(['codesign', '-dvv', str(root / 'python/bin/python3.12')], capture_output=True, text=True).stderr
    team = [] if 'TeamIdentifier=not set' in info else ['--developer-id']
    out = subprocess.run([sys.executable, str(CHECK_SIGNING), *team, '--canary', '--work', str(tmp_path / 'canary'), str(root)],
                         capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stderr
    assert 'canary:' in out.stdout
    # the canary changed nothing the app's seal covers
    assert subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)]).returncode == 0
