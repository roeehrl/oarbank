"""Native package and installed-directory activation without changing this host."""
import json
import os
import platform
import re
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


# ---------------------------------------------------------------------------------------------------------------------
# `oarbank` and `oarbank-setup` on the PATH: the pkg's postinstall links them in /usr/local/bin. Nothing here installs:
# the postinstall runs with its system paths rewritten into pytest's temporary directory.

POSTINSTALL = REPO / 'deploy/macos/coordinator/scripts/postinstall'
PACKAGER = REPO / 'scripts/package-coordinator-macos.sh'
APP_BIN = '/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin'


def test_the_coordinator_pkg_ships_the_postinstall_and_no_usr_local_payload():
    text = PACKAGER.read_text()
    assert 'cp -R "$REPO/deploy/macos/coordinator/scripts" "$WORK/scripts"' in text
    assert 'xattr -cr "$WORK/root" "$WORK/scripts"' in text
    pkgbuild = next(line for line in text.splitlines() if line.startswith('pkgbuild --quiet'))
    assert '--scripts "$WORK/scripts"' in pkgbuild and '--ownership recommended' in pkgbuild
    # the links are the postinstall's, never payload entries that would reset an existing /usr/local/bin's owner and mode
    assert '$WORK/root/usr' not in text and 'root/usr/local' not in text
    # each command runs through a link to it before it is packaged
    assert 'ln -s "$ROOT/bin/$cmd" "$WORK/linked/$cmd"' in text and '"$WORK/linked/$cmd" --help' in text
    assert POSTINSTALL.stat().st_mode & 0o111 == 0o111


def test_the_postinstall_only_links_the_commands():
    assert subprocess.run(['sh', '-n', str(POSTINSTALL)]).returncode == 0
    text = POSTINSTALL.read_text()
    code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    assert f'BIN="{APP_BIN}"' in code
    assert 'for name in oarbank oarbank-setup; do' in code and '/bin/ln -sfn "$BIN/$name" "$link"' in code
    for word in ('launchctl', 'oarbankd', 'install-oarbankd', 'chown', 'chmod', 'rm ', 'set -e'):
        assert word not in code, word
    assert text.rstrip().endswith('exit 0')


def _launcher(build_root: Path, name: str, module: str):
    """bin/<name> exactly as scripts/build-coordinator.sh writes it."""
    source = (REPO / 'scripts/build-coordinator.sh').read_text()
    function = re.search(r'^launcher\(\) \{\n.*?^\}\n', source, re.S | re.M).group(0)
    subprocess.run(['bash', '-c', f'set -eu\nROOT="$1"; PYVER=3.12\n{function}\nlauncher "$2" "$3"', 'build',
                    str(build_root), name, module], check=True)


class Mac:
    def __init__(self, tmp: Path):
        self.root = tmp / 'mac with spaces'
        self.bin = self.root / 'usr/local/bin'
        self.app_bin = Path(str(self.root) + APP_BIN)
        text = POSTINSTALL.read_text()
        text = text.replace('/usr/local/bin', str(self.bin)).replace('/Applications/', str(self.root) + '/Applications/')
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        assert not re.search(rf'(?<!{re.escape(str(self.root))})(/usr/local|/Applications)', code)
        self.script = tmp / 'postinstall'
        self.script.write_text(text)

    def build(self):
        """A stand-in coordinator build in the app: the real launchers, an interpreter that reports how it was run."""
        root = self.app_bin.parent
        (root / 'python/bin').mkdir(parents=True)
        python = root / 'python/bin/python3.12'
        python.write_text('#!/bin/sh\necho "interpreter=$0"\nfor a in "$@"; do echo "arg=$a"; done\n')
        python.chmod(0o755)
        self.app_bin.mkdir(parents=True)
        _launcher(root, 'oarbank', 'oarbank.cli.main')
        _launcher(root, 'oarbank-setup', 'oarbank.setup')
        return root

    def run(self):
        # Installer gives a postinstall no caller environment
        return subprocess.run(['/bin/sh', str(self.script)], env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
                              capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
def test_the_postinstall_links_both_commands_and_they_run_the_apps_build(tmp_path):
    mac = Mac(tmp_path)
    build = mac.build()
    out = mac.run()
    assert out.returncode == 0 and out.stdout == '' and out.stderr == '', out
    for name in ('oarbank', 'oarbank-setup'):
        assert os.readlink(mac.bin / name) == str(mac.app_bin / name)
    # on the PATH, through the link: the app's interpreter, the CLI's module, the arguments intact
    env = {'PATH': f'{mac.bin}:/usr/bin:/bin', 'HOME': str(tmp_path)}
    cli = subprocess.run(['oarbank', 'join-code', '--label', 'a b'], env=env, capture_output=True, text=True, check=True)
    lines = cli.stdout.splitlines()
    assert lines[0] == f'interpreter={build.resolve()}/python/bin/python3.12'
    assert lines[1:4] == ['arg=-I', 'arg=-B', 'arg=-c'] and 'from oarbank.cli.main import main' in lines[4] and lines[-3:] == ['arg=join-code', 'arg=--label', 'arg=a b']
    direct = subprocess.run([str(mac.app_bin / 'oarbank'), 'join-code', '--label', 'a b'], env=env,
                            capture_output=True, text=True, check=True)
    assert direct.stdout == cli.stdout  # the same as by the full path
    setup = subprocess.run(['oarbank-setup', '--no-browser'], env=env, capture_output=True, text=True, check=True)
    assert setup.stdout.splitlines()[-3:] == ['arg=--root', f'arg={build.resolve()}', 'arg=--no-browser']


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
def test_the_postinstall_replaces_links_keeps_other_files_and_the_directory(tmp_path):
    mac = Mac(tmp_path)
    mac.bin.mkdir(parents=True)
    mac.bin.chmod(0o775)                                   # e.g. a Homebrew-owned /usr/local/bin
    (mac.bin / 'oarbank').symlink_to('/somewhere/older/oarbank')
    (mac.bin / 'oarbank-setup').write_text('#!/bin/sh\necho mine\n')
    out = mac.run()
    assert out.returncode == 0, out
    assert os.readlink(mac.bin / 'oarbank') == str(mac.app_bin / 'oarbank')
    assert (mac.bin / 'oarbank-setup').read_text() == '#!/bin/sh\necho mine\n'
    assert 'oarbank-setup is not a link and stays as it is' in out.stdout
    assert mac.bin.stat().st_mode & 0o777 == 0o775
    assert mac.run().returncode == 0 and os.readlink(mac.bin / 'oarbank') == str(mac.app_bin / 'oarbank')  # idempotent
