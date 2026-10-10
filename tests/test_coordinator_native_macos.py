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
    system = tmp_path / 'system'
    env = {**os.environ, 'HOME': str(home), 'XDG_DATA_HOME': str(home / 'data'), 'XDG_CONFIG_HOME': str(home / 'config'),
           'OARBANK_INSTALL_ROOT': str(system)}
    cmd = ['bash', str(REPO / 'deploy/oarbankd/install-oarbankd.sh'), '--installed', str(root), '--agent-bind', '192.168.1.10', '--dry-run']
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert str(root / 'bin/oarbankd') in result.stdout
    assert '192.168.1.10' in result.stdout
    if platform.system() == 'Darwin':
        # Login Items lists both jobs as Oarbank Coordinator (the package's app), not as the signing team
        owner = '<key>AssociatedBundleIdentifiers</key><array><string>dev.codonic.oarbank.coordinator</string></array>'
        assert result.stdout.count(owner) == 2
        assert "CFBundleIdentifier</key><string>dev.codonic.oarbank.coordinator<" in PACKAGER.read_text()
        # a move's standby is the same system service, installed by the build's own installer
        assert 'root.join("install-oarbankd.sh")' in (REPO / 'rust/crates/oarbank-agent/src/coordinstall.rs').read_text()
    assert not list(home.iterdir()) and not system.exists()
    assert manifest.exists()
    manifest.write_text(json.dumps({'format': 1, 'platform': 'windows-amd64'}))
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode != 0 and 'not for' in result.stderr
    assert not list(home.iterdir())

@pytest.mark.skipif(sys.platform != 'darwin', reason='Apple toolchain')
def test_application_launcher_compiles(tmp_path):
    # as scripts/package-coordinator-macos.sh builds it: with the menu bar model it shares with Oarbank Node.app
    result = subprocess.run(['xcrun', 'swiftc', '-O', '-parse-as-library', '-target', f'{platform.machine()}-apple-macos15.0',
        '-framework', 'AppKit', '-framework', 'ServiceManagement', str(REPO / 'deploy/macos/coordinator/Launcher.swift'),
        str(REPO / 'deploy/macos/shared/MenuBar.swift'), '-o', str(tmp_path / 'launcher')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'warning:' not in result.stderr, result.stderr
    packager = (REPO / 'scripts/package-coordinator-macos.sh').read_text()
    assert '"$REPO/deploy/macos/coordinator/Launcher.swift" "$REPO/deploy/macos/shared/MenuBar.swift"' in packager
    assert 'xcrun swiftc -O -parse-as-library' in packager
    assert ('cp "$REPO/deploy/icons/oarbank.icns" "$REPO/deploy/icons/oarbank-coordinator-symbolic.png" '
            '"$REPO/deploy/icons/oarbank-coordinator-symbolic@2x.png" "$APP/Contents/Resources/"') in packager
    assert (tmp_path / 'launcher').is_file()
    build = subprocess.run(['xcrun', 'vtool', '-show-build', str(tmp_path / 'launcher')],
                           capture_output=True, text=True, check=True)
    assert 'minos 15.0' in build.stdout


# ---------------------------------------------------------------------------------------------------------------------
# `oarbank` and `oarbank-setup` on the PATH: the pkg's postinstall links them in /usr/local/bin, refreshes an installed
# system service and migrates an earlier release's per-user coordinator. Nothing here installs: the postinstall runs
# with its system paths rewritten into pytest's temporary directory.

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
    if sys.platform != 'win32':                         # no execute bit on Windows
        assert POSTINSTALL.stat().st_mode & 0o111 == 0o111


def test_the_postinstall_links_the_commands_and_only_refreshes_or_migrates():
    assert subprocess.run(['sh', '-n', str(POSTINSTALL)]).returncode == 0
    text = POSTINSTALL.read_text()
    code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    assert f'ROOT="{APP_BIN[:-len("/bin")]}"' in code and 'BIN="$ROOT/bin"' in code
    assert 'for name in oarbank oarbank-setup; do' in code and '/bin/ln -sfn "$BIN/$name" "$link"' in code
    # a first install starts nothing (the wizard does, with the person's address); never a new fleet from here
    assert '/bin/bash "$ROOT/install-oarbankd.sh" --refresh' in code
    assert '"$BIN/oarbank" coordinator migrate --run --from-installer --build "$ROOT"' in code
    for word in ('launchctl', '--installed', 'chown', 'chmod', 'rm ', 'set -e', 'account create', 'join-code'):
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
        text = text.replace('/Library/Application Support', str(self.root) + '/Library/Application Support')
        text = text.replace('/Users/*', f'"{self.root}/Users/"*')    # quoted: the scratch root has spaces
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        assert not re.search(rf'(?<!{re.escape(str(self.root))})(?<!\*)(/usr/local|/Applications|/Library|/Users)', code)
        self.record = self.root / 'Library/Application Support/Oarbank/coordinator-service.json'
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


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
def test_an_upgrade_refreshes_the_system_service_and_a_per_user_coordinator_is_migrated(tmp_path):
    mac = Mac(tmp_path)
    build = mac.build()
    (build / 'install-oarbankd.sh').write_text('#!/bin/bash\necho "installer $*"\n')
    # the system service is installed: the services are written again from its record, nothing is migrated
    mac.record.parent.mkdir(parents=True)
    mac.record.write_text('{"format": "1"}\n')
    agents = mac.root / 'Users/owner/Library/LaunchAgents'
    agents.mkdir(parents=True)
    (agents / 'dev.codonic.oarbank.oarbankd.plist').write_text('<plist/>')
    out = mac.run()
    assert out.returncode == 0 and out.stdout.splitlines() == ['installer --refresh'], out
    # an earlier release's per-user coordinator and no system service yet: the migration, from the app's build
    mac.record.unlink()
    out = mac.run()
    lines = out.stdout.splitlines()
    assert out.returncode == 0 and lines[0] == f'interpreter={build.resolve()}/python/bin/python3.12', out
    assert [a for a in lines if a.startswith('arg=')][-6:] == [
        'arg=coordinator', 'arg=migrate', 'arg=--run', 'arg=--from-installer', 'arg=--build', f'arg={build}']
    assert lines[-1] == 'Oarbank: the coordinator now runs as a system service'
    # a first install: links only, silently
    (agents / 'dev.codonic.oarbank.oarbankd.plist').unlink()
    out = mac.run()
    assert out.returncode == 0 and out.stdout == '' and out.stderr == '', out


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
