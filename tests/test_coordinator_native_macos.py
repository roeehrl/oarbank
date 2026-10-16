"""Native package and installed-directory activation without changing this host."""
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import apple_tool, coordinator_command

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
    result = apple_tool(['xcrun', 'swiftc', '-O', '-parse-as-library', '-target', f'{platform.machine()}-apple-macos15.0',
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
# `oarbank` and `oarbank-setup` on the PATH: the pkg's postinstall links them in /usr/local/bin to the app's forwarders
# (the build the services run, /Library/Oarbank/Coordinator/current, else the app's own), refreshes an installed
# system service and migrates an earlier release's per-user coordinator. Nothing here installs: the postinstall runs
# with its system paths rewritten into pytest's temporary directory.

POSTINSTALL = REPO / 'deploy/macos/coordinator/scripts/postinstall'
PACKAGER = REPO / 'scripts/package-coordinator-macos.sh'
APP_BIN = '/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin'
APP_CLI = '/Applications/Oarbank Coordinator.app/Contents/Resources/cli'
PROGRAMS = '/Library/Oarbank/Coordinator'


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
    # the app carries the forwarders the links name, one per command
    assert 'install -m 755 "$REPO/deploy/oarbankd/coordinator-command.sh" "$APP/Contents/Resources/cli/$cmd"' in text
    if sys.platform != 'win32':                         # no execute bit on Windows
        assert POSTINSTALL.stat().st_mode & 0o111 == 0o111


def test_the_postinstall_links_the_commands_and_only_refreshes_or_migrates():
    assert subprocess.run(['sh', '-n', str(POSTINSTALL)]).returncode == 0
    text = POSTINSTALL.read_text()
    code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    assert f'ROOT="{APP_BIN[:-len("/bin")]}"' in code and 'BIN="$ROOT/bin"' in code and f'CLI="{APP_CLI}"' in code
    assert 'for name in oarbank oarbank-setup; do' in code and '/bin/ln -sfn "$CLI/$name" "$link"' in code
    # a first install starts nothing (the wizard does, with the person's address); never a new fleet from here
    # an upgrade's refresh runs this build, also after a coordinator self-update ran another (fleet-updates.md, D58)
    refresh = '/bin/bash "$ROOT/install-oarbankd.sh" --refresh --installed "$ROOT"'
    assert refresh in code and code.count('--installed') == 1
    assert '"$BIN/oarbank" coordinator migrate --run --from-installer --build "$ROOT"' in code
    code = code.replace(refresh, '')
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
        self.app_cli = Path(str(self.root) + APP_CLI)
        self.programs = Path(str(self.root) + PROGRAMS)
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
        for name in ('oarbank', 'oarbank-setup'):        # as package-coordinator-macos.sh installs them
            coordinator_command(self.app_cli / name, self.programs / 'current', root)
        return root

    def unpacked(self, version: str) -> Path:
        """A build a coordinator self-update unpacked: PROGRAMS/<v>-<sha12> (coordupdate.py), its own launchers."""
        root = self.programs / f'{version}-0123456789ab'
        (root / 'python/bin').mkdir(parents=True)
        (root / 'python/bin/python3.12').write_text(
            f'#!/bin/sh\necho "interpreter=$0"\necho "version={version}"\nfor a in "$@"; do echo "arg=$a"; done\n')
        (root / 'python/bin/python3.12').chmod(0o755)
        (root / 'bin').mkdir()
        _launcher(root, 'oarbank', 'oarbank.cli.main')
        _launcher(root, 'oarbank-setup', 'oarbank.setup')
        (root / 'oarbank-coordinator.json').write_text(json.dumps({'format': 1, 'version': version}))
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
        assert os.readlink(mac.bin / name) == str(mac.app_cli / name)
    # on the PATH, through the link, before setup (no PROGRAMS/current): the app's interpreter, the CLI's module, the
    # arguments intact
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
def test_the_commands_on_the_path_follow_the_build_a_self_update_installed(tmp_path):
    """After a coordinator self-update the services run PROGRAMS/<v>-<sha12> (PROGRAMS/current names it); the app, and
    the CLI linked to its bin/, stayed the package's version (2.11.0 and earlier: `oarbank node approve --state paused`
    was refused by the 2.10.4 CLI on a 2.11.0 coordinator). The commands on the PATH now run the build `current` names,
    also after a rollback flips it back."""
    mac = Mac(tmp_path)
    build = mac.build()
    assert mac.run().returncode == 0
    env = {'PATH': f'{mac.bin}:/usr/bin:/bin', 'HOME': str(tmp_path)}
    (build / 'oarbank-coordinator.json').write_text(json.dumps({'format': 1, 'version': '2.10.4'}))

    def ran(*argv):
        return subprocess.run(argv, env=env, capture_output=True, text=True, check=True).stdout.splitlines()
    # the system service on the package's build: install-oarbankd --installed points current at it (absolute)
    mac.programs.mkdir(parents=True)
    os.symlink(build, mac.programs / 'current')
    assert ran('oarbank', 'fleet')[0] == f'interpreter={build.resolve()}/python/bin/python3.12'
    # the self-update flips current to the build it unpacked (a sibling by name)
    new = mac.unpacked('2.11.0')
    tmp = mac.programs / '.current.flip'
    os.symlink(new.name, tmp)
    os.replace(tmp, mac.programs / 'current')
    out = ran('oarbank', 'node', 'approve', 'mini', '--state', 'paused')
    assert out[:2] == [f'interpreter={new.resolve()}/python/bin/python3.12', 'version=2.11.0'], out
    assert out[-5:] == ['arg=node', 'arg=approve', 'arg=mini', 'arg=--state', 'arg=paused']
    assert ran(str(mac.app_cli / 'oarbank'), 'fleet')[:2] == out[:2]           # the forwarder by its full path too
    setup = ran('oarbank-setup', '--no-browser')
    assert setup[:2] == out[:2] and setup[-3:] == ['arg=--root', f'arg={new.resolve()}', 'arg=--no-browser'], setup
    # a rollback flips current back to the package's build
    os.symlink(build, tmp)
    os.replace(tmp, mac.programs / 'current')
    assert ran('oarbank', 'fleet')[0] == f'interpreter={build.resolve()}/python/bin/python3.12'
    # a current that is no coordinator build (or names nothing) is never run: the app's own
    os.unlink(mac.programs / 'current')
    os.symlink(tmp_path / 'nowhere', mac.programs / 'current')
    assert ran('oarbank', 'fleet')[0] == f'interpreter={build.resolve()}/python/bin/python3.12'


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
def test_the_postinstall_replaces_links_keeps_other_files_and_the_directory(tmp_path):
    mac = Mac(tmp_path)
    mac.bin.mkdir(parents=True)
    mac.bin.chmod(0o775)                                   # e.g. a Homebrew-owned /usr/local/bin
    (mac.bin / 'oarbank').symlink_to('/somewhere/older/oarbank')
    (mac.bin / 'oarbank-setup').write_text('#!/bin/sh\necho mine\n')
    out = mac.run()
    assert out.returncode == 0, out
    assert os.readlink(mac.bin / 'oarbank') == str(mac.app_cli / 'oarbank')
    assert (mac.bin / 'oarbank-setup').read_text() == '#!/bin/sh\necho mine\n'
    assert 'oarbank-setup is not a link and stays as it is' in out.stdout
    assert mac.bin.stat().st_mode & 0o777 == 0o775
    assert mac.run().returncode == 0 and os.readlink(mac.bin / 'oarbank') == str(mac.app_cli / 'oarbank')  # idempotent


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
    # on this build: also after a coordinator self-update ran another one (fleet-updates.md, D58)
    assert out.returncode == 0 and out.stdout.splitlines() == [f'installer --refresh --installed {build}'], out
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


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell')
def test_the_postinstall_pins_the_coordinators_update_trust_after_a_refresh_or_a_migration(tmp_path):
    """A coordinator upgraded (or migrated from per-user) by the pkg gets its update runner's trust from its home's
    owner keys while the administrator installs, unless one is pinned; the migration's pin runs once the services
    answer (its copied database gets the owner anchors from the new build). fleet-updates.md, D58."""
    mac = Mac(tmp_path)
    build = mac.build()
    (build / 'install-oarbankd.sh').write_text('#!/bin/bash\necho "installer $*"\n')
    data = mac.root / 'Library/Application Support/Oarbank'
    calls = tmp_path / 'coordupdate-calls'
    coordupdate = mac.app_bin / 'oarbank-coordupdate'
    coordupdate.write_text(f'#!/bin/sh\necho "$*" >> "{calls}"\nexit "${{PIN_EXIT:-0}}"\n')
    coordupdate.chmod(0o755)
    expected = f'trust --from-home --home {data}/coordinator --state {data}/coordinator-update'
    mac.record.parent.mkdir(parents=True)
    mac.record.write_text('{"format": "1"}\n')
    # an upgrade of a system service with no home yet: nothing to pin from
    out = mac.run()
    assert out.returncode == 0 and out.stdout.splitlines() == [f'installer --refresh --installed {build}'] and not calls.exists(), out
    # a home and no trust: pinned from it, after the refresh
    (data / 'coordinator').mkdir()
    (data / 'coordinator/oarbank.sqlite3').write_bytes(b'')
    out = mac.run()
    assert out.returncode == 0 and out.stdout.splitlines() == [f'installer --refresh --installed {build}',
                                                               "Oarbank: the coordinator's update trust is pinned"], out
    assert calls.read_text().splitlines() == [expected]
    # no owner keys yet: the runner pins at the first update (coordupdate leaves the pin pending)
    calls.unlink()
    out = subprocess.run(['/bin/sh', str(mac.script)], env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'PIN_EXIT': '1'},
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and out.stdout.splitlines()[-1] == \
        "Oarbank: the coordinator has no owner keys yet; its update runner pins them at the first update", out
    # pinned already: left alone
    calls.unlink()
    (data / 'coordinator-update').mkdir()
    (data / 'coordinator-update/trust.json').write_text('{}')
    assert mac.run().returncode == 0 and not calls.exists()
    (data / 'coordinator-update/trust.json').unlink()
    # a per-user coordinator migrated: the migration makes the record, then the trust is pinned
    mac.record.unlink()
    agents = mac.root / 'Users/owner/Library/LaunchAgents'
    agents.mkdir(parents=True)
    (agents / 'dev.codonic.oarbank.oarbankd.plist').write_text('<plist/>')
    (mac.app_bin / 'oarbank').write_text(f'#!/bin/sh\necho "migrate $*"\necho "{{}}" > "{mac.record}"\n')
    out = mac.run()
    assert out.returncode == 0 and out.stdout.splitlines() == [
        f'migrate coordinator migrate --run --from-installer --build {build}',
        'Oarbank: the coordinator now runs as a system service', "Oarbank: the coordinator's update trust is pinned"], out
    assert calls.read_text().splitlines() == [expected]
    # a migration that waits for its owner pins nothing
    calls.unlink()
    mac.record.unlink()
    (mac.app_bin / 'oarbank').write_text('#!/bin/sh\nexit 3\n')
    assert mac.run().returncode == 0 and not calls.exists()


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
