"""The macOS node package (docs/design/node-enrollment.md): the postinstall that installs without joining, the
managed-policy job, Oarbank Node.app and what scripts/package-macos.sh ships. Nothing here installs, loads a launchd
job or writes outside pytest's temporary directories: the postinstall runs against stand-ins for the system's tools
and folders."""
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MACOS = REPO / "deploy" / "macos"
POSTINSTALL = MACOS / "scripts" / "postinstall"
UNINSTALL = MACOS / "oarbank-uninstall"
POLICY = MACOS / "dev.codonic.oarbank.agent.policy.plist"
NODE_APP = MACOS / "node" / "NodeApp.swift"
PACKAGE = REPO / "scripts" / "package-macos.sh"
SECRET = "OB2-0SECRETCODE0DONOTPRINT0"


# ---------------------------------------------------------------------------------------------------------------------
# postinstall


def test_the_postinstall_parses_and_holds_no_hand_made_files():
    assert subprocess.run(["sh", "-n", str(POSTINSTALL)]).returncode == 0
    text = POSTINSTALL.read_text(encoding="utf-8")
    # /Library/Oarbank/etc (join-code, coordinator, system marker) is gone, and the pkg never joins by itself
    assert "/Library/Oarbank/etc" not in text and "ETC" not in text and "join-code" not in text
    assert "oarbank-launcher\" setup" not in text and " setup " not in text
    assert 'ln -sfn "$BIN/oarbank-launcher" /usr/local/bin/oarbank-node' in text
    assert '[ -z "${COMMAND_LINE_INSTALL:-}" ]' in text
    assert 'MANAGED="/Library/Managed Preferences/$LABEL.plist"' in text
    assert "--args --join" in text and "/bin/launchctl asuser" in text
    assert 'echo "Installed. Join this Mac with: sudo oarbank-node join"' in text
    assert text.rstrip().endswith("exit 0") and "set -e" not in text


def test_the_postinstall_never_prints_a_value_that_could_hold_a_code():
    # install.log is world-readable: every echo is a fixed sentence, and the managed values only feed a test
    text = POSTINSTALL.read_text(encoding="utf-8")
    for line in text.splitlines():
        if re.search(r"\b(echo|printf)\b", line) and not line.lstrip().startswith("#"):
            assert "$" not in line.split("echo", 1)[-1], line
    assert re.search(r'\[ -n "\$\(/usr/bin/plutil -extract "\$key" raw -o - "\$MANAGED" 2>/dev/null\)" \]', text)
    assert "defaults read" not in text and "/bin/cat" not in text


class Mac:
    """The postinstall against stand-ins: its absolute paths rewritten into a temporary root, the system's tools that
    would change this Mac (launchctl, open, sudo, chown) replaced by scripts that record their arguments."""

    def __init__(self, tmp: Path, user: str = "pat"):
        self.root, self.calls = tmp / "mac", tmp / "calls.log"
        self.home = self.root / "Users" / user
        for d in ("stub", "usr/local", "var/log", "Library/LaunchDaemons", "Library/Managed Preferences",
                  "Library/Oarbank/bin", "Applications/Oarbank Node.app/Contents", "Users/" + user + "/Library/LaunchAgents"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        stubs = {
            "launchctl": 'echo "launchctl $*" >> "$CALLS"',
            "open": 'echo "open $*" >> "$CALLS"',
            "sudo": 'echo "sudo $1 $2" >> "$CALLS"; shift 2; exec "$@"',
            "chown": "exit 0",
            "stat": f'echo "{user}"',
            "id": '[ "$2" = root ] && echo 0 || { [ "$2" = loginwindow ] && echo 0 || echo 501; }',
            "dscl": f'echo "NFSHomeDirectory: {self.home}"',
            "who": f'echo "{user} console Oct 10 09:00"',
        }
        for name, body in stubs.items():
            p = self.root / "stub" / name
            p.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            p.chmod(0o755)
        text = POSTINSTALL.read_text(encoding="utf-8")
        r, s = str(self.root), str(self.root / "stub")
        for real, fake in [("/bin/launchctl", f"{s}/launchctl"), ("/usr/bin/open", f"{s}/open"), ("/usr/bin/sudo", f"{s}/sudo"),
                           ("/usr/sbin/chown", f"{s}/chown"), ("/usr/bin/stat", f"{s}/stat"), ("/usr/bin/id", f"{s}/id"),
                           ("/usr/bin/dscl", f"{s}/dscl"), ("/usr/bin/who", f"{s}/who"), ("/bin/sleep", "true"),
                           ("/usr/local/bin", f"{r}/usr/local/bin"), ("/var/log/", f"{r}/var/log/"),
                           ("/Library/LaunchDaemons", f"{r}/Library/LaunchDaemons"),
                           ("/Library/Managed Preferences", f"{r}/Library/Managed Preferences"),
                           ("/Library/Oarbank", f"{r}/Library/Oarbank"), ("/Applications/", f"{r}/Applications/")]:
            text = text.replace(real, fake)
        # nothing left that reaches the real system (the comments aside)
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        assert not re.search(rf"(?<!{re.escape(r)})(/Library/(LaunchDaemons|Managed|Oarbank)|/usr/local/bin|/var/log)", code)
        self.script = tmp / "postinstall"
        self.script.write_text(text, encoding="utf-8")

    def run(self, **env):
        # Installer passes no caller environment: only what the test names
        e = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "CALLS": str(self.calls), **env}
        out = subprocess.run(["/bin/sh", str(self.script)], env=e, capture_output=True, text=True, timeout=60)
        calls = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return out, calls

    def manage(self, **values):
        with open(self.root / "Library/Managed Preferences/dev.codonic.oarbank.agent.plist", "wb") as f:
            plistlib.dump(values, f)


unix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")


@unix
def test_a_double_click_install_opens_the_join_window_as_the_console_user(tmp_path):
    mac = Mac(tmp_path)
    out, calls = mac.run()
    assert out.returncode == 0 and out.stdout == "", out
    assert "sudo -u pat" in calls
    assert f"open -a {mac.root}/Applications/Oarbank Node.app --args --join" in calls
    assert "launchctl asuser 501" in calls
    # the policy job is (re)loaded, oarbank-node points at the launcher, the policy log is root's alone
    assert f"launchctl bootstrap system {mac.root}/Library/LaunchDaemons/dev.codonic.oarbank.agent.policy.plist" in calls
    assert calls.index("bootout system/dev.codonic.oarbank.agent.policy") < calls.index("bootstrap system")
    link = mac.root / "usr/local/bin/oarbank-node"
    assert os.readlink(link) == f"{mac.root}/Library/Oarbank/bin/oarbank-launcher"
    assert (mac.root / "var/log/oarbank-policy.log").stat().st_mode & 0o777 == 0o600


@unix
def test_a_command_line_install_says_how_to_join_and_opens_nothing(tmp_path):
    mac = Mac(tmp_path)
    out, calls = mac.run(COMMAND_LINE_INSTALL="1")
    assert out.returncode == 0
    assert out.stdout.splitlines() == ["Installed. Join this Mac with: sudo oarbank-node join"]
    assert "open " not in calls and "kickstart" not in calls


@unix
def test_no_one_at_the_console_means_no_window(tmp_path):
    for user in ("root", "loginwindow"):
        mac = Mac(tmp_path / user, user=user)
        out, calls = mac.run()
        assert out.returncode == 0 and out.stdout.splitlines() == ["Installed. Join this Mac with: sudo oarbank-node join"]
        assert "open " not in calls


@unix
def test_a_managed_mac_joins_by_policy_and_its_code_is_never_printed(tmp_path):
    for key, value in (("JoinCode", SECRET), ("Coordinator", "https://secret-host.example:7443")):
        mac = Mac(tmp_path / key)
        mac.manage(**{key: value, "ManagedByOrganizationName": "Example Corp"})
        out, calls = mac.run()
        assert out.returncode == 0 and "open " not in calls
        assert value not in out.stdout + out.stderr + calls
        assert out.stdout.splitlines() == ["Installed. Join this Mac with: sudo oarbank-node join"]
    # an empty value is no policy (policy-apply ignores it too)
    mac = Mac(tmp_path / "empty")
    mac.manage(JoinCode="  ".strip())
    assert "--args --join" in mac.run()[1]


@unix
def test_an_upgrade_restarts_the_service_in_either_scope(tmp_path):
    mac = Mac(tmp_path / "system")
    (mac.root / "Library/LaunchDaemons/dev.codonic.oarbank.agent.plist").write_text("<plist/>", encoding="utf-8")
    out, calls = mac.run()
    assert out.returncode == 0 and "open " not in calls
    assert "launchctl kickstart -k system/dev.codonic.oarbank.agent" in calls
    assert "launchctl kickstart -k gui/501/dev.codonic.oarbank.agent.session" in calls
    assert out.stdout.splitlines() == ["Oarbank: upgraded; the service restarted on the new launcher"]
    mac = Mac(tmp_path / "personal")
    (mac.home / "Library/LaunchAgents/dev.codonic.oarbank.agent.plist").write_text("<plist/>", encoding="utf-8")
    out, calls = mac.run()
    assert out.returncode == 0 and "open " not in calls
    assert "launchctl kickstart -k gui/501/dev.codonic.oarbank.agent" in calls
    assert "system/dev.codonic.oarbank.agent " not in calls + " "


@unix
def test_a_failing_launchctl_or_open_never_fails_the_install(tmp_path):
    mac = Mac(tmp_path)
    for name in ("launchctl", "open"):
        (mac.root / "stub" / name).write_text('#!/bin/sh\necho "nope $*" >&2\nexit 5\n', encoding="utf-8")
    out, _ = mac.run()
    assert out.returncode == 0
    assert out.stdout.splitlines()[-1] == "Installed. Join this Mac with: sudo oarbank-node join"


# ---------------------------------------------------------------------------------------------------------------------
# the managed-policy job and the uninstaller


def test_the_policy_job_runs_policy_apply_on_the_managed_preferences():
    with open(POLICY, "rb") as f:
        job = plistlib.load(f)
    assert job["Label"] == "dev.codonic.oarbank.agent.policy" and POLICY.name == job["Label"] + ".plist"
    assert job["ProgramArguments"] == ["/Library/Oarbank/bin/oarbank-launcher", "policy-apply"]
    assert job["RunAtLoad"] is True
    assert job["WatchPaths"] == ["/Library/Managed Preferences/dev.codonic.oarbank.agent.plist"]
    # nothing a managed value could reach is world-readable: stdout nowhere, stderr root's (0600, umask 077)
    assert job["StandardOutPath"] == "/dev/null" and job["StandardErrorPath"] == "/var/log/oarbank-policy.log"
    assert job["Umask"] == 0o077
    assert "UserName" not in job                                    # a daemon: root


@pytest.mark.skipif(not shutil.which("plutil"), reason="macOS plutil")
def test_the_policy_job_lints():
    assert subprocess.run(["plutil", "-lint", str(POLICY)], capture_output=True).returncode == 0


def test_the_uninstaller_removes_the_app_the_policy_job_and_oarbank_node():
    assert subprocess.run(["sh", "-n", str(UNINSTALL)]).returncode == 0
    text = UNINSTALL.read_text(encoding="utf-8")
    assert 'APP="/Applications/Oarbank Node.app"' in text and '/bin/rm -rf "$APP"' in text
    assert '/usr/bin/pkill -x "Oarbank Node"' in text and text.index("pkill") < text.index('rm -rf "$APP"')
    assert '/bin/launchctl bootout "system/$POLICY"' in text and '/bin/rm -f "/Library/LaunchDaemons/$POLICY.plist"' in text
    # the policy job goes before the node's removal, so no profile joins it again on the way out
    assert text.index("bootout") < text.index("oarbank-launcher\" remove")
    assert '[ "$(/usr/bin/readlink /usr/local/bin/oarbank-node 2>/dev/null)" = "$BIN/oarbank-launcher" ] && /bin/rm -f /usr/local/bin/oarbank-node' in text
    assert '/bin/rm -rf "/Library/Application Support/Oarbank/status"' in text
    assert "/bin/rm -rf /Library/Oarbank" in text and "pkgutil --forget dev.codonic.oarbank.agent" in text


# ---------------------------------------------------------------------------------------------------------------------
# Oarbank Node.app


def test_the_app_follows_the_launch_contract():
    swift = NODE_APP.read_text(encoding="utf-8")
    for needle in ('"/Library/Application Support/Oarbank/status/node.json"', '"Library/Application Support/Oarbank/status/node.json"',
                   '"\\(installRoot)/bin/runtime/bin/python3"', '"\\(installRoot)/share/join/join-window.py"',
                   '"\\(installRoot)/bin/oarbank-launcher"', '["-I", joinWindow, "--launcher", launcher]', '["--link", $0]',
                   'CommandLine.arguments.contains("--join")', "kAEGetURL", "kInternetEventClass",
                   'policyValue("AllowUserJoin") as? Bool != false', '"dev.codonic.oarbank.agent" as CFString',
                   "CFPreferencesCopyAppValue", "SMAppService.mainApp.register()", "SMAppService.mainApp.unregister()",
                   ".requiresApproval", "setActivationPolicy(.accessory)", "isTemplate = true", 'keyEquivalent: ","',
                   'keyEquivalent: "q"', '"Join this Mac…"', '"Status…"', '"Waiting for approval"', '"Not joined"',
                   '"Connected to \\(host)"', '"Joining failed: \\(message)"', '"Managed by \\(', "withTimeInterval: 30",
                   "Timer(timeInterval: 5", "applicationShouldHandleReopen"):
        assert needle in swift, needle
    # it never handles a code itself: a link goes to the join window, which asks before anything joins
    assert "JoinCode" not in swift and "--code" not in swift


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("xcrun"), reason="Apple toolchain")
def test_the_app_compiles_for_macos_15(tmp_path):
    out = tmp_path / "Oarbank Node"
    result = subprocess.run(["xcrun", "swiftc", "-O", "-target", f"{platform.machine()}-apple-macos15.0",
                             "-framework", "AppKit", "-framework", "ServiceManagement", str(NODE_APP), "-o", str(out)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    build = subprocess.run(["xcrun", "vtool", "-show-build", str(out)], capture_output=True, text=True, check=True)
    assert "minos 15.0" in build.stdout
    loads = subprocess.run(["otool", "-l", str(out)], capture_output=True, text=True, check=True).stdout
    assert "LC_BUILD_VERSION" in loads and "minos 15.0" in loads
    # check-package.py refuses a binary that names the checkout or the build account's home
    data = out.read_bytes()
    assert str(REPO).encode() not in data and str(Path.home()).encode() not in data


def _info_plist() -> dict:
    text = PACKAGE.read_text(encoding="utf-8")
    body = re.search(r'cat > "\$APP/Contents/Info.plist" <<PLIST\n(.*?)\nPLIST\n', text, re.S).group(1)
    return plistlib.loads(body.replace("$VERSION", "2.8.0").encode())


def test_the_app_bundle_registers_oarbank_links_and_hides_from_the_dock():
    info = _info_plist()
    assert info["CFBundleIdentifier"] == "dev.codonic.oarbank.node"
    assert info["CFBundleExecutable"] == "Oarbank Node" and info["CFBundleName"] == "Oarbank Node"
    assert info["LSUIElement"] is True and info["LSMinimumSystemVersion"] == "15.0"
    assert info["CFBundleURLTypes"][0]["CFBundleURLSchemes"] == ["oarbank"]
    assert info["NSLocalNetworkUsageDescription"].strip()
    # the coordinator app's artwork, from the official logo (deploy/icons/README.md)
    assert info["CFBundleIconFile"] == "oarbank.icns" and (REPO / "deploy/icons/oarbank.icns").is_file()
    assert (REPO / "deploy/icons/oarbank-symbolic.png").is_file()


# ---------------------------------------------------------------------------------------------------------------------
# scripts/package-macos.sh


def test_the_package_builds_signs_and_ships_the_app_the_join_window_and_the_policy_job():
    text = PACKAGE.read_text(encoding="utf-8")
    assert "Oarbank/etc" not in text
    assert 'APP="$WORK/root/Applications/Oarbank Node.app"' in text
    assert 'xcrun swiftc -O -target "$ARCH-apple-macos15.0" -framework AppKit -framework ServiceManagement' in text
    assert '"$REPO/deploy/macos/node/NodeApp.swift" -o "$APP/Contents/MacOS/Oarbank Node"' in text
    assert 'cp "$REPO/deploy/icons/oarbank.icns" "$REPO/deploy/icons/oarbank-symbolic.png" "$APP/Contents/Resources/"' in text
    assert "codesign --force --options runtime --timestamp --identifier dev.codonic.oarbank.node --sign \"$ID\" \"$APP\"" in text
    assert 'codesign --force --identifier dev.codonic.oarbank.node --sign - "$APP"' in text
    assert 'codesign --verify --deep --strict "$APP"' in text
    # check-package.py sees the app's binary (its architecture, no build paths) before anything is signed
    check = text.index('check-package.py" --build-path')
    assert text.index("xcrun swiftc") < check < text.index("--identifier dev.codonic.oarbank.node")
    assert '"$APP/Contents/MacOS/Oarbank Node"' in text[check:check + 600]
    # the join window, or no package
    assert 'JOIN="$WORK/root/Library/Oarbank/share/join"' in text
    assert "for f in join-window.py join-window.html; do" in text and '"$REPO/deploy/node/$f"' in text
    assert "the package has no join window" in text and "exit 1" in text
    assert 'install -m 644 "$REPO/deploy/macos/dev.codonic.oarbank.agent.policy.plist" "$WORK/root/Library/LaunchDaemons/"' in text
    # root:wheel for the daemon's plist (launchd refuses another owner) and a bundle pinned to /Applications
    assert text.count("--ownership recommended") == 1
    assert "BundleIsRelocatable\" -bool NO" in text and '--component-plist "$WORK/components.plist"' in text
    # the hand-made Bom (when ._ entries had to go) is root's too
    assert "cpio -o --format odc -R 0:0" in text and "\\t0/0\\n" in text


@pytest.mark.skipif(not os.environ.get("OARBANK_NODE_PKG"),
                    reason="set OARBANK_NODE_PKG to a pkg scripts/package-macos.sh built to inspect it")
def test_a_built_node_package_holds_the_app_the_join_window_and_the_policy_job(tmp_path):
    pkg = Path(os.environ["OARBANK_NODE_PKG"])
    files = set(subprocess.run(["pkgutil", "--payload-files", str(pkg)], capture_output=True, text=True, check=True).stdout.split("\n"))
    for f in ("./Applications/Oarbank Node.app/Contents/MacOS/Oarbank Node", "./Applications/Oarbank Node.app/Contents/Info.plist",
              "./Applications/Oarbank Node.app/Contents/Resources/oarbank.icns",
              "./Applications/Oarbank Node.app/Contents/_CodeSignature/CodeResources",
              "./Library/Oarbank/share/join/join-window.py", "./Library/Oarbank/share/join/join-window.html",
              "./Library/LaunchDaemons/dev.codonic.oarbank.agent.policy.plist", "./Library/Oarbank/bin/oarbank-launcher"):
        assert f in files, f
    assert not any("/Library/Oarbank/etc" in f or "/._" in f for f in files)
    subprocess.run(["pkgutil", "--expand-full", str(pkg), str(tmp_path / "x")], check=True)
    comp = next((tmp_path / "x").glob("*.pkg"))
    bom = subprocess.run(["lsbom", str(comp / "Bom")], capture_output=True, text=True, check=True).stdout
    daemon = next(line for line in bom.splitlines() if line.startswith("./Library/LaunchDaemons/dev.codonic.oarbank.agent.policy.plist"))
    assert daemon.split("\t")[1:3] == ["100644", "0/0"]
    info = (comp / "PackageInfo").read_text(encoding="utf-8")
    assert 'id="dev.codonic.oarbank.node"' in info and not re.search(r"<relocate>\s*<bundle", info)
    app = comp / "Payload/Applications/Oarbank Node.app"
    assert subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)]).returncode == 0
    signed = subprocess.run(["codesign", "-dv", str(app)], capture_output=True, text=True).stderr
    assert "Identifier=dev.codonic.oarbank.node" in signed
    # the runtime's interpreter carries exactly the library-validation entitlement and, signed as shipped, loads a
    # native wheel from PyPI that the build did not sign (needs PyPI)
    runtime = comp / "Payload/Library/Oarbank/bin/runtime"
    out = check_signing(*developer_id(runtime / "bin" / "python3"), "--canary", "--work", str(tmp_path / "canary"), str(runtime))
    assert out.returncode == 0, out.stderr


# ---------------------------------------------------------------------------------------------------------------------
# the interpreter's code signature: library validation off, so modules' third-party wheels load (docs/release-signing.md,
# "macOS code signatures")

ENTITLEMENTS = MACOS / "python.entitlements"
CODESIGN = REPO / "scripts" / "macos-codesign.sh"
CHECK_SIGNING = REPO / "scripts" / "check-macos-signing.py"
darwin = pytest.mark.skipif(sys.platform != "darwin", reason="codesign")


def check_signing(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CHECK_SIGNING), *args], capture_output=True, text=True, timeout=600)


def developer_id(python: Path) -> list[str]:
    """--developer-id when the interpreter carries a team's signature (a release build), else nothing (ad hoc)."""
    info = subprocess.run(["codesign", "-dvv", str(python)], capture_output=True, text=True).stderr
    return [] if "TeamIdentifier=not set" in info or "TeamIdentifier=" not in info else ["--developer-id"]


def test_the_interpreter_entitlements_turn_off_library_validation_and_nothing_else():
    with open(ENTITLEMENTS, "rb") as f:
        assert plistlib.load(f) == {"com.apple.security.cs.disable-library-validation": True}
    text = ENTITLEMENTS.read_text(encoding="utf-8")
    assert "https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation" in text
    assert "https://developer.apple.com/documentation/security/hardened-runtime" in text


def test_the_package_signs_its_interpreter_with_the_entitlements_and_checks_it():
    text = PACKAGE.read_text(encoding="utf-8")
    sign = 'macos_sign_tree "$ID" "$PAYLOAD/runtime"'
    assert 'source "$REPO/scripts/macos-codesign.sh"' in text and sign in text
    check = text.index('scripts/check-macos-signing.py"')
    # after the runtime is signed and before anything is packaged; a Developer ID build is checked as one, and the
    # canary loads a wheel from PyPI outside the payload
    assert text.index(sign) < check < text.index("pkgbuild --analyze")
    assert "--canary --work \"$WORK/canary\" \"$PAYLOAD/runtime\"" in text[check:check + 300]
    assert '[[ "$ID" == "-" ]] || DEVELOPER_ID=(--developer-id)' in text
    # nothing else signs the runtime's files (the loop that signed the interpreter like a library is gone)
    assert '--sign "$ID" "$f"' not in text
    helper = CODESIGN.read_text(encoding="utf-8")
    assert 'deploy/macos/python.entitlements"' in helper and '--entitlements "$OARBANK_PYTHON_ENTITLEMENTS"' in helper
    assert "codesign --force --options runtime --timestamp" in helper
    assert subprocess.run(["bash", "-n", str(CODESIGN)]).returncode == 0


@darwin
def test_only_the_interpreter_is_signed_with_the_entitlements_and_the_check_holds_to_exactly_that(tmp_path):
    # a tree shaped like the runtime: the interpreter (a copy of this one), its link, and another program (uv's place)
    root = tmp_path / "runtime"
    (root / "bin").mkdir(parents=True)
    python = root / "bin" / "python3.12"
    shutil.copyfile(os.path.realpath(sys.executable), python)
    os.symlink("python3.12", root / "bin" / "python3")
    shutil.copyfile("/bin/echo", root / "bin" / "uv")                 # contents only: /bin's files are restricted
    for f in (python, root / "bin" / "uv"):
        f.chmod(0o755)
        subprocess.run(["codesign", "--force", "--sign", "-", str(f)], check=True, capture_output=True)
    out = check_signing(str(root))                               # as 2.8.0 shipped it: no entitlements
    assert out.returncode == 1 and "python3.12: entitlements none" in out.stderr, out
    subprocess.run([str(CODESIGN), "tree", "-", str(root)], check=True)
    out = check_signing(str(root))
    assert out.returncode == 0, out.stderr
    assert "com.apple.security.cs.disable-library-validation" in out.stdout
    xml = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", str(python)], capture_output=True, check=True).stdout
    assert plistlib.loads(xml) == {"com.apple.security.cs.disable-library-validation": True}
    assert subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", str(root / "bin" / "uv")],
                          capture_output=True, check=True).stdout.strip() == b""
    # an ad hoc signature is not a release's: no hardened runtime, no team
    out = check_signing("--developer-id", str(root))
    assert out.returncode == 1 and "not signed with the hardened runtime by a Developer ID" in out.stderr
    # anything broader on the interpreter, or entitlements on another program, is refused
    broader = tmp_path / "broader.entitlements"
    with open(broader, "wb") as f:
        plistlib.dump({"com.apple.security.cs.disable-library-validation": True,
                       "com.apple.security.cs.allow-unsigned-executable-memory": True}, f)
    subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements", str(broader), str(python)], check=True, capture_output=True)
    out = check_signing(str(root))
    assert out.returncode == 1 and "allow-unsigned-executable-memory" in out.stderr
    subprocess.run([str(CODESIGN), "tree", "-", str(root)], check=True)
    subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements", str(ENTITLEMENTS), str(root / "bin" / "uv")],
                   check=True, capture_output=True)
    out = check_signing(str(root))
    assert out.returncode == 1 and "only the interpreters carry any" in out.stderr
    # a tree without an interpreter is no runtime
    assert "no Python interpreter found" in check_signing(str(root / "bin" / "uv")).stderr


@darwin
@pytest.mark.skipif(not os.environ.get("OARBANK_NODE_RUNTIME"),
                    reason="set OARBANK_NODE_RUNTIME to a node runtime signed by scripts/macos-codesign.sh (needs PyPI)")
def test_a_signed_node_runtime_loads_a_native_wheel_it_did_not_ship():
    root = Path(os.environ["OARBANK_NODE_RUNTIME"])
    out = check_signing(*developer_id(root / "bin" / "python3"), "--canary", str(root))
    assert out.returncode == 0, out.stderr
    assert "canary:" in out.stdout and "loaded _speedups" in out.stdout
