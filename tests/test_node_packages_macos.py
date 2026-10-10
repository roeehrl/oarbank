"""The macOS node package (docs/design/node-enrollment.md): the postinstall that installs without joining, the
managed-policy job, the root helper (its job, its request checks, its client requirement), Oarbank Node.app with its
--elevate mode, and what scripts/package-macos.sh ships. Nothing here installs, loads a launchd job, registers an
authorization right, asks for an administrator or writes outside pytest's temporary directories: the postinstall runs
against stand-ins for the system's tools and folders, and the Swift runs as a checker of its pure functions and as the
app's --elevate failing before it would ask anything."""
import json
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
HELPER_JOB = MACOS / "dev.codonic.oarbank.agent.helper.plist"
NODE_APP = MACOS / "node" / "NodeApp.swift"
ELEVATION = MACOS / "node" / "Elevation.swift"
HELPER = MACOS / "node" / "NodeHelper.swift"
SHARED = MACOS / "shared" / "MenuBar.swift"
COORDINATOR_APP = MACOS / "coordinator" / "Launcher.swift"
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
        helper = self.root / "Library/Oarbank/bin/oarbank-node-helper"
        helper.write_text('#!/bin/sh\necho "oarbank-node-helper $*" >> "$CALLS"\n', encoding="utf-8")
        helper.chmod(0o755)
        # the new launcher: records its arguments and HOME, and exits with $LAUNCHER_RC (0)
        launcher = self.root / "Library/Oarbank/bin/oarbank-launcher"
        launcher.write_text('#!/bin/sh\necho "oarbank-launcher $* HOME=$HOME" >> "$CALLS"\nexit "${LAUNCHER_RC:-0}"\n',
                            encoding="utf-8")
        launcher.chmod(0o755)
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
    # the helper's rights, then its job, before the join window opens (which may ask for it at once)
    helper = f"launchctl bootstrap system {mac.root}/Library/LaunchDaemons/dev.codonic.oarbank.agent.helper.plist"
    assert "oarbank-node-helper register-rights" in calls and helper in calls
    assert calls.index("register-rights") < calls.index("bootout system/dev.codonic.oarbank.agent.helper") \
        < calls.index(helper) < calls.index("open -a")
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
    assert "oarbank-node-helper register-rights" in calls  # a later join from the app needs the rights too


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
def test_an_upgrade_renders_the_service_again_and_restarts_it_in_either_scope(tmp_path):
    # a 2.8 job has no ExitTimeOut (launchd kills the agent 20 s into stopping its jobs): the new launcher renders it
    # again and restarts it (service refresh); only if it cannot is the old job kickstarted on the new launcher
    mac = Mac(tmp_path / "system")
    (mac.root / "Library/LaunchDaemons/dev.codonic.oarbank.agent.plist").write_text("<plist/>", encoding="utf-8")
    out, calls = mac.run()
    assert out.returncode == 0 and "open " not in calls
    assert "oarbank-launcher service refresh --system HOME=" in calls
    assert "kickstart -k system/dev.codonic.oarbank.agent\n" not in calls
    assert "launchctl kickstart -k gui/501/dev.codonic.oarbank.agent.session" in calls
    assert out.stdout.splitlines() == ["Oarbank: upgraded; the service restarted on the new launcher"]
    # an upgrade reloads the helper on its new binary and plist, and registers the rights again (new prompts)
    assert "oarbank-node-helper register-rights" in calls and "bootout system/dev.codonic.oarbank.agent.helper" in calls
    out, calls = Mac(tmp_path / "system").run(LAUNCHER_RC="1")
    assert "oarbank-launcher service refresh --system" in calls
    assert "launchctl kickstart -k system/dev.codonic.oarbank.agent\n" in calls
    mac = Mac(tmp_path / "personal")
    (mac.home / "Library/LaunchAgents/dev.codonic.oarbank.agent.plist").write_text("<plist/>", encoding="utf-8")
    out, calls = mac.run()
    assert out.returncode == 0 and "open " not in calls
    # as the person, with their HOME (which names their LaunchAgents), in their session (launchctl asuser runs it)
    assert (f"launchctl asuser 501 {mac.root}/stub/sudo -u pat /usr/bin/env HOME={mac.home} "
            f"{mac.root}/Library/Oarbank/bin/oarbank-launcher service refresh\n") in calls
    assert "kickstart" not in calls and "system/dev.codonic.oarbank.agent " not in calls + " "


@unix
def test_a_failing_launchctl_or_open_never_fails_the_install(tmp_path):
    mac = Mac(tmp_path)
    for name in ("launchctl", "open"):
        (mac.root / "stub" / name).write_text('#!/bin/sh\necho "nope $*" >&2\nexit 5\n', encoding="utf-8")
    (mac.root / "Library/Oarbank/bin/oarbank-node-helper").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    out, _ = mac.run()
    assert out.returncode == 0
    assert "Oarbank: Oarbank Node's administrator rights could not be registered; join with: sudo oarbank-node join" in out.stdout
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


def test_the_helper_job_is_an_on_demand_mach_service_of_root():
    with open(HELPER_JOB, "rb") as f:
        job = plistlib.load(f)
    assert job["Label"] == "dev.codonic.oarbank.agent.helper" and HELPER_JOB.name == job["Label"] + ".plist"
    # in /Library/Oarbank (root's alone), not in the app bundle an administrator can replace without a prompt
    assert job["ProgramArguments"] == ["/Library/Oarbank/bin/oarbank-node-helper", "serve"]
    assert job["MachServices"] == {"dev.codonic.oarbank.agent.helper": True}
    assert "RunAtLoad" not in job and "KeepAlive" not in job and "UserName" not in job and "Sockets" not in job
    assert job["StandardOutPath"] == job["StandardErrorPath"] == "/dev/null"
    # the Mach service the app connects to and the helper listens on are this label
    assert 'static let machService = "dev.codonic.oarbank.agent.helper"' in ELEVATION.read_text(encoding="utf-8")


def test_every_node_job_belongs_to_oarbank_node_in_login_items():
    # System Settings, Login Items, Allow in the Background groups launchd jobs by AssociatedBundleIdentifiers: without
    # it they show under the signing team's name, and switching that off silently stops the node
    for path in (POLICY, HELPER_JOB):
        with open(path, "rb") as f:
            assert plistlib.load(f)["AssociatedBundleIdentifiers"] == ["dev.codonic.oarbank.node"], path.name
    assert _info_plist()["CFBundleIdentifier"] == "dev.codonic.oarbank.node"
    text = PACKAGE.read_text(encoding="utf-8")
    assert 'plutil -extract AssociatedBundleIdentifiers.0 raw -o - "$REPO/deploy/macos/$job.plist")" == dev.codonic.oarbank.node' in text
    # the agent's own job and the session helper the launcher writes (svc_launchd.rs)
    launchd = (REPO / "rust/crates/oarbank-launcher/src/svc_launchd.rs").read_text(encoding="utf-8")
    assert 'const NODE_APP_BUNDLE: &str = "dev.codonic.oarbank.node";' in launchd
    assert "associated_bundle: Some(NODE_APP_BUNDLE.into())" in launchd and "Some(NODE_APP_BUNDLE));" in launchd


@pytest.mark.skipif(not shutil.which("plutil"), reason="macOS plutil")
def test_the_policy_job_lints():
    for job in (POLICY, HELPER_JOB):
        assert subprocess.run(["plutil", "-lint", str(job)], capture_output=True).returncode == 0, job


def test_the_uninstaller_removes_the_app_the_policy_job_and_oarbank_node():
    assert subprocess.run(["sh", "-n", str(UNINSTALL)]).returncode == 0
    text = UNINSTALL.read_text(encoding="utf-8")
    assert 'APP="/Applications/Oarbank Node.app"' in text and '/bin/rm -rf "$APP"' in text
    assert '/usr/bin/pkill -x "Oarbank Node"' in text and text.index("pkill") < text.index('rm -rf "$APP"')
    assert '/bin/launchctl bootout "system/$POLICY"' in text and '/bin/rm -f "/Library/LaunchDaemons/$POLICY.plist"' in text
    # the helper goes, and its authorization rights with it, before the programs (remove-rights is the helper's)
    assert "HELPER=dev.codonic.oarbank.agent.helper" in text
    assert '/bin/launchctl bootout "system/$HELPER"' in text and '/bin/rm -f "/Library/LaunchDaemons/$HELPER.plist"' in text
    assert '"$BIN/oarbank-node-helper" remove-rights' in text
    assert text.index("remove-rights") < text.index("/bin/rm -rf /Library/Oarbank")
    # the policy job goes before the node's removal, so no profile joins it again on the way out
    assert text.index("bootout") < text.index("oarbank-launcher\" remove")
    assert '[ "$(/usr/bin/readlink /usr/local/bin/oarbank-node 2>/dev/null)" = "$BIN/oarbank-launcher" ] && /bin/rm -f /usr/local/bin/oarbank-node' in text
    assert '/bin/rm -rf "/Library/Application Support/Oarbank/status"' in text
    assert "/bin/rm -rf /Library/Oarbank" in text and "pkgutil --forget dev.codonic.oarbank.agent" in text


# ---------------------------------------------------------------------------------------------------------------------
# Oarbank Node.app


def test_the_app_follows_the_launch_contract():
    swift = NODE_APP.read_text(encoding="utf-8")
    shared = SHARED.read_text(encoding="utf-8")
    for needle in ('"/Library/Application Support/Oarbank/status/node.json"', '"Library/Application Support/Oarbank/status/node.json"',
                   '"dev.codonic.oarbank.agent" as CFString', "CFPreferencesCopyAppValue",
                   'Oarbank.policy("AllowUserJoin") as? Bool != false', '"Waiting for approval"', '"Not joined"',
                   '"Connected to \\(host)"', '"Joining failed: \\(message)"', "SMAppService.mainApp.register()",
                   "SMAppService.mainApp.unregister()", ".requiresApproval", "isTemplate = true"):
        assert needle in shared, needle
    for needle in ('"\\(installRoot)/bin/runtime/bin/python3"', '"\\(installRoot)/share/join/join-window.py"',
                   '"\\(installRoot)/bin/oarbank-launcher"', '["-I", joinWindow, "--launcher", launcher]', '["--link", $0]',
                   'CommandLine.arguments.contains("--join")', 'CommandLine.arguments.contains("--settings")', "kAEGetURL",
                   "kInternetEventClass", "setActivationPolicy(.accessory)", 'keyEquivalent: ","', '"Join this Mac…"', '"Status…"',
                   '"Managed by \\(', "withTimeInterval: 30", "Timer(timeInterval: 5", "applicationShouldHandleReopen",
                   'menuBarGlyph("oarbank-node-symbolic")'):
        assert needle in swift, needle
    # it never handles a code itself: a link goes to the join window, which asks before anything joins; --elevate only
    # relays the join window's code from its standard input to the helper
    assert "JoinCode" not in swift and "--code-file" not in swift and "--code " not in swift
    assert '(Bundle.main.executablePath.map { ["--elevator", $0] } ?? [])' in swift
    assert 'if args.first == "--elevate" { exit(elevate(Array(args.dropFirst()))) }' in swift
    assert "FileHandle.standardInput.readData(ofLength: Elevation.maxCode + 1)" in swift
    assert "O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC" in swift and 'xpc_dictionary_set_fd(message, "progress", progress)' in swift
    assert "XPC_CONNECTION_MACH_SERVICE_PRIVILEGED" in swift and "withExtendedLifetime(delegate)" in swift
    # no shortcut around the helper: no osascript, no AuthorizationExecuteWithPrivileges, no shell
    for banned in ("osascript", "AuthorizationExecuteWithPrivileges", "/bin/sh", "do shell script"):
        for f in (NODE_APP, ELEVATION, HELPER, SHARED):
            assert banned not in f.read_text(encoding="utf-8"), (banned, f.name)


def test_the_app_has_one_menu_bar_setting_and_never_says_quit_for_the_node():
    swift = NODE_APP.read_text(encoding="utf-8")
    shared = SHARED.read_text(encoding="utf-8")
    # one setting: shown means the app's login item is registered; the first launch turns it on; policy decides instead
    assert '"Show Oarbank Node in the menu bar"' in swift
    assert 'MenuBarSetting(managed: { Oarbank.policyBool("ShowStatusIcon") })' in swift
    assert "var isOn: Bool { managed ?? registered }" in shared
    assert "if allowFirstLaunch && managed == nil { try? set(true) }" in shared and "if let managed { try? set(managed) }" in shared
    # the old two-meaning preference is gone: no "Start automatically at sign-in", no unconditional Login Items button
    for gone in ("Start automatically at sign-in", "Applies to your account", "Quit Oarbank Node\", action: #selector(quitApp)",
                 "oarbank-symbolic\""):
        assert gone not in swift, gone
    # Hide from Menu Bar takes ⌘Q, says the node keeps running, and turns the setting off
    assert '"Hide from Menu Bar", action: #selector(hideFromMenuBar), keyEquivalent: "q"' in swift
    assert 'hide.subtitle = "This Mac\'s node keeps running"' in swift
    assert "setMenuBar(false)" in swift and "NSApp.terminate(nil)" in swift
    # the window: the node's two sections, the service in plain words, and the fix action only when macOS needs one
    assert '("This Mac’s node", node), ("Menu bar", menuBar)' in swift
    assert "Running as a system service — starts with the Mac, before anyone signs in, and keeps running when this app quits." in shared
    assert "The node is turned off in Login Items → Allow in the Background. Turn Oarbank Node back on there." in shared
    assert "SMAppService.statusForLegacyPlist(at: URL(fileURLWithPath: path)) == .requiresApproval" in shared
    assert '"/Library/LaunchDaemons/dev.codonic.oarbank.agent.plist"' in shared
    assert "approvalButton.isHidden = !(managed == nil && !coordinatorHere && setting.needsApproval)" in swift
    assert 'menuBarNote.stringValue = "Managed by \\(organization ?? "your organization")."' in swift
    # one item per Mac: where Oarbank Coordinator is, the node shows none and opens nothing at login
    assert "let show = setting.isOn && !coordinatorHere" in swift
    assert "if coordinatorHere { try? setting.set(false) } else { setting.launched() }" in swift
    assert "static var coordinatorBundleID: String { coordinatorBundleBase + buildSuffix }" in shared
    assert 'static let coordinatorBundleBase = "dev.codonic.oarbank.coordinator"' in shared
    # with nothing left to show, the app quits; the node is never stopped from here
    assert "guard statusItem == nil, window?.isVisible != true, child?.isRunning != true else { return }" in swift
    for word in ("launchctl", "bootout", "kickstart"):
        assert word not in swift and word not in shared, word


def test_the_coordinator_app_shares_the_model_and_shows_this_macs_node():
    swift = COORDINATOR_APP.read_text(encoding="utf-8")
    assert "@main" in swift and "private let setting = MenuBarSetting()" in swift
    assert '"Show Oarbank Coordinator in the menu bar"' in swift and 'menuBarGlyph("oarbank-coordinator-symbolic")' in swift
    assert '"Hide from Menu Bar", action: #selector(hideFromMenuBar), keyEquivalent: "q"' in swift
    assert 'hide.subtitle = "The coordinator keeps running"' in swift
    assert 'NSMenuItem.sectionHeader(title: "This Mac’s Node")' in swift
    assert 'Oarbank.open(Oarbank.nodeBundleID, arguments: ["--join"])' in swift and "Oarbank.open(Oarbank.nodeBundleID)" in swift
    assert 'CommandLine.arguments.contains("--open-web")' in swift
    # the coordinator's system daemons (coordinator-system-service.md); a 2.8 per-user coordinator is offered the move
    assert '"/Library/LaunchDaemons/dev.codonic.oarbank.\\($0).plist"' in swift and "switchedOffInLoginItems(coordinatorJobPlists)" in swift
    assert '"Move the Coordinator to a System Service…"' in swift and 'operation == "migrate" ? ["--migrate"]' in swift
    assert "Runs as a system service — starts with the Mac, before anyone logs in, as _oarbankd" in swift
    for gone in ("Start automatically at sign-in", "Quit Oarbank Coordinator\", action:", "oarbank-symbolic\""):
        assert gone not in swift, gone
    # Oarbank Node's Open Console opens it
    assert 'Oarbank.open(Oarbank.coordinatorBundleID, arguments: ["--open-web"])' in NODE_APP.read_text(encoding="utf-8")


def test_the_menu_bar_glyphs_are_two_rendered_template_pairs():
    icons = REPO / "deploy/icons"
    assert not (icons / "oarbank-symbolic.png").exists()
    for name in ("oarbank-node-symbolic", "oarbank-coordinator-symbolic"):
        svg = (icons / f"{name}.svg").read_text(encoding="utf-8")
        assert 'viewBox="0 0 18 18"' in svg and "currentColor" in svg
        for suffix, size in (("", 18), ("@2x", 36)):
            data = (icons / f"{name}{suffix}.png").read_bytes()
            assert data[:8] == b"\x89PNG\r\n\x1a\n"
            assert int.from_bytes(data[16:20], "big") == int.from_bytes(data[20:24], "big") == size, (name, suffix)
    # different drawings: one oar (a machine) and three (the fleet)
    node, coordinator = ((icons / f"oarbank-{n}-symbolic.svg").read_text(encoding="utf-8") for n in ("node", "coordinator"))
    assert node.count("z") == 1 and coordinator.count("z") == 3
    assert (icons / "oarbank-node-symbolic.png").read_bytes() != (icons / "oarbank-coordinator-symbolic.png").read_bytes()
    script = (REPO / "scripts/render-menu-bar-icons.swift").read_text(encoding="utf-8")
    assert '["oarbank-node-symbolic", "oarbank-coordinator-symbolic"]' in script and '[(1, ""), (2, "@2x")]' in script


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("xcrun"), reason="Apple toolchain")
def test_the_rendered_glyphs_match_their_svgs(tmp_path):
    # rendering is deterministic: the committed PNGs are what the script makes from the committed SVGs
    work = tmp_path / "repo"
    (work / "deploy/icons").mkdir(parents=True)
    (work / "scripts").mkdir()
    shutil.copy(REPO / "scripts/render-menu-bar-icons.swift", work / "scripts")
    for svg in (REPO / "deploy/icons").glob("*-symbolic.svg"):
        shutil.copy(svg, work / "deploy/icons")
    r = subprocess.run(["xcrun", "swift", str(work / "scripts/render-menu-bar-icons.swift")], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    for png in (work / "deploy/icons").glob("*.png"):
        assert png.read_bytes() == (REPO / "deploy/icons" / png.name).read_bytes(), png.name


def test_the_helper_checks_the_client_the_request_and_the_launcher():
    helper = HELPER.read_text(encoding="utf-8")
    for needle in ("xpc_connection_set_peer_code_signing_requirement(peer, requirement)",
                   "XPC_CONNECTION_MACH_SERVICE_LISTENER", "AuthorizationCreateFromExternalForm",
                   "[.extendRights, .interactionAllowed]", "kAuthorizationEnvironmentPrompt", "kAuthorizationEnvironmentIcon",
                   "errAuthorizationCanceled", "xpc_dictionary_dup_fd(message, \"progress\")", "st.st_nlink == 1",
                   "st.st_uid == uid", "xpc_connection_get_euid(peer)", "st.st_uid == 0 && (st.st_mode & 0o022) == 0",
                   "POSIX_SPAWN_CLOEXEC_DEFAULT", "posix_spawn_file_actions_adddup2(&actions, progress, 3)",
                   "posix_spawn_file_actions_adddup2(&actions, pipeFDs[0], 0)", '"HOME=/var/root"', "signal(SIGPIPE, SIG_IGN)",
                   "AuthorizationRightSet(", "AuthorizationRightRemove(", 'case "register-rights"', 'case "remove-rights"',
                   'case "requirement"', 'case "serve"', "Elevation.launcherArguments(request)"):
        assert needle in helper, needle
    # the code never reaches an argv: it goes to the launcher's standard input only
    assert "request.code" in helper and helper.count("request.code") == 1 and "stdin: request.code" in helper


apple = pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("xcrun"), reason="Apple toolchain")


def swiftc(out: Path, *sources: Path, frameworks=("Security",)):
    """Compile as package-macos.sh does (-O, -parse-as-library, macOS 15) and check what it requires of the result."""
    cmd = ["xcrun", "swiftc", "-O", "-parse-as-library", "-target", f"{platform.machine()}-apple-macos15.0"]
    for f in frameworks:
        cmd += ["-framework", f]
    result = subprocess.run([*cmd, *map(str, sources), "-o", str(out)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "warning:" not in result.stderr, result.stderr
    build = subprocess.run(["xcrun", "vtool", "-show-build", str(out)], capture_output=True, text=True, check=True)
    assert "minos 15.0" in build.stdout
    loads = subprocess.run(["otool", "-l", str(out)], capture_output=True, text=True, check=True).stdout
    assert "LC_BUILD_VERSION" in loads and "minos 15.0" in loads
    # check-package.py refuses a binary that names the checkout or the build account's home
    data = out.read_bytes()
    assert str(REPO).encode() not in data and str(Path.home()).encode() not in data
    return out


@pytest.fixture(scope="module")
def node_app(tmp_path_factory):
    out = tmp_path_factory.mktemp("app") / "Oarbank Node"
    return swiftc(out, NODE_APP, ELEVATION, SHARED, frameworks=("AppKit", "ServiceManagement", "Security"))


def helper_build(tmp_path: Path, pin: str) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    build = tmp_path / "HelperBuild.swift"
    build.write_text(f"let helperClientPin: Elevation.ClientPin = {pin}\n", encoding="utf-8")
    return swiftc(tmp_path / "oarbank-node-helper", HELPER, ELEVATION, build)


@apple
def test_the_app_compiles_for_macos_15(node_app):
    assert node_app.is_file()


@apple
def test_the_helper_compiles_for_macos_15_and_says_what_it_requires(tmp_path):
    helper = helper_build(tmp_path / "id", '.developerID(team: "MKNM96EU7J")')
    r = subprocess.run([str(helper), "requirement"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == (
        'anchor apple generic and identifier "dev.codonic.oarbank.node" and certificate 1[field.1.2.840.113635.100.6.2.6] '
        'exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MKNM96EU7J"')
    # the requirement compiles (csreq is the system's requirement compiler)
    req = tmp_path / "req.bin"
    assert subprocess.run(["csreq", "-r", f"={r.stdout.strip()}", "-b", str(req)]).returncode == 0
    adhoc = helper_build(tmp_path / "adhoc", '.adHoc(cdhash: "' + "ab" * 20 + '")')
    out = subprocess.run([str(adhoc), "requirement"], capture_output=True, text=True).stdout.strip()
    assert out == 'identifier "dev.codonic.oarbank.node" and cdhash H"' + "ab" * 20 + '"'
    # a malformed pin, or an unknown command: it runs nothing
    bad = helper_build(tmp_path / "bad", '.developerID(team: "not a team")')
    assert subprocess.run([str(bad), "serve"], capture_output=True).returncode == 78
    assert subprocess.run([str(adhoc)], capture_output=True).returncode == 64
    assert subprocess.run([str(adhoc), "join"], capture_output=True).returncode == 64


@apple
def test_an_ad_hoc_app_satisfies_the_requirement_its_helper_pins(tmp_path, node_app):
    # what package-macos.sh does for a local package: sign the app ad hoc, pin its cdhash, check with codesign -R
    app = tmp_path / "Oarbank Node.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    shutil.copy(node_app, app / "Contents/MacOS/Oarbank Node")
    info = _info_plist()
    with open(app / "Contents/Info.plist", "wb") as f:
        plistlib.dump(info, f)
    subprocess.run(["codesign", "--force", "--identifier", "dev.codonic.oarbank.node", "--sign", "-", str(app)], check=True,
                   capture_output=True)
    shown = subprocess.run(["codesign", "-dvvv", str(app)], capture_output=True, text=True).stderr
    cdhash = re.search(r"^CDHash=([0-9a-f]{40})$", shown, re.M).group(1)
    helper = helper_build(tmp_path, f'.adHoc(cdhash: "{cdhash}")')
    requirement = subprocess.run([str(helper), "requirement"], capture_output=True, text=True, check=True).stdout.strip()
    assert subprocess.run(["codesign", "--verify", "--strict", f"-R={requirement}", str(app)], capture_output=True).returncode == 0
    # another build of the app (here: the same one signed under another identifier) does not
    subprocess.run(["codesign", "--force", "--identifier", "dev.codonic.other", "--sign", "-", str(app)], check=True,
                   capture_output=True)
    assert subprocess.run(["codesign", "--verify", "--strict", f"-R={requirement}", str(app)], capture_output=True).returncode != 0
    # nor would a Developer ID requirement accept an ad-hoc app
    team = subprocess.run([str(helper_build(tmp_path / "t", '.developerID(team: "MKNM96EU7J")')), "requirement"],
                          capture_output=True, text=True, check=True).stdout.strip()
    assert subprocess.run(["codesign", "--verify", f"-R={team}", str(app)], capture_output=True).returncode != 0


# The pure functions both programs share (Elevation.swift), run by a checker compiled with them: the request the helper
# accepts, the argv it builds, the app's --elevate grammar, the rights and the pins.
CHECKS = r'''
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok { failures += 1; print("FAIL \(line): \(what)") }
}

@main
struct Checks {
    static func main() {
        typealias F = Elevation.Field
        let code = "OB2-ABCDEFGH"
        let join: [String: F] = ["op": .string("join"), "auth": .other, "progress": .other, "code": .string(" \(code)\n")]
        guard case .success(let r) = Elevation.request(join) else { check(false, "a plain join"); exit(1) }
        check(r == Elevation.Request(op: .join, code: code, name: nil, containers: false), "join request")
        check(Elevation.launcherArguments(r) == ["/Library/Oarbank/bin/oarbank-launcher", "join", "--scope", "system",
              "--code-stdin", "--no-input", "--no-wait", "--progress-file", "/dev/fd/3"], "join argv")
        var named = join
        named["name"] = .string("build-07"); named["containers"] = .bool(true)
        if case .success(let n) = Elevation.request(named) {
            check(Elevation.launcherArguments(n).suffix(3) == ["--containers", "--name", "build-07"], "name and containers")
            check(!Elevation.launcherArguments(n).contains(where: { $0.contains(code) }), "the code is never an argument")
        } else { check(false, "a named join") }
        let leave: [String: F] = ["op": .string("leave"), "auth": .other, "progress": .other]
        if case .success(let l) = Elevation.request(leave) {
            check(Elevation.launcherArguments(l) == ["/Library/Oarbank/bin/oarbank-launcher", "leave", "--progress-file", "/dev/fd/3"], "leave argv")
        } else { check(false, "a leave") }
        // refused: each a request the helper never authorizes or runs
        var bad: [[String: F]] = []
        bad.append(join.merging(["op": .string("remove")]) { $1 })
        bad.append(join.merging(["op": .bool(true)]) { $1 })
        bad.append(join.filter { $0.key != "auth" })
        bad.append(join.filter { $0.key != "progress" })
        bad.append(join.filter { $0.key != "code" })
        bad.append(join.merging(["code": .string("   ")]) { $1 })
        bad.append(join.merging(["code": .string("OB2-\u{7f}")]) { $1 })
        bad.append(join.merging(["code": .string("OB2-\u{1b}[2J")]) { $1 })
        bad.append(join.merging(["code": .string(String(repeating: "A", count: 4097))]) { $1 })
        bad.append(join.merging(["code": .bool(true)]) { $1 })
        for name in ["-x", "a b", "a/b", "..", String(repeating: "a", count: 64), "", "naïve", "a;rm"] {
            bad.append(join.merging(["name": .string(name)]) { $1 })
        }
        bad.append(join.merging(["name": .bool(true)]) { $1 })
        bad.append(join.merging(["containers": .string("yes")]) { $1 })
        bad.append(join.merging(["argv": .string("--force")]) { $1 })
        bad.append(join.merging(["launcher": .string("/tmp/x")]) { $1 })
        bad.append(leave.merging(["code": .string(code)]) { $1 })
        bad.append(leave.merging(["name": .string("x")]) { $1 })
        for (i, b) in bad.enumerated() {
            if case .success = Elevation.request(b) { check(false, "bad request \(i) accepted") }
        }
        check(Elevation.validName("a") && Elevation.validName("Build-07.lab_2") && Elevation.validName(String(repeating: "a", count: 63)), "good names")
        // the app's --elevate grammar: the join window's two command lines, in any order, and nothing else
        let p = "/private/var/folders/x/T/oarbank-join-501/oarbank-join-1/progress.jsonl"
        let window = ["join", "--code-stdin", "--no-input", "--no-wait", "--progress-file", p, "--scope", "system", "--name", "build-07"]
        check(Elevation.command(window) == Elevation.Command(op: .join, progress: p, name: "build-07", containers: false), "window join")
        check(Elevation.command(["join", "--scope", "system", "--progress-file", p, "--no-wait", "--no-input", "--code-stdin", "--containers"])
              == Elevation.Command(op: .join, progress: p, name: nil, containers: true), "any order")
        check(Elevation.command(["leave", "--progress-file", p]) == Elevation.Command(op: .leave, progress: p), "window leave")
        let refused: [[String]] = [[], ["--elevate"], ["remove", "--progress-file", p],
            Array(window.dropLast(2)).filter { $0 != "--code-stdin" },            // the code must come on stdin
            window.filter { $0 != "--no-wait" }, window.filter { $0 != "--no-input" },
            window.map { $0 == "system" ? "personal" : $0 },                       // only the system service elevates
            window.map { $0 == p ? "progress.jsonl" : $0 },                        // an absolute path
            window + ["--code-file", "/tmp/code"], window + ["--force"], window + ["--name", "again"],
            window.map { $0 == "build-07" ? "-rf" : $0 }, ["join", "--progress-file"],
            ["leave", "--progress-file", p, "--name", "x"], ["leave", "--progress-file", p, "--code-stdin"], ["leave"],
            ["leave", "--progress-file", "/" + String(repeating: "a", count: 1024)]]
        for (i, args) in refused.enumerated() { check(Elevation.command(args) == nil, "command line \(i) accepted: \(args)") }
        // the rights: an administrator every time, nothing cached or shared, the operation's own prompt
        for op in Elevation.Operation.allCases {
            let d = Elevation.rightDefinition(op)
            check(op.right == "dev.codonic.oarbank.node.\(op.rawValue)", "right name")
            check(d["class"] as? String == "user" && d["group"] as? String == "admin" && d["timeout"] as? Int == 0
                  && d["shared"] as? Bool == false && d["allow-root"] as? Bool == false && d["authenticate-user"] as? Bool == true, "rule")
            check((d["default-prompt"] as? [String: String])?[""] == op.prompt, "prompt")
        }
        check(Elevation.Operation.join.prompt == "Oarbank Node wants to join this Mac to an Oarbank fleet.", "join prompt")
        check(Elevation.Operation.leave.prompt == "Oarbank Node wants to make this Mac leave its Oarbank fleet.", "leave prompt")
        // the pins: a team or a cdhash, nothing that could widen the requirement
        check(Elevation.requirement(.developerID(team: "MKNM96EU7J"))?.hasSuffix("certificate leaf[subject.OU] = \"MKNM96EU7J\"") == true, "team")
        for t in ["MKNM96EU7", "mknm96eu7j", "MKNM96EU7J\" or true", "MKNM96EU7JX", ""] {
            check(Elevation.requirement(.developerID(team: t)) == nil, "team \(t)")
        }
        check(Elevation.requirement(.adHoc(cdhash: String(repeating: "A", count: 64))) == "identifier \"dev.codonic.oarbank.node\" and cdhash H\"\(String(repeating: "a", count: 64))\"", "cdhash")
        for h in ["", "abc", String(repeating: "g", count: 40), String(repeating: "a", count: 40) + "\" or true"] {
            check(Elevation.requirement(.adHoc(cdhash: h)) == nil, "cdhash \(h)")
        }
        print(failures == 0 ? "ok" : "\(failures) failed")
        exit(failures == 0 ? 0 : 1)
    }
}
'''


@apple
def test_the_elevation_contract(tmp_path):
    checks = tmp_path / "Checks.swift"
    checks.write_text(CHECKS, encoding="utf-8")
    binary = swiftc(tmp_path / "checks", ELEVATION, checks, frameworks=())
    r = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stdout + r.stderr


@apple
def test_elevate_refuses_before_it_asks_for_anything(tmp_path, node_app):
    # every failure here comes before the app reads the authorization database or reaches the helper: nothing on this
    # Mac is asked or changed
    progress = tmp_path / "progress.jsonl"
    progress.write_text("")
    progress.chmod(0o600)
    def elevate(*args, stdin=""):
        return subprocess.run([str(node_app), "--elevate", *args], input=stdin, capture_output=True, text=True, timeout=30)
    join = ["join", "--code-stdin", "--no-input", "--no-wait", "--progress-file", str(progress), "--scope", "system"]
    assert elevate().returncode == 2 and "usage" in elevate().stderr
    assert elevate(*join[:-1], "personal").returncode == 2
    assert elevate(*join, "--name", "-x").returncode == 2
    # a progress file that is a link, missing, or not a regular file: refused, nothing written through it
    link = tmp_path / "link.jsonl"
    link.symlink_to(progress)
    for path in (link, tmp_path / "missing.jsonl", tmp_path):
        r = elevate(*[str(path) if a == str(progress) else a for a in join], stdin=SECRET)
        assert r.returncode == 2 and SECRET not in r.stdout + r.stderr, path
    assert progress.read_text() == ""
    # no code on standard input: a result line the join window shows, never the code
    for stdin in ("", "   \n", "OB2-\x1b[2J", "A" * 4097):
        progress.write_text("")
        r = elevate(*join, stdin=stdin)
        assert r.returncode == 2 and r.stdout == ""
        (line,) = progress.read_text().splitlines()
        assert json.loads(line) == {"type": "result", "ok": False, "exit": 2, "code": "E_CODE_FORMAT",
                                    "message": "Paste the join code from your Oarbank console."}


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
    assert (REPO / "deploy/icons/oarbank-node-symbolic.png").is_file() and (REPO / "deploy/icons/oarbank-node-symbolic@2x.png").is_file()


# ---------------------------------------------------------------------------------------------------------------------
# scripts/package-macos.sh


def test_the_package_builds_signs_and_ships_the_app_the_join_window_and_the_policy_job():
    text = PACKAGE.read_text(encoding="utf-8")
    assert "Oarbank/etc" not in text
    assert 'APP="$WORK/root/Applications/Oarbank Node.app"' in text
    assert 'xcrun swiftc -O -parse-as-library -target "$ARCH-apple-macos15.0" -framework AppKit -framework ServiceManagement' in text
    assert '"$REPO/deploy/macos/node/NodeApp.swift" "$REPO/deploy/macos/node/Elevation.swift"' in text
    assert '"$REPO/deploy/macos/shared/MenuBar.swift" -o "$APP/Contents/MacOS/Oarbank Node"' in text
    assert ('cp "$REPO/deploy/icons/oarbank.icns" "$REPO/deploy/icons/oarbank-node-symbolic.png" '
            '"$REPO/deploy/icons/oarbank-node-symbolic@2x.png" "$APP/Contents/Resources/"') in text
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
    assert "for job in dev.codonic.oarbank.agent.policy dev.codonic.oarbank.agent.helper; do" in text
    assert 'plutil -lint -s "$REPO/deploy/macos/$job.plist"' in text
    assert 'install -m 644 "$REPO/deploy/macos/$job.plist" "$WORK/root/Library/LaunchDaemons/"' in text
    # root:wheel for the daemon's plist (launchd refuses another owner) and a bundle pinned to /Applications
    assert text.count("--ownership recommended") == 1
    assert "BundleIsRelocatable\" -bool NO" in text and '--component-plist "$WORK/components.plist"' in text
    # the hand-made Bom (when ._ entries had to go) is root's too
    assert "cpio -o --format odc -R 0:0" in text and "\\t0/0\\n" in text


def test_the_package_builds_the_helper_for_the_app_it_signed():
    text = PACKAGE.read_text(encoding="utf-8")
    # after the app is signed (its cdhash is the ad-hoc pin), before the payload is packaged
    helper = text.index('-o "$PAYLOAD/oarbank-node-helper"')
    assert text.index('--identifier dev.codonic.oarbank.node --sign "$ID" "$APP"') < helper < text.index("pkgbuild --analyze")
    assert '"$REPO/deploy/macos/node/NodeHelper.swift" "$REPO/deploy/macos/node/Elevation.swift" "$WORK/HelperBuild.swift"' in text
    assert "cdhash=\"$(codesign -dvvv \"$APP\" 2>&1 | sed -n 's/^CDHash=//p')\"" in text
    assert 'pin=".adHoc(cdhash: \\"$cdhash\\")"' in text and 'pin=".developerID(team: \\"$team\\")"' in text
    assert 'team="${OARBANK_TEAM_ID:-MKNM96EU7J}"' in text
    # checked like the other binaries, signed under its identifier (hardened with a Developer ID), and the app it
    # serves satisfies its requirement
    assert 'check-package.py" --build-path "$WORK" --platform "$PLATFORM" \\\n    "$PAYLOAD/oarbank-node-helper"' in text
    assert ('codesign --force --options runtime --timestamp --identifier dev.codonic.oarbank-node-helper --sign "$ID" '
            '"$PAYLOAD/oarbank-node-helper"') in text
    assert 'codesign --force --identifier dev.codonic.oarbank-node-helper --sign - "$PAYLOAD/oarbank-node-helper"' in text
    assert 'requirement="$("$PAYLOAD/oarbank-node-helper" requirement)"' in text
    assert 'codesign --verify --strict -R="$requirement" "$APP"' in text


@pytest.mark.skipif(not os.environ.get("OARBANK_NODE_PKG"),
                    reason="set OARBANK_NODE_PKG to a pkg scripts/package-macos.sh built to inspect it")
def test_a_built_node_package_holds_the_app_the_join_window_and_the_policy_job(tmp_path):
    pkg = Path(os.environ["OARBANK_NODE_PKG"])
    files = set(subprocess.run(["pkgutil", "--payload-files", str(pkg)], capture_output=True, text=True, check=True).stdout.split("\n"))
    for f in ("./Applications/Oarbank Node.app/Contents/MacOS/Oarbank Node", "./Applications/Oarbank Node.app/Contents/Info.plist",
              "./Applications/Oarbank Node.app/Contents/Resources/oarbank.icns",
              "./Applications/Oarbank Node.app/Contents/Resources/oarbank-node-symbolic.png",
              "./Applications/Oarbank Node.app/Contents/Resources/oarbank-node-symbolic@2x.png",
              "./Applications/Oarbank Node.app/Contents/_CodeSignature/CodeResources",
              "./Library/Oarbank/share/join/join-window.py", "./Library/Oarbank/share/join/join-window.html",
              "./Library/LaunchDaemons/dev.codonic.oarbank.agent.policy.plist", "./Library/Oarbank/bin/oarbank-launcher",
              "./Library/LaunchDaemons/dev.codonic.oarbank.agent.helper.plist", "./Library/Oarbank/bin/oarbank-node-helper"):
        assert f in files, f
    assert not any("/Library/Oarbank/etc" in f or "/._" in f for f in files)
    subprocess.run(["pkgutil", "--expand-full", str(pkg), str(tmp_path / "x")], check=True)
    comp = next((tmp_path / "x").glob("*.pkg"))
    bom = subprocess.run(["lsbom", str(comp / "Bom")], capture_output=True, text=True, check=True).stdout
    for job in ("policy", "helper"):
        daemon = next(line for line in bom.splitlines() if line.startswith(f"./Library/LaunchDaemons/dev.codonic.oarbank.agent.{job}.plist"))
        assert daemon.split("\t")[1:3] == ["100644", "0/0"]
    helper_line = next(line for line in bom.splitlines() if line.startswith("./Library/Oarbank/bin/oarbank-node-helper"))
    assert helper_line.split("\t")[1:3] == ["100755", "0/0"]
    info = (comp / "PackageInfo").read_text(encoding="utf-8")
    assert 'id="dev.codonic.oarbank.node"' in info and not re.search(r"<relocate>\s*<bundle", info)
    app = comp / "Payload/Applications/Oarbank Node.app"
    assert subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)]).returncode == 0
    signed = subprocess.run(["codesign", "-dv", str(app)], capture_output=True, text=True).stderr
    assert "Identifier=dev.codonic.oarbank.node" in signed
    # the helper is signed under its identifier and serves exactly this app
    helper = comp / "Payload/Library/Oarbank/bin/oarbank-node-helper"
    assert "Identifier=dev.codonic.oarbank-node-helper" in subprocess.run(["codesign", "-dv", str(helper)], capture_output=True, text=True).stderr
    requirement = subprocess.run([str(helper), "requirement"], capture_output=True, text=True, check=True).stdout.strip()
    assert 'identifier "dev.codonic.oarbank.node"' in requirement
    assert subprocess.run(["codesign", "--verify", "--strict", f"-R={requirement}", str(app)]).returncode == 0
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
    if sys.platform != "win32":                         # Windows' bash is WSL's, which cannot open a D:\ path
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
