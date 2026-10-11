"""The Linux node package and the one-line installers (docs/design/node-enrollment.md, "Channels", "Linux package
variables"): what deploy/linux/nfpm.yaml ships, the maintainer scripts, the desktop entry, scripts/install/
oarbank-install.sh and .ps1, and scripts/package-install-scripts.sh. Nothing here installs a package, starts a service
or downloads anything: the maintainer scripts run as copies whose system paths point into pytest's temporary
directories, and the installer runs against stand-ins for uname, id, curl, the package managers and oarbank-node."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    pytest.skip("the Linux package's scripts and oarbank-install.sh are POSIX sh", allow_module_level=True)

REPO = Path(__file__).resolve().parents[1]
LINUX = REPO / "deploy" / "linux"
NFPM = LINUX / "nfpm.yaml"
POSTINSTALL = LINUX / "postinstall.sh"
PREREMOVE = LINUX / "preremove.sh"
POSTREMOVE = LINUX / "postremove.sh"
DESKTOP = LINUX / "node-desktop.desktop"
INSTALL_SH = REPO / "scripts" / "install" / "oarbank-install.sh"
INSTALL_PS1 = REPO / "scripts" / "install" / "oarbank-install.ps1"
PACKAGE_INSTALL = REPO / "scripts" / "package-install-scripts.sh"
SECRET = "OB2-0SECRETCODE0DONOTPRINT0"
URL = "https://coord.example:7443"
VERSION = "2.9.0"

SHELLS = ["sh"] + (["dash"] if shutil.which("dash") else [])


# ---------------------------------------------------------------------------------------------------------------------
# nfpm.yaml (no YAML library: the dev extras have none, and the file is a flat list)


def nfpm_contents():
    """contents: as a list of {key: raw value} (file_info stays its inline text)."""
    entries, inside = [], False
    for line in NFPM.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\S", line):
            inside = line.startswith("contents:")
            continue
        if not inside or not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^  (- )?\s*(\w+): (.*)$", line)
        assert m, line
        if m.group(1):
            entries.append({})
        entries[-1][m.group(2)] = m.group(3).strip()
    return entries


def by_dst():
    return {e["dst"]: e for e in nfpm_contents()}


def test_the_package_ships_the_node_cli_the_join_window_its_desktop_entry_and_icon():
    c = by_dst()
    assert c["/usr/bin/oarbank-node"] == {"src": "/usr/lib/oarbank/oarbank-launcher", "dst": "/usr/bin/oarbank-node", "type": "symlink"}
    assert c["/usr/bin/oarbank-launcher"]["type"] == "symlink"
    for f in ("join-window.py", "join-window.html"):
        e = c[f"/usr/lib/oarbank/join/{f}"]
        assert e["src"] == f"${{REPO}}/deploy/node/{f}" and "0644" in e["file_info"]
    e = c["/usr/share/applications/dev.codonic.oarbank.node.desktop"]
    assert e["src"] == "./node-desktop.desktop" and "0644" in e["file_info"]
    # the coordinator's artwork (coordinator-stage.py fills its ICON with docs/assets/logo.svg), named for the node
    e = c["/usr/share/icons/hicolor/scalable/apps/oarbank-node.svg"]
    assert e["src"] == "${REPO}/docs/assets/logo.svg"
    assert '"ICON": str(repo / "docs/assets/logo.svg")' in (LINUX / "coordinator-stage.py").read_text(encoding="utf-8")
    assert "/usr/share/icons/hicolor/scalable/apps/oarbank-coordinator.svg" in (LINUX / "coordinator-nfpm.yaml").read_text(encoding="utf-8")
    # an administrator's policy.json goes in /etc/oarbank, a directory the package owns
    assert c["/etc/oarbank"]["type"] == "dir" and "0755" in c["/etc/oarbank"]["file_info"]


def test_the_package_holds_no_hand_made_files_and_no_desktop_dependencies():
    text = NFPM.read_text(encoding="utf-8")
    assert "join-code" not in text and "/etc/oarbank/coordinator" not in text
    assert not any(d.startswith("/etc/oarbank/") for d in by_dst())
    # a headless node pulls no desktop libraries (the coordinator's package depends on GTK for its tray; this one must not)
    assert not re.search(r"^(depends|overrides):", text, re.M)
    assert not re.search(r"gtk|python3-gi|gobject|libayatana|appindicator", text, re.I)
    assert re.search(r"^recommends:\n  - podman$", text, re.M)
    scripts = dict(re.findall(r"^  (postinstall|preremove|postremove): \./(\S+)$", text, re.M))
    assert scripts == {"postinstall": "postinstall.sh", "preremove": "preremove.sh", "postremove": "postremove.sh"}
    for name in scripts.values():
        assert os.access(LINUX / name, os.X_OK), name


def test_every_file_the_package_names_exists_and_every_variable_is_filled_in():
    for e in nfpm_contents():
        src = e.get("src", "")
        if e.get("type") == "symlink" or not src or src.startswith(("${BIN_DIR}", "${RUNTIME_DIR}")):
            continue
        path = REPO / src.removeprefix("${REPO}/") if src.startswith("${REPO}/") else LINUX / src
        assert path.is_file(), src
    used = set(re.findall(r"\$\{(\w+)\}", NFPM.read_text(encoding="utf-8")))
    script = (REPO / "scripts" / "package-linux.sh").read_text(encoding="utf-8")
    filled = set(re.findall(r'-e "s\|\\\$\{(\w+)\}\|', script))
    assert used == {"ARCH", "VERSION", "BIN_DIR", "RUNTIME_DIR", "REPO"} and used <= filled, (used, filled)


def test_the_desktop_entry_opens_the_join_window_and_handles_oarbank_links():
    if shutil.which("desktop-file-validate"):
        r = subprocess.run(["desktop-file-validate", str(DESKTOP)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
    lines = DESKTOP.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "[Desktop Entry]"
    keys = dict(l.split("=", 1) for l in lines[1:] if l and not l.startswith("#"))
    assert keys["Type"] == "Application" and keys["Name"] == "Oarbank Node"
    assert keys["Comment"] == "Join this machine to an Oarbank fleet"
    assert keys["Exec"] == ("/usr/lib/oarbank/runtime/bin/python3 -I /usr/lib/oarbank/join/join-window.py "
                            "--launcher /usr/lib/oarbank/oarbank-launcher --link %u")
    assert keys["MimeType"] == "x-scheme-handler/oarbank;" and keys["Icon"] == "oarbank-node"
    assert keys["Terminal"] == "false" and keys["Categories"] == "System;Network;"
    # what Exec names is what the package installs there
    c = by_dst()
    assert "/usr/lib/oarbank/join/join-window.py" in c and "/usr/lib/oarbank/oarbank-launcher" in c
    assert c["/usr/lib/oarbank/runtime"]["type"] == "tree"


def test_the_polkit_actions_brand_the_join_windows_administrator_prompt():
    # the join window runs `pkexec /usr/lib/oarbank/oarbank-launcher join|leave …`: pkexec picks the action whose
    # exec.path and exec.argv1 match, and shows its message and icon instead of its generic "run … as the super user"
    import xml.etree.ElementTree as ET
    policy = LINUX / "dev.codonic.oarbank.node.policy"
    e = by_dst()["/usr/share/polkit-1/actions/dev.codonic.oarbank.node.policy"]
    assert e["src"] == "./dev.codonic.oarbank.node.policy" and "0644" in e["file_info"]
    text = policy.read_text(encoding="utf-8")
    assert '"-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"' in text
    root = ET.fromstring(text.encode())
    assert root.tag == "policyconfig" and root.findtext("vendor") == "Codonic" and root.findtext("icon_name") == "oarbank-node"
    actions = {a.get("id"): a for a in root.findall("action")}
    assert set(actions) == {"dev.codonic.oarbank.node.join", "dev.codonic.oarbank.node.leave"}
    messages = {"join": "Oarbank Node wants to join this computer to an Oarbank fleet.",
                "leave": "Oarbank Node wants to make this computer leave its Oarbank fleet."}
    for op, message in messages.items():
        a = actions[f"dev.codonic.oarbank.node.{op}"]
        assert a.findtext("message") == message and a.findtext("icon_name") == "oarbank-node" and a.findtext("description")
        # an administrator every time, never kept (auth_admin_keep would let the next request through unasked)
        assert {d.tag: d.text for d in a.find("defaults")} == {"allow_any": "auth_admin", "allow_inactive": "auth_admin",
                                                               "allow_active": "auth_admin"}
        notes = {n.get("key"): n.text for n in a.findall("annotate")}
        assert notes == {"org.freedesktop.policykit.exec.path": "/usr/lib/oarbank/oarbank-launcher",
                         "org.freedesktop.policykit.exec.argv1": op}
    # the program and the icon it names are what the package installs, and the program is the one the desktop entry
    # hands the join window
    c = by_dst()
    assert "/usr/lib/oarbank/oarbank-launcher" in c and "/usr/share/icons/hicolor/scalable/apps/oarbank-node.svg" in c
    assert "--launcher /usr/lib/oarbank/oarbank-launcher" in DESKTOP.read_text(encoding="utf-8")
    window = (REPO / "deploy/node/join-window.py").read_text(encoding="utf-8")
    assert "return [pkexec, *argv]" in window


# ---------------------------------------------------------------------------------------------------------------------
# maintainer scripts


@pytest.mark.parametrize("script", [POSTINSTALL, PREREMOVE, POSTREMOVE], ids=lambda p: p.name)
def test_the_maintainer_scripts_parse_in_posix_shells(script):
    for sh in SHELLS:
        r = subprocess.run([sh, "-n", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, (sh, r.stderr)
    assert script.read_text(encoding="ascii").startswith("#!/bin/sh\n")


def test_the_postinstall_has_no_hand_made_files_and_never_prints_the_code():
    text = POSTINSTALL.read_text(encoding="utf-8")
    assert "/etc/oarbank" not in text.replace("/etc/oarbank/policy.json", "") and "ETC=" not in text
    assert "printf '%s' \"$code\" | \"$L\" setup --scope system --join-code-stdin" in text
    assert '< "$code_file"' in text and "--join-code-file" not in text and "--join-code " not in text
    assert "Installed. Join this machine with: sudo oarbank-node join" in text
    for line in text.splitlines():
        if re.search(r"\b(echo|printf)\b", line) and "| \"$L\"" not in line:
            assert not re.search(r"\$\{?code\b(?!_)", line), line


def write_fake(path, body):
    path.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
    path.chmod(0o755)


# The stand-in launcher: each call appends its argv, standard input and whether OARBANK_JOIN_CODE reached it, and exits
# with the next code from rcs (the last one repeats).
FAKE_LAUNCHER = r"""import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
data = sys.stdin.read() if not sys.stdin.isatty() else ""
with open(os.path.join(d, "calls.jsonl"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "stdin": data, "env_code": os.environ.get("OARBANK_JOIN_CODE")}) + "\n")
rcs = open(os.path.join(d, "rcs")).read().split() if os.path.exists(os.path.join(d, "rcs")) else ["0"]
n = sum(1 for _ in open(os.path.join(d, "calls.jsonl")))
print("launcher: ok")
sys.exit(int(rcs[min(n, len(rcs)) - 1]))
"""

FAKE_TOOL = r"""import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(d, "tools.jsonl"), "a") as f:
    f.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\n")
"""


class Sandbox:
    """A maintainer script copied with its system paths moved under `root`: the launcher, the joined marker, systemd's
    run directory, /var/lib/oarbank and the applications folder; PATH holds only stand-ins."""

    def __init__(self, root: Path, script: Path):
        self.root, self.bin = root, root / "bin"
        self.bin.mkdir()
        self.launcher = self.bin / "oarbank-launcher"
        write_fake(self.launcher, FAKE_LAUNCHER)
        for tool in ("systemctl", "loginctl"):
            write_fake(self.bin / tool, FAKE_TOOL)
        os.symlink(shutil.which("rm"), self.bin / "rm")      # postremove's purge
        self.var = root / "var-lib-oarbank"
        self.systemd = root / "run-systemd-system"
        text = script.read_text(encoding="utf-8")
        for old, new in (("/usr/lib/oarbank/oarbank-launcher", str(self.launcher)), ("/var/lib/oarbank", str(self.var)),
                         ("/run/systemd/system", str(self.systemd)), ("/usr/share/applications", str(root / "apps"))):
            text = text.replace(old, new)
        self.script = root / script.name
        self.script.write_text(text, encoding="utf-8")

    def rcs(self, *codes):
        (self.bin / "rcs").write_text(" ".join(map(str, codes)))

    def run(self, *args, sh="sh", env=None):
        e = {"PATH": str(self.bin), "HOME": str(self.root)}
        e.update(env or {})
        return subprocess.run([shutil.which(sh), str(self.script), *args], env=e, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)

    def calls(self):
        p = self.bin / "calls.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def tools(self):
        p = self.bin / "tools.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


@pytest.fixture
def post(tmp_path):
    s = Sandbox(tmp_path, POSTINSTALL)
    s.systemd.mkdir()
    return s


@pytest.mark.parametrize("sh", SHELLS)
def test_a_code_reaches_setup_on_stdin_never_in_argv_or_the_output(post, sh):
    r = post.run(sh=sh, env={"OARBANK_JOIN_CODE": SECRET, "OARBANK_COORDINATOR": URL, "OARBANK_NAME": "build 07"})
    assert r.returncode == 0, r.stderr
    [call] = post.calls()
    assert call["argv"] == ["setup", "--scope", "system", "--join-code-stdin", "--coordinator", URL, "--name", "build 07"]
    assert call["stdin"] == SECRET and call["env_code"] is None
    assert SECRET not in r.stdout + r.stderr
    assert "joining with the code" in r.stdout


@pytest.mark.parametrize("sh", SHELLS)
def test_a_code_file_reaches_setup_on_stdin(post, sh, tmp_path):
    f = tmp_path / "code.txt"
    f.write_text(SECRET + "\n")
    r = post.run(sh=sh, env={"OARBANK_JOIN_CODE_FILE": str(f)})
    assert r.returncode == 0
    [call] = post.calls()
    assert call["argv"] == ["setup", "--scope", "system", "--join-code-stdin"] and call["stdin"] == SECRET + "\n"
    assert str(f) not in call["argv"] and SECRET not in r.stdout + r.stderr


@pytest.mark.parametrize("sh", SHELLS)
def test_without_a_code_it_installs_the_waiting_service_and_says_how_to_join(post, sh):
    r = post.run(sh=sh)
    assert r.returncode == 0
    assert [c["argv"] for c in post.calls()] == [["setup", "--scope", "system"]]
    assert r.stdout.strip().splitlines()[-1] == "Installed. Join this machine with: sudo oarbank-node join"


def test_a_coordinator_alone_joins_by_url(post):
    r = post.run(env={"OARBANK_COORDINATOR": URL})
    assert r.returncode == 0
    assert [c["argv"] for c in post.calls()] == [["setup", "--scope", "system", "--coordinator", URL]]
    assert URL in r.stdout


def test_a_refused_code_still_installs_the_waiting_service(post):
    post.rcs(1, 0)
    r = post.run(env={"OARBANK_JOIN_CODE": SECRET, "OARBANK_COORDINATOR": URL, "OARBANK_NAME": "n1"})
    assert r.returncode == 0
    first, second = post.calls()
    assert "--join-code-stdin" in first["argv"]
    assert second["argv"] == ["setup", "--scope", "system", "--name", "n1"] and second["stdin"] == ""
    assert SECRET not in r.stdout + r.stderr
    assert "Installed. Join this machine with: sudo oarbank-node join" in r.stdout


@pytest.mark.parametrize("sh", SHELLS)
def test_a_failing_setup_never_fails_the_package(post, sh):
    post.rcs(1)
    for env in ({"OARBANK_JOIN_CODE": SECRET}, {}):
        r = post.run(sh=sh, env=env)
        assert r.returncode == 0
        assert "failed" in r.stdout and "sudo oarbank-node join" in r.stdout
        assert SECRET not in r.stdout + r.stderr


def test_without_systemd_it_stages_without_a_service_and_exits_0(tmp_path):
    s = Sandbox(tmp_path, POSTINSTALL)                     # no run directory: systemd is not running
    r = s.run(env={"OARBANK_JOIN_CODE": SECRET})
    assert r.returncode == 0
    [call] = s.calls()
    assert call["argv"] == ["setup", "--scope", "system", "--join-code-stdin", "--no-service"] and call["stdin"] == SECRET
    assert "systemd is not running" in r.stdout and SECRET not in r.stdout + r.stderr


def test_an_upgrade_of_a_joined_node_renders_its_unit_again_and_runs_no_setup(post):
    # a 2.8 unit has no TimeoutStopSec: the new launcher renders it again (and restarts the service itself), so a stop
    # gives the agent the time to stop its jobs
    (post.var / "agent").mkdir(parents=True)
    (post.var / "agent" / "agent.json").write_text("{}")
    r = post.run(env={"OARBANK_JOIN_CODE": SECRET})
    assert r.returncode == 0 and [c["argv"] for c in post.calls()] == [["service", "refresh", "--system"]]
    assert post.tools() == [] and r.stdout.splitlines() == ["Oarbank: upgraded; the service restarted on the new launcher"]
    # a launcher that cannot refresh it (an edited unit): the service still restarts on the new launcher
    post.rcs(1)
    (post.bin / "calls.jsonl").unlink()
    r = post.run()
    assert r.returncode == 0 and [c["argv"] for c in post.calls()] == [["service", "refresh", "--system"]]
    assert ["systemctl", "try-restart", "dev.codonic.oarbank.agent.service"] in post.tools()


def test_containers_only_hint_at_podman_when_it_is_missing(post):
    r = post.run(env={"OARBANK_CONTAINERS": "1"})
    assert r.returncode == 0 and "podman" in r.stdout
    write_fake(post.bin / "podman", FAKE_TOOL)
    r = post.run(env={"OARBANK_CONTAINERS": "1"})
    assert "podman" not in r.stdout


def test_an_unreadable_code_file_installs_without_a_code(post, tmp_path):
    r = post.run(env={"OARBANK_JOIN_CODE_FILE": str(tmp_path / "missing")})
    assert r.returncode == 0 and "cannot be read" in r.stdout
    assert [c["argv"] for c in post.calls()] == [["setup", "--scope", "system"]]


@pytest.mark.parametrize("arg", ["upgrade", "failed-upgrade", "1", "2"])
def test_preremove_leaves_an_upgrade_alone(tmp_path, arg):
    s = Sandbox(tmp_path, PREREMOVE)
    r = s.run(arg)
    assert r.returncode == 0 and s.calls() == [] and s.tools() == []


@pytest.mark.parametrize("arg", ["remove", "deconfigure", "0"])
def test_preremove_removes_the_service_and_keeps_the_node(tmp_path, arg):
    s = Sandbox(tmp_path, PREREMOVE)
    s.rcs(1)                                               # a failing removal still lets the package go
    r = s.run(arg)
    assert r.returncode == 0
    assert [c["argv"] for c in s.calls()] == [["remove", "--scope", "system"]]
    assert ["loginctl", "disable-linger", "oarbank"] in s.tools()


@pytest.mark.parametrize("arg,kept", [("purge", False), ("remove", True), ("0", True), ("upgrade", True), ("1", True)])
def test_only_debs_purge_deletes_the_node(tmp_path, arg, kept):
    s = Sandbox(tmp_path, POSTREMOVE)
    (s.var / "agent" / "keys").mkdir(parents=True)
    r = s.run(arg)
    assert r.returncode == 0 and s.var.exists() == kept


# ---------------------------------------------------------------------------------------------------------------------
# package-install-scripts.sh


def package_install(out: Path, version=VERSION):
    return subprocess.run(["bash", str(PACKAGE_INSTALL), version, str(out)], capture_output=True, text=True)


def test_the_installers_get_the_version_lf_endings_and_their_sums(tmp_path):
    (tmp_path / f"SHA256SUMS-install-{VERSION}").write_text("abc  other-file\n")
    for v in (VERSION, "v" + VERSION):                       # twice: entries are replaced, not repeated
        r = package_install(tmp_path, v)
        assert r.returncode == 0, r.stderr
    sums = (tmp_path / f"SHA256SUMS-install-{VERSION}").read_bytes()
    assert b"\r" not in sums
    lines = sums.decode().splitlines()
    assert lines[0] == "abc  other-file" and len(lines) == 3
    for name in ("oarbank-install.sh", "oarbank-install.ps1"):
        data = (tmp_path / name).read_bytes()
        assert b"\r" not in data and b"@OARBANK_VERSION@" not in data and VERSION.encode() in data
        assert f"{hashlib.sha256(data).hexdigest()}  {name}" in lines
    assert f"OB_VERSION='{VERSION}'" in (tmp_path / "oarbank-install.sh").read_text()
    assert f"$Version = '{VERSION}'" in (tmp_path / "oarbank-install.ps1").read_text()
    assert os.access(tmp_path / "oarbank-install.sh", os.X_OK)


def test_package_install_scripts_refuses_a_bad_version(tmp_path):
    assert package_install(tmp_path, "2.8/0").returncode == 2
    assert not (tmp_path / "oarbank-install.sh").exists()


def test_ci_publishes_the_installers_with_the_linux_packages():
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = ci[ci.index("\n  package-linux:"):ci.index("\n  package-windows:")]
    assert 'scripts/package-install-scripts.sh "${VERSION#v}" dist' in job


# ---------------------------------------------------------------------------------------------------------------------
# oarbank-install.sh


def test_the_installer_parses_and_its_body_is_one_function_called_last():
    for sh in ["sh", "bash"] + SHELLS[1:]:
        r = subprocess.run([sh, "-n", str(INSTALL_SH)], capture_output=True, text=True)
        assert r.returncode == 0, (sh, r.stderr)
    text = INSTALL_SH.read_text(encoding="ascii")          # ASCII: whatever decodes it, it reads the same
    top = [l for l in text.splitlines() if l and not l.startswith("#") and not l[0].isspace()]
    assert top == ["oarbank_install() {", "}", 'oarbank_install "$@"']
    assert text.rstrip("\n").splitlines()[-1] == 'oarbank_install "$@"'


def test_the_installer_verifies_and_never_puts_the_code_on_a_command_line():
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "sha256sum" in text and "shasum -a 256" in text and "cannot be verified" in text
    assert "printf '%s' \"$code\" | \"$node\" \"$@\" --code-stdin --no-input" in text
    # a piped script never asks for the code: only a terminal on its own standard input lets oarbank-node ask
    assert '"$node" "$@" < /dev/tty' not in text and 'elif [ -t 0 ]; then\n' in text
    assert "--code " not in text and "--join-code" not in text
    # the asset names the package scripts write
    assert "SHA256SUMS-agent-$OB_VERSION-$platform" in text
    assert 'prefix="oarbank-agent-$OB_VERSION-macos-"' in text
    macos = (REPO / "scripts" / "package-macos.sh").read_text(encoding="utf-8")
    assert 'PKG="$OUT/oarbank-agent-$VERSION-macos-$ARCH.pkg"' in macos and "PLATFORM=darwin-arm64" in macos
    assert "PLATFORM=darwin-amd64" in macos and '"SHA256SUMS-agent-$VERSION-$PLATFORM"' in macos
    linux = (REPO / "scripts" / "package-linux.sh").read_text(encoding="utf-8")
    assert '"SHA256SUMS-agent-$VERSION-linux-$ARCH"' in linux and "ARCH=amd64" in linux and "ARCH=arm64" in linux
    windows = (REPO / "scripts" / "package-windows.ps1").read_text(encoding="utf-8")
    assert '"$Out\\oarbank-agent-$Version-windows-$Arch.msi"' in windows
    assert '"$Out\\SHA256SUMS-agent-$Version-windows-$Arch"' in windows


FAKE_UNAME = r"""import os, sys
print({"-s": os.environ["FAKE_OS"], "-m": os.environ["FAKE_ARCH"]}[sys.argv[1]])
"""
FAKE_ID = r"""import os
print(os.environ.get("FAKE_UID", "0"))
"""
FAKE_CURL = r"""import json, os, shutil, sys
d = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]
out, url = a[a.index("-o") + 1], a[-1]
with open(os.path.join(d, "tools.jsonl"), "a") as f:
    f.write(json.dumps(["curl", url]) + "\n")
src = url[len("file://"):] if url.startswith("file://") else None
if not src or not os.path.exists(src):
    sys.exit(22)
shutil.copyfile(src, out)
"""
FAKE_SHA256SUM = r"""import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest() + "  " + sys.argv[1])
"""
# package managers and installer: log argv, the package's own bytes and whether a package variable leaked to them
FAKE_PM = r"""import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
pkg = next((a for a in sys.argv[1:] if os.path.isfile(a)), None)
with open(os.path.join(d, "tools.jsonl"), "a") as f:
    f.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\n")
with open(os.path.join(d, "pm.json"), "w") as f:
    json.dump({"pkg": pkg, "bytes": open(pkg, "rb").read().decode() if pkg else None,
               "leaked": sorted(k for k in os.environ if k.startswith("OARBANK_") and k != "OARBANK_INSTALL_BASE_URL"),
               "stdin_tty": sys.stdin.isatty()}, f)
"""
FAKE_NODE = r"""import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
tty = sys.stdin.isatty()
data = "" if tty else sys.stdin.read()
with open(os.path.join(d, "node.jsonl"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "stdin": data, "tty": tty, "env_code": os.environ.get("OARBANK_JOIN_CODE")}) + "\n")
sys.exit(int(os.environ.get("FAKE_NODE_RC", "0")))
"""


class Installer:
    """oarbank-install.sh, as package-install-scripts.sh writes it, against a release in a directory and stand-ins."""

    def __init__(self, root: Path):
        self.root = root
        self.dist, self.rel, self.bin = root / "dist", root / "release", root / "bin"
        for d in (self.dist, self.rel, self.bin):
            d.mkdir()
        assert package_install(self.dist).returncode == 0
        self.script = self.dist / "oarbank-install.sh"
        for tool in ("mktemp", "chmod", "rm"):
            os.symlink(shutil.which(tool), self.bin / tool)
        for name, body in (("uname", FAKE_UNAME), ("id", FAKE_ID), ("curl", FAKE_CURL), ("sysctl", "print(0)\n"),
                           ("sha256sum", FAKE_SHA256SUM), ("oarbank-node", FAKE_NODE)):
            write_fake(self.bin / name, body)

    def tool(self, *names):
        for n in names:
            write_fake(self.bin / n, FAKE_PM)

    def release(self, platform, files):
        sums = "".join(f"{hashlib.sha256(data).hexdigest()}  ./{name}\n" for name, data in files.items())
        for name, data in files.items():
            (self.rel / name).write_bytes(data)
        (self.rel / f"SHA256SUMS-agent-{VERSION}-{platform}").write_text(sums)

    def run(self, *args, env=None, os_="Linux", arch="x86_64", sh="sh", **kw):
        e = {"PATH": str(self.bin), "HOME": str(self.root), "TMPDIR": str(self.root), "FAKE_OS": os_, "FAKE_ARCH": arch,
             "OARBANK_INSTALL_BASE_URL": "file://" + str(self.rel)}
        e.update(env or {})
        if "input" not in kw:
            kw.setdefault("stdin", subprocess.DEVNULL)
        kw.setdefault("start_new_session", True)            # no controlling terminal: /dev/tty cannot be opened
        return subprocess.run([shutil.which(sh), str(self.script), *args], env=e, capture_output=True, text=True, **kw)

    def log(self, name):
        p = self.bin / name
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def pm(self):
        p = self.bin / "pm.json"
        return json.loads(p.read_text()) if p.exists() else None


LINUX_AMD64 = {f"oarbank-agent_{VERSION}_amd64.deb": b"the deb", f"oarbank-agent-{VERSION}-1.x86_64.rpm": b"the rpm",
               f"oarbank-agent-{VERSION}-linux-amd64.tar.gz": b"tar", f"oarbank-agent-{VERSION}-linux-amd64": b"agent"}


@pytest.fixture
def inst(tmp_path):
    i = Installer(tmp_path)
    i.release("linux-amd64", LINUX_AMD64)
    return i


@pytest.mark.parametrize("sh", SHELLS)
def test_a_deb_install_verifies_installs_and_joins_with_the_code_on_stdin(inst, sh):
    inst.tool("dpkg", "apt-get")
    r = inst.run("--containers", "--name", "build 07", sh=sh,
                 env={"OARBANK_JOIN_CODE": SECRET, "OARBANK_NAME": "x", "FAKE_NODE_RC": "3"})
    assert r.returncode == 3, r.stdout + r.stderr          # oarbank-node's exit code (3: pending approval)
    pm = inst.pm()
    assert pm["bytes"] == "the deb" and pm["leaked"] == [] and not pm["stdin_tty"]
    [apt] = [t for t in inst.log("tools.jsonl") if t[0] == "apt-get"]
    assert apt[:3] == ["apt-get", "install", "-y"] and apt[3].endswith(f"/oarbank-agent_{VERSION}_amd64.deb")
    [node] = inst.log("node.jsonl")
    assert node["argv"] == ["join", "--containers", "--name", "build 07", "--code-stdin", "--no-input"]
    assert node["stdin"] == SECRET and node["env_code"] is None
    everything = r.stdout + r.stderr + json.dumps(inst.log("tools.jsonl"))
    assert SECRET not in everything
    # the download directory went with the script
    assert not Path(apt[3]).parent.exists()
    assert [t[1].rsplit("/", 1)[1] for t in inst.log("tools.jsonl") if t[0] == "curl"] == \
        [f"SHA256SUMS-agent-{VERSION}-linux-amd64", f"oarbank-agent_{VERSION}_amd64.deb"]


def test_an_rpm_install_where_dnf_is(inst):
    inst.tool("dnf")
    r = inst.run("--no-join")
    assert r.returncode == 0, r.stderr
    assert inst.pm()["bytes"] == "the rpm" and inst.log("node.jsonl") == []
    assert "sudo oarbank-node join" in r.stdout
    [dnf] = [t for t in inst.log("tools.jsonl") if t[0] == "dnf"]
    assert dnf[:3] == ["dnf", "install", "-y"] and dnf[3].endswith(f"oarbank-agent-{VERSION}-1.x86_64.rpm")


def test_a_mac_installs_the_pkg_for_its_architecture(tmp_path):
    i = Installer(tmp_path)
    i.release("darwin-arm64", {f"oarbank-agent-{VERSION}-macos-arm64.pkg": b"the pkg", f"oarbank-agent-{VERSION}-darwin-arm64": b"agent"})
    i.tool("installer")
    r = i.run("--no-join", os_="Darwin", arch="arm64")
    assert r.returncode == 0, r.stderr
    [inst] = [t for t in i.log("tools.jsonl") if t[0] == "installer"]
    assert inst[1] == "-pkg" and inst[2].endswith(f"oarbank-agent-{VERSION}-macos-arm64.pkg") and inst[3:] == ["-target", "/"]
    assert i.pm()["bytes"] == "the pkg"


def test_the_consoles_containers_variable_counts_like_the_option(inst):
    # the console's commands set OARBANK_CONTAINERS=1 rather than passing --containers
    inst.tool("dpkg", "apt-get")
    r = inst.run(env={"OARBANK_JOIN_CODE": SECRET, "OARBANK_CONTAINERS": "1", "FAKE_NODE_RC": "0"})
    assert r.returncode == 0, r.stdout + r.stderr
    [node] = inst.log("node.jsonl")
    assert node["argv"] == ["join", "--containers", "--code-stdin", "--no-input"]


def test_a_package_that_does_not_match_its_sum_is_never_installed(inst):
    inst.tool("dpkg", "apt-get")
    (inst.rel / f"oarbank-agent_{VERSION}_amd64.deb").write_bytes(b"tampered")
    r = inst.run(env={"OARBANK_JOIN_CODE": SECRET})
    assert r.returncode != 0 and "does not match" in r.stderr
    assert inst.pm() is None and inst.log("node.jsonl") == []


def test_without_a_sha256_tool_it_refuses_before_downloading(inst):
    inst.tool("dpkg", "apt-get")
    (inst.bin / "sha256sum").unlink()
    r = inst.run()
    assert r.returncode != 0 and "cannot be verified" in r.stderr
    assert inst.log("tools.jsonl") == []


def test_it_needs_root_and_refuses_other_systems(inst):
    inst.tool("dpkg", "apt-get")
    r = inst.run(env={"FAKE_UID": "1000"})
    assert r.returncode == 8 and "sudo sh" in r.stderr and inst.log("tools.jsonl") == []
    r = inst.run(os_="FreeBSD")
    assert r.returncode == 2 and "no Oarbank package for FreeBSD" in r.stderr
    r = inst.run(arch="riscv64")
    assert r.returncode == 2 and "riscv64" in r.stderr
    (inst.bin / "dpkg").unlink()
    (inst.bin / "apt-get").unlink()
    r = inst.run()
    assert r.returncode == 2 and "tar.gz" in r.stderr
    r = inst.run("--bogus")
    assert r.returncode == 2


HINT = ("Installed. Join this computer with: sudo oarbank-node join\n"
        "(or run the command from the console's Add machine page, which has the code in it)\n")


class Terminal:
    """A pseudo-terminal for the installer: its controlling terminal (what /dev/tty opens), and its standard input
    when asked (sudo sh oarbank-install.sh) rather than the piped script (curl ... | sudo sh)."""

    def __enter__(self):
        self.master, self.slave = os.openpty()
        self.name = os.ttyname(self.slave)
        return self

    def __exit__(self, *exc):
        os.close(self.master)
        os.close(self.slave)

    def ctty(self):
        import fcntl
        import termios
        fd = os.open(self.name, os.O_RDWR)
        fcntl.ioctl(fd, termios.TIOCSCTTY, 0)

    def run(self, inst, *args, stdin_is_terminal=False, **kw):
        if stdin_is_terminal:
            kw["stdin"] = self.slave
        else:
            kw.setdefault("input", "the script itself\n")
        return inst.run(*args, start_new_session=True, preexec_fn=self.ctty, **kw)


def test_piped_without_a_code_or_a_terminal_it_installs_and_says_how_to_join(inst):
    inst.tool("dpkg", "apt-get")
    r = inst.run("--name", "n1", input="the script itself\n")
    assert r.returncode == 0, r.stderr
    assert inst.log("node.jsonl") == [] and r.stdout.endswith(HINT)


def test_piped_on_a_terminal_it_never_asks_for_the_code(inst):
    # ssh -t host 'curl ... | sudo sh': there is a terminal, but sudo (use_pty) leaves it echoing, so no prompt at all
    inst.tool("dpkg", "apt-get")
    with Terminal() as t:
        r = t.run(inst, "--name", "n1")
    assert r.returncode == 0, r.stderr
    assert inst.log("node.jsonl") == [] and r.stdout.endswith(HINT)


def test_piped_on_a_terminal_a_code_still_goes_by_printf(inst):
    inst.tool("dpkg", "apt-get")
    with Terminal() as t:
        r = t.run(inst, "--name", "n1", env={"OARBANK_JOIN_CODE": SECRET, "FAKE_NODE_RC": "0"})
    assert r.returncode == 0, r.stderr
    [node] = inst.log("node.jsonl")
    assert node["argv"] == ["join", "--name", "n1", "--code-stdin", "--no-input"] and node["stdin"] == SECRET
    assert node["env_code"] is None and SECRET not in r.stdout + r.stderr


def test_run_as_a_file_on_a_terminal_oarbank_node_asks_there(inst):
    # sudo sh oarbank-install.sh: standard input is the terminal, which sudo puts in raw mode, so the prompt is hidden
    inst.tool("dpkg", "apt-get")
    with Terminal() as t:
        r = t.run(inst, "--name", "n1", stdin_is_terminal=True)
    assert r.returncode == 0, r.stderr
    [node] = inst.log("node.jsonl")
    assert node["argv"] == ["join", "--name", "n1"] and node["tty"] is True
    assert "Installed. Join" not in r.stdout


def test_a_coordinator_confirms_its_fingerprint_on_the_terminal_or_joins_without_input(inst):
    # device code: nothing secret is typed, only y/N to the fingerprint, so a piped script may ask it on the terminal
    inst.tool("dpkg", "apt-get")
    url = {"OARBANK_COORDINATOR": "https://coord.example:7443"}
    with Terminal() as t:
        r = t.run(inst, env=url)
    assert r.returncode == 0, r.stderr
    r = inst.run(env=url, input="the script itself\n")
    assert r.returncode == 0, r.stderr
    on_terminal, no_terminal = inst.log("node.jsonl")
    assert on_terminal["argv"] == ["join", "--coordinator", url["OARBANK_COORDINATOR"]] and on_terminal["tty"] is True
    assert no_terminal["argv"] == ["join", "--coordinator", url["OARBANK_COORDINATOR"], "--no-input"]
    assert no_terminal["tty"] is False and no_terminal["stdin"] == ""


def test_no_join_installs_and_says_how_to_join_even_on_a_terminal(inst):
    inst.tool("dpkg", "apt-get")
    with Terminal() as t:
        r = t.run(inst, "--no-join", stdin_is_terminal=True)
    assert r.returncode == 0, r.stderr
    assert inst.log("node.jsonl") == [] and r.stdout.endswith("Installed. Join this computer with: sudo oarbank-node join\n")


# ---------------------------------------------------------------------------------------------------------------------
# oarbank-install.ps1


def test_the_windows_installer_verifies_and_keeps_the_code_off_command_lines():
    text = INSTALL_PS1.read_text(encoding="ascii")        # ASCII: Windows PowerShell 5.1 reads irm's text as Latin-1
    assert "Get-FileHash -Algorithm SHA256" in text and "-ine $want" in text
    assert "JOINCODE" not in text                          # the MSI never gets the code: oarbank-node does, on stdin
    msi_args = "\n".join(l for l in text.splitlines() if "msiArgs" in l)
    assert "CONTAINERS=1" in msi_args and "NAME=" in msi_args and "/qn" in msi_args and "/norestart" in msi_args
    assert re.search(r"3010 \{ \$restart = \$true \}", text)
    assert "Read-Host -AsSecureString" in text and "$code | & $node @joinArgs --code-stdin --no-input" in text
    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in text
    assert "$env:OARBANK_INSTALL_BASE_URL" in text and "@OARBANK_VERSION@" in text
    assert "SHA256SUMS-agent-$Version-windows-$Arch" in text and "oarbank-agent-$Version-windows-$Arch.msi" in text
    code_lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert code_lines[0].startswith("param(") and code_lines[-3].startswith("$OarbankInstallExit = [int]@(Install-OarbankNode")


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell 7 (pwsh) is not installed")
def test_the_windows_installer_parses_and_refuses_other_systems_cleanly(tmp_path):
    assert package_install(tmp_path).returncode == 0
    script = tmp_path / "oarbank-install.ps1"
    parse = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
             f"'{script}', [ref]$null, [ref]$e); $e.Count")
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", parse], capture_output=True, text=True)
    assert r.stdout.strip() == "0", r.stdout + r.stderr
    r = subprocess.run(["pwsh", "-NoProfile", "-File", str(script), "-NoJoin"], capture_output=True, text=True)
    assert r.returncode == 2 and "for Windows" in r.stdout, r.stdout + r.stderr
