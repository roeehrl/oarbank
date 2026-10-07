"""The node packages' declarative parts, checked without building them."""
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

WXS = Path(__file__).resolve().parents[1] / "deploy" / "windows" / "oarbank-agent.wxs"
NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}


def test_msi_replaces_an_installed_build_of_the_same_version():
    # package-windows.ps1 gives every build of 1.0.0-alpha.1 the MSI version 1.0.0; without same-version upgrades a
    # rebuilt MSI installs beside the old product (two entries, the old one's uninstall removing the shared service)
    pkg = ET.parse(WXS).getroot().find("w:Package", NS)
    upgrade = pkg.find("w:MajorUpgrade", NS)
    assert upgrade is not None and upgrade.get("AllowSameVersionUpgrades") == "yes"


def test_msi_upgrade_keeps_the_node():
    # the replaced product's uninstall must not run `oarbank-launcher remove` (the node's service) during an upgrade
    seq = ET.parse(WXS).getroot().find("w:Package/w:InstallExecuteSequence", NS)
    remove = next(c for c in seq.findall("w:Custom", NS) if c.get("Action") == "RemoveNode")
    assert "NOT UPGRADINGPRODUCTCODE" in remove.get("Condition")


def test_an_uninstall_removes_what_the_helper_installed_and_an_upgrade_keeps_it():
    # the helper's filters and loopback exemptions outlive its service, so running jobs keep their openings across a
    # restart or an upgrade (helper_windows.rs); only an uninstall clears them, after the node's own removal
    root = ET.parse(WXS).getroot()
    assert root.find(".//w:SetProperty[@Id='ClearHelper']", NS).get("Value") == '"[INSTALLFOLDER]oarbank-launcher.exe" helper-clear'
    ca = root.find(".//w:CustomAction[@Id='ClearHelper']", NS)
    assert (ca.get("Execute"), ca.get("Impersonate")) == ("deferred", "no")
    seq = root.find("w:Package/w:InstallExecuteSequence", NS)
    steps = {c.get("Action"): c for c in seq.findall("w:Custom", NS)}
    assert steps["ClearHelper"].get("Condition") == 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'
    assert (steps["RemoveNode"].get("Before"), steps["ClearHelper"].get("Before")) == ("ClearHelper", "RemoveFiles")


def test_the_helper_service_starts_after_the_filtering_engine_and_is_configured_by_the_launcher():
    # the agent's service gets its delayed start and recovery from `oarbank-launcher service install`, the helper's from
    # `oarbank-launcher helper-config` (tests/rust/test_launcher_service.py); the MSI's own ServiceConfig tables failed
    # an upgrade with error 1939
    root = ET.parse(WXS).getroot()
    svc = root.find(".//w:ServiceInstall[@Name='OarbankHelper']", NS)
    assert svc.get("Start") == "auto" and not svc.findall("w:ServiceConfig", NS)
    assert [d.get("Id") for d in svc.findall("w:ServiceDependency", NS)] == ["BFE"]   # it opens the WFP engine
    prop = root.find(".//w:SetProperty[@Id='ConfigureHelper']", NS)
    assert prop.get("Value") == '"[INSTALLFOLDER]oarbank-launcher.exe" helper-config'
    ca = root.find(".//w:CustomAction[@Id='ConfigureHelper']", NS)
    assert (ca.get("Execute"), ca.get("Impersonate"), ca.get("Return")) == ("deferred", "no", "check")
    step = root.find(".//w:InstallExecuteSequence/w:Custom[@Action='ConfigureHelper']", NS)
    assert step.get("After") == "InstallServices" and step.get("Condition") == 'NOT REMOVE="ALL"'


def test_windows_checksum_files_end_lines_with_lf():
    # sha256sum -c and shasum -c on Linux and macOS take a CRLF line's \r as part of the file name, and Set-Content
    # ends lines with CRLF on Windows: the sums files are written whole, with LF
    for name in ("package-windows.ps1", "build-coordinator.ps1"):
        lines = [l for l in (WXS.parents[2] / "scripts" / name).read_text(encoding="utf-8").splitlines() if "SHA256SUMS-" in l]
        assert lines and all("WriteAllText" in l and "`n" in l for l in lines), (name, lines)


def test_windows_checksum_files_end_lines_with_lf():
    # sha256sum -c and shasum -c on Linux and macOS take a CRLF line's \r as part of the file name, and Set-Content
    # ends lines with CRLF on Windows: the sums files are written whole, with LF
    for name in ("package-windows.ps1", "build-coordinator.ps1"):
        lines = [l for l in (WXS.parents[2] / "scripts" / name).read_text(encoding="utf-8").splitlines() if "SHA256SUMS-" in l]
        assert lines and all("WriteAllText" in l and "`n" in l for l in lines), (name, lines)


def test_windows_build_scripts_stop_when_a_native_command_fails():
    # PowerShell's $ErrorActionPreference does not see a native command's exit code: a failed cargo build once went on
    # to package the binaries an earlier build had left in target\release
    scripts = WXS.parents[2] / "scripts"
    for name in ("package-windows.ps1", "build-node-runtime.ps1"):
        lines = [l.strip() for l in (scripts / name).read_text(encoding="utf-8").splitlines()]
        for i, line in enumerate(lines):
            if line.split(" ")[0] in ("cargo", "uv", "wix") or (line.startswith("& ") and ".ps1" not in line):
                assert any("$LASTEXITCODE" in l for l in lines[i + 1:i + 4]), f"{name}: {line}"


def test_build_scripts_remove_their_temporary_directories():
    # package-linux.sh left its 140 MB node runtime in /tmp after every build (a tmpfs on the build VM)
    for script in sorted((WXS.parents[2] / "scripts").glob("*.sh")):
        text = script.read_text(encoding="utf-8")
        for var in re.findall(r'^\s*(\w+)="\$\(mktemp -d', text, re.M):
            assert re.search(rf"trap '[^']*rm -rf \"\${var}\"", text), f"{script.name}: {var} is never removed"


@pytest.mark.skipif(sys.platform == "win32", reason="install-oarbankd.sh is for macOS and Linux (Windows has install-oarbankd.ps1)")
def test_the_coordinator_installer_lists_every_option_and_refuses_unknown_ones():
    # --help was an "unknown argument", and nothing listed the options
    script = WXS.parents[1] / "oarbankd" / "install-oarbankd.sh"
    r = subprocess.run(["bash", str(script), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("usage: install-oarbankd.sh")
    options = {o for pat in re.findall(r"^\s+(-[-\w|]+)\)", script.read_text(encoding="utf-8"), re.M) for o in pat.split("|")}
    assert {"--build", "--checkout", "--agent-bind", "--dry-run", "--help", "-h"} <= options
    assert all(re.search(rf"^\s+(-h, )?{re.escape(o)}\b", r.stdout, re.M) for o in options), r.stdout
    for argv in (["--bogus"], ["stray"], ["--build"], ["--checkout", "--build", "x.tar.gz", "--agent-bind", "127.0.0.1"]):
        r = subprocess.run(["bash", str(script), *argv], capture_output=True, text=True)
        assert r.returncode == 2 and "install-oarbankd.sh: " in r.stderr and not r.stdout, (argv, r.stderr)


UV_HOMEBREW = ("/opt/homebrew/bin/uv", "/usr/local/bin/uv", "/home/linuxbrew/.linuxbrew/bin/uv")


def _installer(tmp_path, *argv, uv=True):
    """install-oarbankd.sh in a scratch HOME, with only a fake uv (when `uv`) and the system tools on PATH."""
    import os
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "uv").unlink(missing_ok=True)
    if uv:
        (bin_dir / "uv").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "uv").chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin", "XDG_BIN_HOME": str(tmp_path / "nobin")}
    script = WXS.parents[1] / "oarbankd" / "install-oarbankd.sh"
    return subprocess.run(["bash", str(script), *argv], capture_output=True, text=True, env=env), bin_dir


def _coordinator_build(tmp_path, platform) -> Path:
    import io
    import tarfile
    manifest = ('{"format": 1, "version": "1.2.3", "platform": "%s", "exec": ["bin/oarbankd"], '
                '"console": ["bin/oarbank-console"]}\n' % platform).encode()
    out = tmp_path / f"oarbank-coordinator-1.2.3-{platform}.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        info = tarfile.TarInfo("oarbank-coordinator.json")
        info.size = len(manifest)
        tf.addfile(info, io.BytesIO(manifest))
    return out


@pytest.mark.skipif(sys.platform == "win32", reason="install-oarbankd.sh is for macOS and Linux (Windows has install-oarbankd.ps1)")
def test_the_coordinator_installer_finds_uv_and_reads_builds_on_macos_and_linux(tmp_path):
    # --checkout ran /opt/homebrew/bin/uv (macOS with Homebrew only) and the platform check spoke of "this Mac"
    import hashlib
    import platform as pf
    r, bin_dir = _installer(tmp_path, "--checkout", "--agent-bind", "127.0.0.1", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert f"{bin_dir}/uv sync -q --inexact" in r.stdout
    assert f"{bin_dir}:" in r.stdout                                  # the services find the same uv
    if not any(Path(p).is_file() for p in ("/usr/bin/uv", "/bin/uv", *UV_HOMEBREW)):     # else it finds that one
        r, _ = _installer(tmp_path, "--checkout", "--agent-bind", "127.0.0.1", "--dry-run", uv=False)
        assert r.returncode == 1 and "uv is not installed" in r.stderr, r.stderr
    want = {("Darwin", "arm64"): "darwin-arm64", ("Darwin", "x86_64"): "darwin-amd64",
            ("Linux", "aarch64"): "linux-arm64", ("Linux", "x86_64"): "linux-amd64"}[(pf.system(), pf.machine())]
    r, _ = _installer(tmp_path, "--build", str(_coordinator_build(tmp_path, "plan9-mips")), "--agent-bind", "127.0.0.1")
    assert r.returncode == 1 and f"the build is for plan9-mips, this machine is {want}" in r.stderr, r.stderr
    build = _coordinator_build(tmp_path, want)
    r, _ = _installer(tmp_path, "--build", str(build), "--agent-bind", "127.0.0.1", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert f"coordinator-app/1.2.3-{hashlib.sha256(build.read_bytes()).hexdigest()[:12]}" in r.stdout
    # a build brings its own uv, first on the services' PATH, so oarbankd installs module dependencies on a machine
    # without one (it reported "uv is not available on this coordinator")
    r, bin_dir = _installer(tmp_path, "--build", str(build), "--agent-bind", "127.0.0.1", "--dry-run", uv=False)
    assert r.returncode == 0, r.stderr
    data = tmp_path / "home" / ("Library/Application Support/Oarbank" if pf.system() == "Darwin" else ".local/share/oarbank")
    svc_path = re.search(r"<key>PATH</key><string>([^<]*)</string>|\"PATH=([^\"]*)\"", r.stdout)
    assert (svc_path.group(1) or svc_path.group(2)).split(":")[0] == f"{data}/coordinator-app/current/bin", r.stdout
    assert str(bin_dir) not in r.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="install-oarbankd.sh is for macOS and Linux (Windows has install-oarbankd.ps1)")
def test_the_coordinator_installer_writes_systemd_units_on_linux(tmp_path):
    # run as on a Linux machine (a fake uname) wherever the suite runs
    fake = tmp_path / "tools"
    fake.mkdir()
    (fake / "uname").write_text('#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n')
    (fake / "uname").chmod(0o755)
    build = _coordinator_build(tmp_path, "linux-amd64")
    r, bin_dir = _installer(tmp_path, "--build", str(build), "--agent-bind", "10.0.0.1", "--dry-run")
    assert r.returncode == 0, r.stderr
    home = tmp_path / "home"
    assert f"# {home}/.config/systemd/user/dev.codonic.oarbank.oarbankd.service" in r.stdout
    assert f'ExecStart="{home}/.local/share/oarbank/coordinator-app/current/bin/oarbankd" "--agent-bind" "10.0.0.1"' in r.stdout
    assert f'"PATH={home}/.local/share/oarbank/coordinator-app/current/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"' in r.stdout
    assert "systemctl --user enable --now" in r.stdout and "launchctl" not in r.stdout
    (fake / "uname").write_text('#!/bin/sh\necho MINGW64_NT-10.0\n')
    r, _ = _installer(tmp_path, "--build", str(build), "--agent-bind", "10.0.0.1", "--dry-run")
    assert r.returncode == 1 and "installs on macOS and Linux (install-oarbankd.ps1 on Windows), not MINGW64_NT-10.0" in r.stderr, r.stderr


WINDOWS_INSTALLER = WXS.parents[1] / "oarbankd" / "install-oarbankd.ps1"


def _ps_installer(*argv):
    from helpers import windows_powershell
    return windows_powershell("-ExecutionPolicy", "Bypass", "-File", str(WINDOWS_INSTALLER), *argv, capture_output=True,
                              text=True)


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows coordinator installer (PowerShell, sc.exe, icacls)")
def test_the_windows_installer_sets_up_two_services_under_virtual_accounts(tmp_path):
    """install-oarbankd.ps1 -DryRun: the build checked against this machine, the services under their own virtual
    accounts with the recovery actions that keep exit 0 down and restart a failed exit, the home's DACL naming the two
    accounts by the SIDs the coordinator computes, the firewall rule and the standby arguments."""
    import hashlib
    from oarbank.platform import files
    r = _ps_installer("-Help")
    assert r.returncode == 0 and r.stdout.startswith("usage: install-oarbankd.ps1"), r.stderr
    for opt in ("-Build", "-AgentBind", "-Url", "-Pair", "-From", "-FromCa", "-ArchiveHome", "-Uninstall", "-DryRun"):
        assert opt in r.stdout, opt
    from oarbank_sdk import portable
    want = portable.host_platform()                               # the machine's, whatever this interpreter emulates
    r = _ps_installer("-Build", str(_coordinator_build(tmp_path, "plan9-mips")), "-AgentBind", "10.0.0.1", "-DryRun")
    assert r.returncode != 0 and f"the build is for plan9-mips, this machine is {want}" in r.stderr, r.stderr
    build = _coordinator_build(tmp_path, want)
    r = _ps_installer("-Build", str(build), "-AgentBind", "10.0.0.1", "-DryRun")
    assert r.returncode == 0, r.stderr
    out = r.stdout
    sha = hashlib.sha256(build.read_bytes()).hexdigest()[:12]
    assert f"Coordinator\\1.2.3-{sha}" in out and "junction" in out
    for name in files.COORDINATOR_SERVICES:
        assert f"New-Service {name} -BinaryPathName " in out and f"sc.exe config {name} start= delayed-auto obj= NT SERVICE\\{name}" in out
        assert f"sc.exe failure {name} reset= 86400 actions= restart/10000/restart/10000/restart/60000" in out
        assert f"sc.exe failureflag {name} 1" in out and f"*{files.service_sid(name)}:(OI)(CI)F" in out
    assert 'current\\bin\\oarbankd.py" --service --agent-bind 10.0.0.1 --agent-port 7443 --url https://10.0.0.1:7443' in out
    assert 'current\\bin\\oarbank-console.py" --service' in out and "/inheritance:r" in out
    assert "OARBANKD_HOME=" in out and "inbound TCP 7443 for dev.codonic.oarbank.oarbankd" in out
    r = _ps_installer("-Build", str(build), "-AgentBind", "10.0.0.1", "-Pair", "OBP-1", "-From", "https://a:7443",
                      "-FromCa", "abc", "-ArchiveHome", "-DryRun")
    assert r.returncode == 0, r.stderr
    assert "--url https://10.0.0.1:7443 --standby --pair OBP-1 --from https://a:7443 --from-ca abc --archive-home" in r.stdout
    r = _ps_installer("-Build", str(build), "-AgentBind", "10.0.0.1", "-Pair", "OBP-1", "-DryRun")
    assert r.returncode != 0 and "-Pair) also needs -From and -FromCa" in r.stderr


def _relocate_shebangs():
    import importlib.util
    spec = importlib.util.spec_from_file_location("relocate_shebangs", WXS.parents[2] / "scripts" / "relocate_shebangs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shebangs (the coordinator builds and node runtimes off Windows)")
def test_bundled_console_scripts_run_from_wherever_the_build_is_unpacked(tmp_path):
    # the linux-arm64 coordinator build's python/bin/oarbank-sdk named its /tmp build path as interpreter
    import os
    rs = _relocate_shebangs()
    built = tmp_path / "build dir" / "python" / "bin"
    built.mkdir(parents=True)
    (built / "python3.12").symlink_to(os.path.realpath(sys.executable))
    scripts = {
        "plain": f"#!{built}/python3.12\nprint('plain ran')\n",                      # what pip writes
        "long": f"#!/bin/sh\n'''exec' '{built}/python3.12' \"$0\" \"$@\"\n' '''\nprint('long ran')\n",  # long paths
        "shell": "#!/bin/sh\necho shell ran\n",
        "foreign": "#!/opt/elsewhere/bin/python3\nprint('never')\n",               # another interpreter's script
    }
    for name, text in scripts.items():
        (built / name).write_text(text)
        (built / name).chmod(0o755)
    assert rs.relocate(built) == ["long", "plain"]
    assert (built / "shell").read_text(encoding="utf-8") == scripts["shell"]
    unpacked = tmp_path / "elsewhere"
    (tmp_path / "build dir").rename(unpacked)
    for name in ("plain", "long", "shell"):
        r = subprocess.run([str(unpacked / "python" / "bin" / name)], capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout == f"{name} ran\n", (name, r.stderr)
    assert rs.problems(unpacked) == ["python/bin/foreign: /opt/elsewhere/bin/python3"]
    r = subprocess.run([sys.executable, rs.__file__, str(unpacked / "python" / "bin"), str(unpacked)],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "not relocatable: python/bin/foreign" in r.stderr


def _pe_with_rcdata(resources: dict[str, bytes]) -> bytes:
    """A PE32+ image with one .rsrc section holding named RCDATA resources, laid out like uv's trampolines (resource
    type 10, a name level, one language, a data entry per resource)."""
    import struct
    names = list(resources)
    n = len(names)
    l2 = 16 + 8                        # the root directory: one id entry (RCDATA)
    l3 = l2 + 16 + 8 * n               # the name directory
    entries = l3 + n * (16 + 8)        # one language directory per name
    strings = entries + 16 * n
    blob = b"".join(struct.pack("<H", len(k)) + k.encode("utf-16-le") for k in names)
    data = strings + len(blob) + (-(strings + len(blob)) % 8)
    va, raw = 0x1000, 0x400
    rsrc = bytearray(struct.pack("<12xHH", 0, 1) + struct.pack("<II", 10, 0x8000_0000 | l2))
    rsrc += struct.pack("<12xHH", n, 0)
    str_at, data_at, payload = strings, data, b""
    for i, k in enumerate(names):
        rsrc += struct.pack("<II", 0x8000_0000 | str_at, 0x8000_0000 | (l3 + 24 * i))
        str_at += 2 + 2 * len(k)
    for i in range(n):
        rsrc += struct.pack("<12xHH", 0, 1) + struct.pack("<II", 1033, entries + 16 * i)
    for k in names:
        rsrc += struct.pack("<IIII", va + data_at, len(resources[k]), 0, 0)
        data_at += len(resources[k]) + (-len(resources[k]) % 8)
        payload += resources[k] + bytes(-len(resources[k]) % 8)
    rsrc += blob + bytes(data - strings - len(blob)) + payload
    nt, opt_size = 0x40, 240
    head = bytearray(raw)
    head[:2], head[0x3C:0x40] = b"MZ", struct.pack("<I", nt)
    head[nt:nt + 24] = b"PE\0\0" + struct.pack("<HHIIIHH", 0xAA64, 1, 0, 0, 0, opt_size, 0x22)
    opt = nt + 24
    head[opt:opt + 2] = struct.pack("<H", 0x20B)
    head[opt + 108:opt + 112] = struct.pack("<I", 16)
    head[opt + 112 + 16:opt + 112 + 24] = struct.pack("<II", va, len(rsrc))
    head[opt + opt_size:opt + opt_size + 40] = b".rsrc\0\0\0" + struct.pack("<IIII16x", len(rsrc), va, len(rsrc), raw)
    return bytes(head + rsrc)


def _script_zip(main: str) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("__main__.py", (1980, 1, 1, 0, 0, 0)), main)
    return buf.getvalue()


def test_windows_launchers_name_the_bundled_python_relative_to_themselves(tmp_path):
    # the Windows node runtime's Scripts\oarbank-sdk.exe named C:\...\Temp\oarbank-runtime\python.exe, so it broke once
    # installed under C:\Program Files\Oarbank\runtime
    import io
    import os
    import zipfile
    rs = _relocate_shebangs()
    root = tmp_path / "build dir" / "runtime"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    python = str(root / "python.exe")
    main = "# -*- coding: utf-8 -*-\nimport sys\nfrom oarbank_sdk.cli import main\nsys.exit(main())\n"

    def trampoline(interpreter: str) -> bytes:
        return _pe_with_rcdata({"UV_PYTHON_PATH": interpreter.encode(),
                                "UV_SCRIPT_DATA": _script_zip(f"#!{interpreter}\n{main}"), "UV_TRAMPOLINE_KIND": b"\x01"})

    (scripts / "oarbank-sdk.exe").write_bytes(trampoline(python))
    (scripts / "foreign.exe").write_bytes(trampoline(r"C:\Python312\python.exe"))     # another interpreter's launcher
    # pip's (distlib) launcher: a PE stub, a #! line and a zip, which no relative path can fix
    (scripts / "pip-made.exe").write_bytes(b"MZ" + bytes(510) + f'#!"{python}"\r\n'.encode() + _script_zip(main))
    (scripts / ".empty").write_bytes(b"")
    (root / "python.exe").write_bytes(b"MZ" + bytes(1022))
    assert rs.relocate(scripts) == ["oarbank-sdk.exe"]
    rel = os.path.join("..", "python.exe")
    pe = (scripts / "oarbank-sdk.exe").read_bytes()
    assert rs.relocate(scripts) == [] and (scripts / "oarbank-sdk.exe").read_bytes() == pe   # once only
    assert rs.launcher_interpreters(pe) == [rel, rel]
    res = rs._rcdata(pe)
    _, at, size = res["UV_SCRIPT_DATA"]
    with zipfile.ZipFile(io.BytesIO(pe[at:at + size])) as z:
        assert z.read("__main__.py").decode() == f"#!{rel}\n{main}"
    assert pe[res["UV_TRAMPOLINE_KIND"][1]] == 1
    assert rs.problems(root) == [r"Scripts/foreign.exe: C:\Python312\python.exe", f"Scripts/pip-made.exe: {python}"]
    r = subprocess.run([sys.executable, rs.__file__, str(scripts), str(root)], capture_output=True, text=True)
    assert r.returncode == 1 and "not relocatable: Scripts/pip-made.exe" in r.stderr
    (scripts / "foreign.exe").unlink()
    (scripts / "pip-made.exe").unlink()
    r = subprocess.run([sys.executable, rs.__file__, str(scripts), str(root)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_windows_builds_take_their_architecture_from_the_caller_or_the_machine():
    # PROCESSOR_ARCHITECTURE is the emulated one under emulation (an x64 PowerShell on Windows on Arm says AMD64): the
    # scripts ask windows-arch.ps1, which takes -Arch from the caller and asks Windows for the machine otherwise
    scripts = WXS.parents[2] / "scripts"
    for ps1 in scripts.glob("*.ps1"):
        code = [l for l in ps1.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#")]
        assert not any("PROCESSOR_ARCHITECTURE" in l for l in code), ps1.name
    for name in ("build-node-runtime.ps1", "package-windows.ps1", "build-coordinator.ps1", "verify-windows-containers.ps1"):
        assert '"$PSScriptRoot\\windows-arch.ps1"' in (scripts / name).read_text(encoding="utf-8"), name
    pkg = (scripts / "package-windows.ps1").read_text(encoding="utf-8")
    assert "-Arch $Arch" in pkg and "--target $Target" in pkg and "--platform \"windows-$(if ($Arch -eq 'arm64')" in pkg
    assert "--target $Target" in (scripts / "build-coordinator.ps1").read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform != "win32", reason="asks Windows for the machine's architecture")
def test_the_architecture_is_the_machine_s_under_emulation_and_whatever_the_environment_says():
    from oarbank_sdk import portable
    script = WXS.parents[2] / "scripts" / "windows-arch.ps1"
    machine = {"amd64": "x64", "arm64": "arm64"}[portable.host_platform().split("-")[1]]
    root = os.environ.get("SystemRoot", r"C:\Windows")
    # this machine's own PowerShell, and the 32-bit one, which runs under WOW64 or Windows on Arm's x86 emulation
    shells = [p for p in (rf"{root}\System32\WindowsPowerShell\v1.0\powershell.exe",
                          rf"{root}\SysWOW64\WindowsPowerShell\v1.0\powershell.exe") if os.path.exists(p)]

    def arch(shell, *args, env=None):
        r = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
                           capture_output=True, text=True, env=env, timeout=120)
        return r.returncode, r.stdout.strip()
    assert len(shells) == 2, shells
    for shell in shells:
        for claimed in (None, "AMD64", "ARM64", "x86"):
            env = {**os.environ, **({"PROCESSOR_ARCHITECTURE": claimed} if claimed else {})}
            assert arch(shell, env=env) == (0, machine), (shell, claimed)
        assert arch(shell, "-Arch", "x64") == (0, "x64") and arch(shell, "-Arch", "arm64") == (0, "arm64")
        assert arch(shell, "-Arch", "ia64")[0] != 0


def _script(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), WXS.parents[2] / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_package_check_finds_links_out_and_build_paths(tmp_path):
    # uv names its managed Pythons through junctions (links), records the checkout it installed from (direct_url.json),
    # writes its store's path into bytecode and build configuration; rustc embeds CARGO_HOME: none of it may ship
    check = _script("check-package")
    rt = tmp_path / "runtime"
    info = rt / "lib" / "site-packages" / "oarbank_sdk-1.5.0.dist-info"
    info.mkdir(parents=True)
    (info / "RECORD").write_text("oarbank_sdk/__init__.py,sha256=x,1\n", encoding="utf-8")
    (rt / "python3.12").write_bytes(b"\x7fELF")
    build = tmp_path / "Builder" / "checkout"
    assert check.bad_links(rt) == [] and check.references(rt, [str(build)], []) == []
    target = tmp_path / "cpython-3.12.15"
    target.mkdir()
    if sys.platform == "win32":
        import _winapi
        _winapi.CreateJunction(str(target), str(rt / "DLLs"))
        assert len(check.bad_links(rt)) == 1
    else:
        (rt / "python3").symlink_to("python3.12")                     # inside the tree: kept
        assert check.bad_links(rt) == []
        (rt / "DLLs").symlink_to(target, target_is_directory=True)     # absolute: refused
        (rt / "up").symlink_to(os.path.join("..", target.name))        # relative but outside: refused
        assert sorted(b.split(": ")[0] for b in check.bad_links(rt)) == sorted([str(rt / "DLLs"), str(rt / "up")])
        (rt / "DLLs").unlink()
        (rt / "up").unlink()
    (info / "direct_url.json").write_text('{"url": "' + (build / "vendor" / "oarbank-sdk").as_uri() + '"}', encoding="utf-8")
    (rt / "module.so").write_bytes(b"\0\1" + str(build / "target" / "x.o").encode() + b"\0")      # a compiled file
    found = sorted({f for f, _ in check.references(rt, [str(build)], [])})
    assert found == sorted([info / "direct_url.json", rt / "module.so"]), found
    if sys.platform == "win32":                                        # as a PE resource stores it, any case
        (rt / "res.dll").write_bytes(str(build).upper().encode("utf-16-le"))
        assert rt / "res.dll" in {f for f, _ in check.references(rt, [str(build)], [])}
    # the account's home: refused in what the build writes, not in a native binary built elsewhere (a wheel's, uv's,
    # often on a CI machine with the same account name), except a binary the build made and names itself
    for f in ("module.so", "res.dll"):
        (rt / f).unlink(missing_ok=True)
    (info / "direct_url.json").unlink()
    account = tmp_path / "Users" / "runneradmin"
    (rt / "wheel.so").write_bytes(b"\x7fELF" + str(account / ".cargo" / "registry").encode())
    (account / "Library" / "Application Support" / "uv").mkdir(parents=True)
    (rt / "lib" / "site-packages" / "x.pth").write_text(str(account / "Library" / "Application Support" / "uv") + " (uv)",
                                                         encoding="utf-8")
    # a wheel built on a CI account named like this build's records that machine's paths: none exists here
    sbom = rt / "lib" / "site-packages" / "w-1.0.dist-info" / "sboms" / "w.cyclonedx.json"
    sbom.parent.mkdir(parents=True)
    sbom.write_text(json.dumps({"bom-ref": str(account / "work" / "w" / "w") + "#1.0"}), encoding="utf-8")
    assert {f for f, _ in check.references(rt, [str(build)], [str(account)])} == {rt / "lib" / "site-packages" / "x.pth"}
    assert check.references(rt / "wheel.so", [], [str(account)]) == [(rt / "wheel.so", str(account))]


def _macho(cpu: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + cpu.to_bytes(4, "little") + bytes(24)


def _fat(*cpus: int) -> bytes:
    return b"\xca\xfe\xba\xbe" + len(cpus).to_bytes(4, "big") + b"".join(c.to_bytes(4, "big") + bytes(16) for c in cpus)


def _elf(machine: int, cls: int = 2) -> bytes:
    return b"\x7fELF" + bytes([cls, 1, 1]) + bytes(9) + (3).to_bytes(2, "little") + machine.to_bytes(2, "little") + bytes(44)


def _pe(machine: int, chpe: int = 0) -> bytes:
    """A PE32+ image with one section holding its load configuration, whose CHPE metadata pointer is `chpe`."""
    import struct
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 240, 0x22)
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 10 * 8, 0x1000, 0x140)
    opt = struct.pack("<H", 0x20B) + bytes(110) + bytes(dirs)
    section = struct.pack("<8sIIIIIIHHI", b".rdata", 0x1000, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0)
    head = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + section
    load_config = bytearray(0x200)
    struct.pack_into("<I", load_config, 0, 0x140)
    struct.pack_into("<Q", load_config, 0xC8, chpe)
    return head.ljust(0x400, b"\0") + bytes(load_config)


def _ar(*members: tuple[bytes, bytes]) -> bytes:
    out = b"!<arch>\n"
    for name, body in members:
        out += name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n"
        out += body + (b"\n" if len(body) % 2 else b"")
    return out


ARM64, X86_64 = 0x0100000C, 0x01000007


def test_the_package_check_reads_the_platform_of_every_kind_of_native_file():
    # the macOS pkg shipped universal binaries beside a node runtime of the build machine's architecture only: every
    # native file is read for the platforms its code is for, thin or universal, in an executable or a library's objects
    check = _script("check-package")
    of = check.platforms_of
    assert of(_macho(ARM64)) == {"darwin-arm64"} and of(_macho(X86_64)) == {"darwin-amd64"}
    assert of(_fat(ARM64, X86_64)) == {"darwin-arm64", "darwin-amd64"}
    assert of(b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + bytes(64)) is None              # a Java class file (major 65)
    assert of(b"\xce\xfa\xed\xfe" + bytes(28)) == {"darwin-32-bit-or-big-endian"}
    assert of(_elf(0xB7)) == {"linux-arm64"} and of(_elf(0x3E)) == {"linux-amd64"}
    assert of(_elf(0x03, cls=1)) == {"linux-32-bit-or-big-endian"}
    assert of(_pe(0xAA64)) == {"windows-arm64"} and of(_pe(0x8664)) == {"windows-amd64"} and of(_pe(0x14C)) == {"windows-machine-0x14c"}
    # Arm64EC behind an x64 header (python-build-standalone's Windows on Arm vcruntime140_1.dll, Microsoft's own),
    # and Arm64X: code for Windows on Arm only
    assert of(_pe(0x8664, chpe=0x180001000)) == {"windows-arm64"} and of(_pe(0xAA64, chpe=0x180001000)) == {"windows-arm64"}
    assert of(b"MZ not a program") is None and of(b"#!/bin/sh\n") is None
    # static libraries: BSD (names in the body, symbol table skipped), GNU, and a Windows import library's entries
    bsd = _ar((b"#1/12", b"__.SYMDEF\0\0\0"), (b"#1/4", b"a.o\0" + _macho(X86_64)))
    assert of(bsd) == {"darwin-amd64"}
    assert of(_ar((b"/", b"\0" * 8), (b"a.o/", _elf(0xB7)))) == {"linux-arm64"}
    short = b"\0\0\xff\xff\0\0" + (0xAA64).to_bytes(2, "little") + bytes(12)
    coff = (0x8664).to_bytes(2, "little") + bytes(18)
    assert of(_ar((b"/", b"\0" * 4), (b"python312.dll/", short))) == {"windows-arm64"}
    assert of(_ar((b"x.obj/", coff))) == {"windows-amd64"}


def test_the_package_check_refuses_native_files_for_another_platform(tmp_path):
    check = _script("check-package")
    rt = tmp_path / "runtime"
    site = rt / "lib" / "site-packages"
    (site / "pip" / "_vendor" / "distlib").mkdir(parents=True)
    (rt / "bin").mkdir()
    (rt / "bin" / "python3.12").write_bytes(_macho(ARM64))
    (rt / "bin" / "uv").write_bytes(_fat(ARM64, X86_64))                      # code for more platforms: fine
    (site / "pip" / "_vendor" / "distlib" / "t32.exe").write_bytes(_pe(0x14C))   # a launcher template pip copies out
    (site / "README.txt").write_text("text", encoding="utf-8")
    assert check.wrong_platforms(rt, {"": {"darwin-arm64"}}) == []
    (site / "_core.so").write_bytes(_macho(X86_64))                           # the build machine's wheel, not the package's
    (site / "lib.a").write_bytes(_ar((b"#1/4", b"b.o\0" + _macho(X86_64))))
    bad = check.wrong_platforms(rt, {"": {"darwin-arm64"}})
    assert sorted(b.split(": ")[0] for b in bad) == [str(site / "_core.so"), str(site / "lib.a")]
    assert "code for darwin-amd64, not darwin-arm64" in bad[0]
    assert len(check.wrong_platforms(rt, {"": {"darwin-arm64", "darwin-amd64"}})) == 3    # universal: python3.12 too
    (site / "_core.so").unlink()
    (site / "lib.a").unlink()
    # a tree of two platforms (the Windows coordinator: an x64 interpreter, the platform's launcher and uv): the longest
    # directory that holds a file decides
    (rt / "bin" / "oarbank-sandbox.exe").write_bytes(_pe(0xAA64))
    (rt / "bin" / "python3.12").write_bytes(_pe(0x8664))
    (rt / "bin" / "uv").write_bytes(_pe(0xAA64))
    (site / "core.pyd").write_bytes(_pe(0x8664))
    rules = check.platform_rules(["windows-amd64", f"{rt / 'bin'}=windows-arm64"])
    assert [b.split(": ")[0] for b in check.wrong_platforms(rt, rules)] == [str(rt / "bin" / "python3.12")]
    with pytest.raises(SystemExit):
        check.platform_rules([f"{rt}=windows-amd64"])                         # nothing names the package's own


def test_the_package_check_reads_this_interpreter_as_this_machine_s():
    # a real binary: the interpreter running the tests (an x64 Python under Windows on Arm's emulation is x64)
    import platform as pf
    from oarbank_sdk import portable
    check = _script("check-package")
    exe = Path(sys.executable).resolve()
    want = portable.host_platform()
    if sys.platform == "win32" and pf.machine().lower() in ("amd64", "x86_64"):
        want = "windows-amd64"
    assert want in check.platforms_of(exe.read_bytes())


def test_uv_is_fetched_for_the_package_s_platform_and_checked_against_its_pin(tmp_path, monkeypatch):
    # the runtime shipped the build machine's own uv: an arm64 uv in a package for x86_64 Macs
    import hashlib
    import io
    import tarfile
    from oarbank_sdk import portable
    fetch = _script("fetch-uv")
    assert set(fetch.ASSETS) == set(portable.KNOWN_PLATFORMS)
    target = fetch.ASSETS["darwin-amd64"][0]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(f"uv-{target}/uv")
        info.size = len(_macho(X86_64))
        tf.addfile(info, io.BytesIO(_macho(X86_64)))
    asset = buf.getvalue()
    urls = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False
    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda url, timeout: urls.append(url) or Response(asset))
    with pytest.raises(SystemExit, match="does not match its pin"):
        fetch.fetch("darwin-amd64", tmp_path / "uv")
    assert urls == [f"https://github.com/astral-sh/uv/releases/download/{fetch.VERSION}/uv-x86_64-apple-darwin.tar.gz"]
    assert not (tmp_path / "uv").exists()
    monkeypatch.setitem(fetch.ASSETS, "darwin-amd64", (target, hashlib.sha256(asset).hexdigest()))
    fetch.fetch("darwin-amd64", tmp_path / "uv")
    assert (tmp_path / "uv").read_bytes() == _macho(X86_64) and os.access(tmp_path / "uv", os.X_OK)
    ci = (WXS.parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert ci.count(f'version: "{fetch.VERSION}"') >= 5                       # the uv CI builds with is the one shipped


def test_each_macos_package_is_for_one_architecture_and_refuses_the_other():
    # one pkg for both: universal binaries, an arm64 runtime, and productbuild's distribution claiming x86_64 and arm64
    pkg = (WXS.parents[2] / "scripts" / "package-macos.sh").read_text(encoding="utf-8")
    assert "lipo" not in pkg and '--target "$TARGET"' in pkg
    assert 'build-node-runtime.sh" "$PAYLOAD/runtime" "$PLATFORM"' in pkg and '--platform "$PLATFORM"' in pkg
    assert 'hostArchitectures="$ARCH"' in pkg and '<installation-check script="architecture()"/>' in pkg
    assert 'system.sysctl("hw.optional.arm64") == 1' in pkg and "--distribution" in pkg and "productbuild --quiet --package" not in pkg
    assert 'PKG="$OUT/oarbank-agent-$VERSION-macos-$ARCH.pkg"' in pkg
    assert '"$OUT/oarbank-agent-$VERSION-$PLATFORM"' in pkg
    ci = (WXS.parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "for arch in arm64 x86_64" in ci and "--install-rosetta" in ci


def test_the_coordinator_archive_names_no_owner(tmp_path):
    # tar writes the build account's user and group names into every entry
    import tarfile
    (tmp_path / "root" / "bin").mkdir(parents=True)
    (tmp_path / "root" / "bin" / "x").write_text("x", encoding="utf-8")
    out = tmp_path / "b.tar.gz"
    assert _script("pack-tar").main([str(out), str(tmp_path / "root"), "bin"]) == 0
    with tarfile.open(out) as tf:
        assert {(m.name, m.uid, m.gid, m.uname, m.gname) for m in tf} == {("bin", 0, 0, "", ""), ("bin/x", 0, 0, "", "")}


def test_every_package_build_checks_what_it_ships():
    scripts = WXS.parents[2] / "scripts"
    for name in ("package-linux.sh", "package-macos.sh", "package-windows.ps1", "build-coordinator.sh", "build-coordinator.ps1"):
        text = (scripts / name).read_text(encoding="utf-8")
        assert "check-package.py" in text and "--run " in text and "--platform " in text, name
        assert "remap-path-prefix" in text, name
    for name in ("build-node-runtime.sh", "build-coordinator.sh"):
        assert "bundle-python.sh" in (scripts / name).read_text(encoding="utf-8"), name
    # what they ship includes uv, the release for the package's platform, which installs into the build
    for name in ("build-node-runtime.sh", "build-coordinator.sh", "build-node-runtime.ps1", "build-coordinator.ps1"):
        text = (scripts / name).read_text(encoding="utf-8")
        assert "fetch-uv.py" in text and text.index("fetch-uv.py\"") < text.index(" pip install"), name
        assert "(Get-Command uv)" not in text and "command -v uv" not in text, name
    for name in ("build-node-runtime.ps1", "build-coordinator.ps1"):
        assert "bundle-python.ps1" in (scripts / name).read_text(encoding="utf-8"), name


@pytest.mark.skipif(not os.environ.get("OARBANK_NODE_RUNTIME"),
                    reason="set OARBANK_NODE_RUNTIME to a node runtime scripts/build-node-runtime.* built to check it")
def test_a_built_node_runtime_is_fit_to_package():
    root = Path(os.environ["OARBANK_NODE_RUNTIME"])
    python = "python.exe" if sys.platform == "win32" else "bin/python3"
    from oarbank_sdk import portable
    assert _script("check-package").main(["--platform", portable.host_platform(), "--run", f"{root}={python}", str(root)]) == 0


def test_the_macos_binaries_say_why_they_use_the_local_network():
    # Local Network privacy does not exempt LaunchAgents, which the personal scope runs (the launcher, whose children's
    # requests are attributed to it): the binaries carry an Info.plist (build.rs) with the usage text and the Bonjour
    # service, under the identifier package-macos.sh signs them with, which checks it is bound
    import plistlib
    rust = WXS.parents[2] / "rust" / "crates"
    for crate in ("oarbank-agent", "oarbank-launcher"):
        info = plistlib.loads((rust / crate / "Info.plist").read_bytes())
        assert info["CFBundleIdentifier"] == f"dev.codonic.{crate}"
        assert info["NSLocalNetworkUsageDescription"].strip() and info["NSBonjourServices"] == ["_oarbank._tcp"]
        build = (rust / crate / "build.rs").read_text(encoding="utf-8")
        assert "-Wl,-sectcreate,__TEXT,__info_plist," in build and '"Info.plist"' in build
    pkg = (WXS.parents[2] / "scripts" / "package-macos.sh").read_text(encoding="utf-8")
    assert '--identifier "dev.codonic.$b"' in pkg and "Info.plist entries=" in pkg


def test_build_scripts_relocate_their_bundled_console_scripts():
    scripts = WXS.parents[2] / "scripts"
    coord = (scripts / "build-coordinator.sh").read_text(encoding="utf-8")
    call = '"$PY" -I -B "$REPO/scripts/relocate_shebangs.py" "$ROOT/python/bin" "$ROOT"'
    assert call in coord and coord.index(call) < coord.index('pack-tar.py" "$TGZ"')
    assert coord.index(" pip install") < coord.index(call)
    node = (scripts / "build-node-runtime.sh").read_text(encoding="utf-8")
    assert '"$PY" -I -B "$REPO/scripts/relocate_shebangs.py" "$OUT/bin"' in node
    windows = (scripts / "build-node-runtime.ps1").read_text(encoding="utf-8")
    call = '& "$Out\\python.exe" -I -B "$Repo\\scripts\\relocate_shebangs.py" "$Out\\Scripts" $Out'
    assert call in windows and windows.index('scripts\\fetch-uv.py') < windows.index(call)
    assert windows.index(" pip install") < windows.index(call)


@pytest.mark.skipif(not __import__("os").environ.get("OARBANK_COORDINATOR_BUILD"),
                    reason="set OARBANK_COORDINATOR_BUILD to a coordinator build's .tar.gz to inspect it")
def test_a_coordinator_build_runs_from_where_it_is_unpacked(tmp_path):
    import os
    import tarfile
    with tarfile.open(os.environ["OARBANK_COORDINATOR_BUILD"]) as tf:
        tf.extractall(tmp_path, filter="tar")
    assert _relocate_shebangs().problems(tmp_path) == []
    uv = tmp_path / "bin" / ("uv.exe" if sys.platform == "win32" else "uv")     # module environments
    assert subprocess.run([str(uv), "--version"], capture_output=True, text=True).stdout.startswith("uv ")
    for entry in sorted((tmp_path / "bin").iterdir()):
        assert os.access(entry, os.X_OK), entry.name
        head = entry.read_bytes()[:64]
        assert not head.startswith(b"#!") or head.startswith(b"#!/bin/sh\n"), (entry.name, head)
