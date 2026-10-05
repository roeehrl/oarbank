"""The node packages' declarative parts, checked without building them."""
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
    assert f'"PATH={bin_dir}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"' in r.stdout
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
    assert "-Arch $Arch" in pkg and "--target $Target" in pkg and "check-pe-imports.py\" --machine $Arch" in pkg
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


def _check_node_runtime():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_node_runtime", WXS.parents[2] / "scripts" / "check-node-runtime.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_node_runtime_check_finds_links_and_build_paths(tmp_path):
    # uv names its managed Pythons through junctions; a runtime copied through one, or naming the checkout it was built
    # from (uv's direct_url.json), is refused before the MSI packages it
    check = _check_node_runtime()
    rt = tmp_path / "runtime"
    info = rt / "Lib" / "site-packages" / "oarbank_sdk-1.5.0.dist-info"
    info.mkdir(parents=True)
    (info / "RECORD").write_text("oarbank_sdk/__init__.py,sha256=x,1\n", encoding="utf-8")
    (rt / "python.exe").write_bytes(b"MZ")
    assert check.links(rt) == [] and check.references(rt, [str(tmp_path / "checkout")]) == []
    target = tmp_path / "cpython-3.12.15"
    target.mkdir()
    if sys.platform == "win32":
        import _winapi
        _winapi.CreateJunction(str(target), str(rt / "DLLs"))
    else:
        (rt / "DLLs").symlink_to(target, target_is_directory=True)
    assert check.links(rt) == [rt / "DLLs"]
    checkout = tmp_path / "Checkout" / "vendor" / "oarbank-sdk"
    (info / "direct_url.json").write_text('{"url": "' + checkout.as_uri() + '", "dir_info": {}}', encoding="utf-8")
    found = check.references(rt, [str(tmp_path / "Checkout")])
    assert [f for f, _ in found] == [info / "direct_url.json"], found


@pytest.mark.skipif(not os.environ.get("OARBANK_NODE_RUNTIME"),
                    reason="set OARBANK_NODE_RUNTIME to a node runtime scripts/build-node-runtime.ps1 built to check it")
def test_a_built_node_runtime_is_fit_to_package():
    check = _check_node_runtime()
    root = Path(os.environ["OARBANK_NODE_RUNTIME"])
    assert check.main([str(root), str(WXS.parents[2])]) == 0


def test_build_scripts_relocate_their_bundled_console_scripts():
    scripts = WXS.parents[2] / "scripts"
    coord = (scripts / "build-coordinator.sh").read_text(encoding="utf-8")
    call = '"$PY" -I "$REPO/scripts/relocate_shebangs.py" "$ROOT/python/bin" "$ROOT"'
    assert call in coord and coord.index(call) < coord.index('tar -czf "$TGZ"')
    assert coord.index("uv pip install") < coord.index(call)
    node = (scripts / "build-node-runtime.sh").read_text(encoding="utf-8")
    assert '"$PY" -I "$REPO/scripts/relocate_shebangs.py" "$OUT/bin"' in node
    windows = (scripts / "build-node-runtime.ps1").read_text(encoding="utf-8")
    call = '& "$Out\\python.exe" -I "$Repo\\scripts\\relocate_shebangs.py" "$Out\\Scripts" $Out'
    assert call in windows and windows.index('Copy-Item (Get-Command uv).Source') < windows.index(call)
    assert windows.index("uv pip install") < windows.index(call)


@pytest.mark.skipif(not __import__("os").environ.get("OARBANK_COORDINATOR_BUILD"),
                    reason="set OARBANK_COORDINATOR_BUILD to a coordinator build's .tar.gz to inspect it")
def test_a_coordinator_build_runs_from_where_it_is_unpacked(tmp_path):
    import os
    import tarfile
    with tarfile.open(os.environ["OARBANK_COORDINATOR_BUILD"]) as tf:
        tf.extractall(tmp_path, filter="tar")
    assert _relocate_shebangs().problems(tmp_path) == []
    for entry in sorted((tmp_path / "bin").iterdir()):
        assert os.access(entry, os.X_OK), entry.name
        head = entry.read_bytes()[:64]
        assert not head.startswith(b"#!") or head.startswith(b"#!/bin/sh\n"), (entry.name, head)
