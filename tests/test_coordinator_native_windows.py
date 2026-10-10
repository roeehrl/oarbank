"""Windows MSI ownership and safe activation; runtime checks use only staging and installer dry runs."""
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WXS = REPO / "deploy/windows/oarbank-coordinator.wxs"
INSTALLER = REPO / "deploy/oarbankd/install-oarbankd.ps1"
PACKAGER = REPO / "scripts/package-coordinator-windows.ps1"
NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell and native archive tools")
FILES = (
    "python/python.exe", "python/pythonw.exe", "bin/oarbankd.py", "bin/oarbank-console.py",
    "bin/oarbank-setup.py", "bin/oarbank-setup.cmd", "bin/oarbank.cmd", "bin/oarbank-sandbox.exe", "bin/uv.exe",
)


def _package():
    return ET.parse(WXS).getroot().find("w:Package", NS)


def _broker():
    return re.search(r"\$setupBroker = @'\n(.*?)\n'@", PACKAGER.read_text(), re.S).group(1)


def test_coordinator_msi_has_independent_identity_and_owns_only_its_package_tree():
    pkg = _package()
    agent = ET.parse(REPO / "deploy/windows/oarbank-agent.wxs").getroot().find("w:Package", NS)
    assert pkg.get("Scope") == "perMachine" and pkg.get("UpgradeCode") != agent.get("UpgradeCode")
    upgrade = pkg.find("w:MajorUpgrade", NS)
    assert upgrade.get("AllowSameVersionUpgrades") == "yes"
    assert upgrade.get("Schedule") == "afterInstallInitialize"  # old removal participates in rollback
    dirs = pkg.findall("w:StandardDirectory[@Id='ProgramFiles64Folder']/w:Directory/w:Directory/w:Directory", NS)
    assert [(d.get("Id"), d.get("Name")) for d in dirs] == [("PACKAGEFOLDER", "package")]
    assert pkg.find("w:Feature/w:Files", NS).attrib == {"Directory": "PACKAGEFOLDER", "Include": "$(var.PackageDir)\\**"}
    assert not pkg.findall(".//w:RemoveFile", NS)  # no wildcard deletion of data, legacy builds or the agent
    assert not pkg.findall(".//w:ServiceInstall", NS)  # initial configuration belongs to the wizard


def test_msi_upgrade_preserves_service_configuration_and_uninstall_has_rollback():
    pkg = _package()
    services = pkg.findall(".//w:ServiceControl", NS)
    assert {s.get("Name") for s in services} == {"dev.codonic.oarbank.oarbankd", "dev.codonic.oarbank.console"}
    assert all(s.get("Stop") == "both" and s.get("Start") == "install" and s.get("Wait") == "yes" for s in services)
    assert all(s.get("Remove") is None for s in services)
    steps = {s.get("Action"): s for s in pkg.findall("w:InstallExecuteSequence/w:Custom", NS)}
    assert steps["RemoveCoordinator"].get("Before") == "RemoveFiles"
    assert steps["RestoreCoordinator"].get("Before") == "RemoveCoordinator"
    assert steps["DiscardCoordinatorSnapshot"].get("After") == "RemoveCoordinator"
    assert all(s.get("Condition") == 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE' for s in steps.values())
    actions = {a.get("Id"): a for a in pkg.findall("w:CustomAction", NS)}
    assert actions["RemoveCoordinator"].get("Execute") == "deferred"
    assert actions["RestoreCoordinator"].get("Execute") == "rollback"
    assert all(a.get("Impersonate") == "no" for a in actions.values())
    command = pkg.find("w:SetProperty[@Id='RemoveCoordinator']", NS).get("Value")
    assert '-File "[PACKAGEFOLDER]install-oarbankd.ps1" -Uninstall -KeepPrograms' in command
    assert '-SaveConfiguration "[COORDINATORFOLDER]uninstall-[ProductCode].xml"' in command
    assert pkg.find("w:SetProperty[@Id='RestoreCoordinator']", NS).get("Value").endswith(
        '-RestoreConfiguration "[COORDINATORFOLDER]uninstall-[ProductCode].xml"'
    )


def test_initial_msi_install_does_not_attempt_to_start_services_that_the_wizard_has_not_created():
    pkg = _package()
    registration = pkg.find(".//w:Component[@Id='CoordinatorRegistration']", NS)
    assert registration.find("w:ServiceControl", NS) is None
    controls = pkg.findall(".//w:Component/w:ServiceControl/..", NS)
    assert len(controls) == 2
    for component in controls:
        service = component.find("w:ServiceControl", NS)
        prop = pkg.find(f"w:Property[@Id='{component.get('Condition')}']", NS)
        assert prop is not None and prop.get("Secure") == "yes"
        search = prop.find("w:RegistrySearch", NS)
        assert search.get("Root") == "HKLM" and search.get("Bitness") == "always64"
        assert search.get("Key") == "SYSTEM\\CurrentControlSet\\Services\\" + service.get("Name")
        assert search.get("Name") == "ImagePath" and search.get("Type") == "raw"
        assert component.get("Transitive") == "yes"
        assert pkg.find(f"w:Feature/w:ComponentRef[@Id='{component.get('Id')}']", NS) is not None


def test_start_menu_uses_hidden_elevation_broker_and_bundled_gui_interpreter():
    shortcut = _package().find(".//w:Shortcut", NS)
    pkg = _package()
    icon = pkg.find("w:Icon[@Id='OarbankIcon']", NS)
    assert shortcut.get("Icon") == icon.get("Id") and shortcut.get("IconIndex") == "0"
    assert icon.get("SourceFile") == "$(var.PackageDir)\\oarbank.ico"
    assert pkg.find("w:Property[@Id='ARPPRODUCTICON']", NS).get("Value") == icon.get("Id")
    from PIL import Image
    with Image.open(REPO / "deploy/icons/oarbank.ico") as image:
        assert {(16, 16), (32, 32), (48, 48), (256, 256)} <= image.ico.sizes()
    assert shortcut.get("Directory") == "ProgramMenuFolder" and shortcut.get("Advertise") == "no"
    assert shortcut.get("Target") == "[PACKAGEFOLDER]Oarbank Coordinator.exe"
    assert shortcut.get("Arguments") is None
    manifest = ET.parse(REPO / "deploy/windows/coordinator-tray.manifest").getroot()
    execution = next(e for e in manifest.iter() if e.tag.endswith('requestedExecutionLevel'))
    assert execution.get('level') == 'asInvoker'
    closer = next(e for e in pkg.iter() if e.tag.endswith('CloseApplication'))
    assert closer.get('Target') == 'Oarbank Coordinator.exe' and closer.get('CloseMessage') == 'yes'
    broker = _broker()
    assert "Join-Path $PSScriptRoot 'python\\pythonw.exe'" in broker
    assert "Join-Path $PSScriptRoot 'bin\\oarbank-setup.py'" in broker
    assert '-Verb RunAs -PassThru -Wait' in broker and '--root "' in broker
    assert "MessageBox]::Show" in broker and "$process.ExitCode -ne 0" in broker
    assert 'New-Service' not in broker and 'sc.exe' not in broker


def test_packager_defaults_select_repository_version_and_native_archive_and_write_lf_checksum():
    text = PACKAGER.read_text()
    assert '[Parameter(Mandatory)]' not in text
    assert '"$PSScriptRoot\\windows-arch.ps1" -Arch $Arch' in text
    assert '"$Repo\\pyproject.toml"' in text and '"$Repo\\dist\\oarbank-coordinator-$Version-$Platform.tar.gz"' in text
    assert "'python\\pythonw.exe'" in text  # fail before WiX if the GUI interpreter is absent
    assert 'WriteAllText("$Root\\oarbank-setup.ps1", $setupBroker)' in text
    lines = [line for line in text.splitlines() if "SHA256SUMS-" in line]
    assert len(lines) == 1 and "WriteAllText" in lines[0] and '`n"' in lines[0]
    assert "& signtool sign" in text and "finally {" in text


def _ps(script, *args, env=None):
    from helpers import windows_powershell
    return windows_powershell("-ExecutionPolicy", "Bypass", "-File", str(script), *map(str, args),
                              env=env, capture_output=True, text=True)


def _manifest(platform=None):
    if platform is None:
        from oarbank_sdk.portable import host_platform
        platform = host_platform()
    return {"format": 1, "version": "2.6.0", "platform": platform,
            "exec": ["python/python.exe", "-I", "bin/oarbankd.py"],
            "console": ["python/python.exe", "-I", "bin/oarbank-console.py"]}


def _installed(tmp_path, manifest=None):
    root = tmp_path / "Payload with spaces" / "package"
    for name in FILES:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"fixture only; never executed")
    (root / "oarbank-coordinator.json").write_text(json.dumps(manifest or _manifest()))
    return root


def _snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _env(tmp_path):
    return {**os.environ, "ProgramFiles": str(tmp_path / "Programs"), "ProgramW6432": str(tmp_path / "Programs"),
            "ProgramData": str(tmp_path / "Data")}


@WINDOWS
def test_installed_directory_activation_and_keep_programs_are_read_only_dry_runs(tmp_path):
    root = _installed(tmp_path)
    before = _snapshot(root)
    env = _env(tmp_path)
    for _ in range(2):  # reconfiguration keeps the same payload and junction target
        r = _ps(INSTALLER, "-Installed", root, "-AgentBind", "192.168.1.10", "-DryRun", env=env)
        assert r.returncode == 0, r.stderr
        assert f"junction {env['ProgramFiles']}\\Oarbank\\Coordinator\\current -> {root}" in r.stdout
        assert 'unpack ' not in r.stdout and 'remove ' not in r.stdout
        assert "--agent-bind 192.168.1.10 --agent-port 7443" in r.stdout
        assert "OARBANKD_HOME=" in r.stdout and "icacls.exe" in r.stdout
        assert _snapshot(root) == before
    r = _ps(INSTALLER, "-Uninstall", "-KeepPrograms", "-SaveConfiguration", tmp_path / "rollback.xml", "-DryRun", env=env)
    assert r.returncode == 0, r.stderr
    assert "Keeping programs" in r.stdout and "home stays" in r.stdout
    assert _snapshot(root) == before and not (tmp_path / "rollback.xml").exists()
    assert not (tmp_path / "Programs").exists() and not (tmp_path / "Data").exists()
    r = _ps(INSTALLER, "-RestoreConfiguration", tmp_path / "rollback.xml", "-DryRun", env=env)
    assert r.returncode == 0 and "restore service/firewall/junction" in r.stdout


@WINDOWS
@pytest.mark.parametrize("bad", ["format", "version", "platform", "exec", "missing", "json", "both", "port"])
def test_invalid_installed_build_fails_before_service_changes(tmp_path, bad):
    root = _installed(tmp_path)
    manifest_path = root / "oarbank-coordinator.json"
    manifest = json.loads(manifest_path.read_text())
    if bad in ("format", "version", "platform", "exec"):
        manifest[bad] = {"format": 2, "version": "../escape", "platform": "linux-amd64", "exec": ["../bad.exe"]}[bad]
        manifest_path.write_text(json.dumps(manifest))
    elif bad == "missing":
        (root / "python/python.exe").unlink()
    elif bad == "json":
        manifest_path.write_text("{broken")
    extra = ["-Build", "unused.tar.gz"] if bad == "both" else ["-AgentPort", "65536"] if bad == "port" else []
    r = _ps(INSTALLER, "-Installed", root, "-AgentBind", "127.0.0.1", "-DryRun", *extra, env=_env(tmp_path))
    assert r.returncode != 0 and r.stderr
    assert "New-Service" not in r.stdout and "sc.exe" not in r.stdout and "junction " not in r.stdout


def _archive(tmp_path, platform="windows-amd64", missing=None, extra=None):
    archive = tmp_path / "coordinator build.tar.gz"
    content = {name: b"fixture only; never executed" for name in FILES if name != missing}
    content["oarbank-coordinator.json"] = json.dumps(_manifest(platform)).encode()
    if extra:
        content[extra] = b"invalid entry"
    with tarfile.open(archive, "w:gz") as tf:
        for name, data in content.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive


@WINDOWS
@pytest.mark.parametrize("platform,arch", [("windows-amd64", "x64"), ("windows-arm64", "arm64")])
def test_package_archive_dry_run_stages_setup_without_building_or_installing(tmp_path, platform, arch):
    archive = _archive(tmp_path, platform)
    before = archive.read_bytes()
    output = tmp_path / "MSI output"
    r = _ps(PACKAGER, "-Build", archive, "-Out", output, "-DryRun")
    assert r.returncode == 0, r.stderr
    assert f'"-arch" "{arch}"' in r.stdout and '"Version=2.6.0"' in r.stdout
    assert f"oarbank-coordinator-2.6.0-windows-{arch}.msi" in r.stdout
    assert archive.read_bytes() == before and not output.exists()


@WINDOWS
@pytest.mark.parametrize("bad", ["pythonw", "setup", "traversal", "platform", "arch", "version"])
def test_package_rejects_unusable_or_unsafe_payload_before_wix(tmp_path, bad):
    archive = _archive(tmp_path, platform="linux-amd64" if bad == "platform" else "windows-amd64",
                       missing={"pythonw": "python/pythonw.exe", "setup": "bin/oarbank-setup.py"}.get(bad),
                       extra="../escaped.txt" if bad == "traversal" else None)
    extra = ["-Arch", "arm64"] if bad == "arch" else ["-Version", "2.6.1"] if bad == "version" else []
    r = _ps(PACKAGER, "-Build", archive, "-DryRun", *extra)
    assert r.returncode != 0 and r.stderr
    assert "wix " not in r.stdout and not (tmp_path / "escaped.txt").exists()


@WINDOWS
def test_powershell_sources_and_generated_elevation_broker_parse(tmp_path):
    from helpers import windows_powershell
    broker = tmp_path / "broker.ps1"
    broker.write_text(_broker())
    for script in (INSTALLER, PACKAGER, broker):
        # The parser reads source only; it never invokes commands in those scripts.
        command = "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors); if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
        parser = tmp_path / "parse.ps1"
        parser.write_text(command)
        r = windows_powershell("-ExecutionPolicy", "Bypass", "-File", str(parser), str(script), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def _forwarder():
    """package\\cli\\oarbank.cmd as the packager writes it."""
    block = re.search(r"\$cliForwarder = @\(\n(.*?)\n  \)", PACKAGER.read_text(), re.S).group(1)
    return [re.fullmatch(r"\s*'(.*)',?", line).group(1).replace("''", "'") for line in block.splitlines()]


def test_msi_puts_only_the_cli_forwarder_folder_on_the_system_path_and_removes_it_on_uninstall():
    pkg = _package()
    component = pkg.find(".//w:Directory[@Id='PACKAGEFOLDER']/w:Component[@Id='CoordinatorCliPath']", NS)
    assert component is not None and component.get("Condition") is None
    assert pkg.find("w:Feature/w:ComponentRef[@Id='CoordinatorCliPath']", NS) is not None
    env = component.findall("w:Environment", NS)
    assert len(env) == 1 and env[0].attrib == {
        "Id": "CoordinatorCliPath", "Name": "PATH", "Value": "[PACKAGEFOLDER]cli", "Action": "set", "Part": "last",
        "System": "yes", "Permanent": "no"}
    # one PATH entry in the whole package: not bin\ (uv.exe, the setup scripts) and not the moving current junction
    assert len(pkg.findall(".//w:Environment", NS)) == 1
    key = component.find("w:RegistryValue", NS)
    assert key.get("KeyPath") == "yes" and key.get("Value") == "[PACKAGEFOLDER]cli"
    text = PACKAGER.read_text()
    assert 'New-Item -ItemType Directory -Force "$Root\\cli"' in text
    assert 'WriteAllText("$Root\\cli\\oarbank.cmd", (($cliForwarder -join "`r`n") + "`r`n"))' in text


def test_the_path_forwarder_runs_the_services_build_else_the_packages_own():
    lines = _forwarder()
    assert lines[0] == "@echo off"
    assert lines[2:] == [
        'if not exist "%~dp0..\\..\\current\\bin\\oarbank.cmd" goto package',
        '"%~dp0..\\..\\current\\bin\\oarbank.cmd" %*',      # no `call`: control and the exit code stay with the CLI
        ':package',
        '"%~dp0..\\bin\\oarbank.cmd" %*',
    ]
    assert all("(" not in line for line in lines[2:])  # no block: %* may hold a parenthesis


@WINDOWS
def test_the_path_forwarder_forwards_arguments_and_exit_codes(tmp_path):
    coordinator = tmp_path / "Oarbank with spaces" / "Coordinator"
    cli = coordinator / "package" / "cli"
    cli.mkdir(parents=True)
    (cli / "oarbank.cmd").write_bytes(("\r\n".join(_forwarder()) + "\r\n").encode("ascii"))

    def build(name, code):
        (coordinator / name / "bin").mkdir(parents=True)
        (coordinator / name / "bin" / "oarbank.cmd").write_bytes(f"@echo {name}: %*& exit /b {code}\r\n".encode("ascii"))

    def run():
        return subprocess.run(["cmd.exe", "/d", "/c", "oarbank", "join-code", "--label", "a b"], cwd=tmp_path,
                              env={**os.environ, "PATH": f"{cli};{os.environ['SystemRoot']}\\System32"},
                              capture_output=True, text=True)

    build("package", 3)
    r = run()                                              # before setup: the package's own CLI
    assert (r.returncode, r.stdout.strip()) == (3, 'package: join-code --label "a b"'), r
    build("current", 7)
    r = run()                                              # after setup: the build Coordinator\current names
    assert (r.returncode, r.stdout.strip()) == (7, 'current: join-code --label "a b"'), r
