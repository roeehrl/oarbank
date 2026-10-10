"""The Windows node package's enrollment parts (docs/design/node-enrollment.md), checked without building them: the MSI's
properties, setup actions, join page and last page, PATH entry, oarbank:// handler and tray app, the Group Policy
template, the tray app's source, and the build and CI scripts that make and exercise them. WiX and the .NET Framework
compiler run on Windows CI (.github/workflows/msi.yml)."""
import itertools
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WINDOWS = REPO / "deploy" / "windows"
WXS = WINDOWS / "oarbank-agent.wxs"
TRAY = WINDOWS / "NodeTray.cs"
ADMX = WINDOWS / "admx" / "oarbank.admx"
ADML = WINDOWS / "admx" / "en-US" / "oarbank.adml"
PACKAGE = REPO / "scripts" / "package-windows.ps1"
CI = REPO / "scripts" / "ci-windows-msi.ps1"
WORKFLOW = REPO / ".github" / "workflows" / "msi.yml"
POLICY_RS = REPO / "rust" / "crates" / "oarbank-agent" / "src" / "policy.rs"
SUPPORT_RS = REPO / "rust" / "crates" / "oarbank-launcher" / "src" / "container_support.rs"
SETUP_RS = REPO / "rust" / "crates" / "oarbank-launcher" / "src" / "setup.rs"
NODE_RS = REPO / "rust" / "crates" / "oarbank-launcher" / "src" / "node.rs"
AGENT_MAIN_RS = REPO / "rust" / "crates" / "oarbank-agent" / "src" / "main.rs"
NS = {"w": "http://wixtoolset.org/schemas/v4/wxs", "util": "http://wixtoolset.org/schemas/v4/wxs/util"}
GP = {"p": "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"}
POLICY_KEY = r"SOFTWARE\Policies\Codonic\Oarbank\Agent"
LAUNCHER = '"[INSTALLFOLDER]oarbank-launcher.exe"'
# the dialogs the WixUI extension's library provides (WixUI_Common and the dialogs WixUI_Minimal references)
WIXUI_DIALOGS = {"ErrorDlg", "FatalError", "FilesInUse", "MsiRMFilesInUse", "PrepareDlg", "ProgressDlg", "ResumeDlg",
                 "UserExit", "ExitDialog", "MaintenanceWelcomeDlg", "MaintenanceTypeDlg", "VerifyReadyDlg", "CancelDlg",
                 "WaitForCostingDlg", "OutOfDiskDlg", "OutOfRbDiskDlg"}


def _pkg():
    return ET.parse(WXS).getroot().find("w:Package", NS)


def _prop(pkg, pid):
    return pkg.find(f"w:Property[@Id='{pid}']", NS)


def _set(pkg, pid):
    return pkg.find(f"w:SetProperty[@Id='{pid}']", NS)


def _ca(pkg, cid):
    return pkg.find(f"w:CustomAction[@Id='{cid}']", NS)


def _steps(pkg):
    return {c.get("Action"): c for c in pkg.findall("w:InstallExecuteSequence/w:Custom", NS)}


def _dialog(pkg, did):
    return pkg.find(f"w:UI/w:Dialog[@Id='{did}']", NS)


def _holds(condition, props):
    """A Windows Installer condition made of property names, PROPERTY="value" comparisons, AND, OR, NOT and parentheses,
    for the properties set."""
    tokens = re.findall(r'\(|\)|[A-Za-z_][A-Za-z0-9_.]*="[^"]*"|[A-Za-z_][A-Za-z0-9_.]*|\S', condition)
    py = []
    for t in tokens:
        if t in ("(", ")"):
            py.append(t)
        elif t in ("AND", "OR", "NOT"):
            py.append(t.lower())
        elif m := re.fullmatch(r'([A-Za-z_][A-Za-z0-9_.]*)="([^"]*)"', t):
            py.append(repr(props.get(m.group(1)) == m.group(2)))
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", t):
            py.append(repr(bool(props.get(t))))
        else:
            raise AssertionError(f"not a plain condition: {condition}")
    return eval(" ".join(py), {"__builtins__": {}})  # noqa: S307 (built from the tokens above only)


# MARK: properties

def test_the_msi_properties_of_the_contract_and_the_code_stays_secret():
    pkg = _pkg()
    code = _prop(pkg, "JOINCODE")
    assert (code.get("Secure"), code.get("Hidden")) == ("yes", "yes") and code.get("Value") is None
    for name in ("JOINCODEFILE", "COORDINATOR", "CONTAINERS", "NAME", "NOLAUNCH"):
        assert _prop(pkg, name) is not None and _prop(pkg, name).get("Secure") == "yes", name   # the UI hands them on
    # the deferred action's data holds the code: hidden too, and the action hides its target
    assert _prop(pkg, "SetupWithCode").get("Hidden") == "yes"
    assert _ca(pkg, "SetupWithCode").get("HideTarget") == "yes"
    # nothing remembers the code: no search fills it, no registry value or other action carries it
    assert not code.findall("*")
    text = WXS.read_text(encoding="utf-8")
    users = [e.get("Id") for e in pkg.iter() if "[JOINCODE]" in " ".join(e.attrib.values())]
    assert users == ["SetupWithCode"], users
    assert not [v for v in pkg.iter(f"{{{NS['w']}}}RegistryValue") if "JOINCODE" in (v.get("Value") or "")]
    assert "/Library/Oarbank/etc" not in text and "/etc/oarbank/join-code" not in text and "OB1-" not in text


# MARK: setting up the node's service

def test_setup_actions_run_the_launcher_elevated_with_the_right_source_of_the_code():
    pkg = _pkg()
    commands = {
        # a code made for container jobs gets container support after the installer (--containers-later)
        "SetupWithFile": f'{LAUNCHER} setup --scope system --or-wait --containers-later --join-code-file "[JOINCODEFILE]" [NodeNameArgument]',
        "SetupWithCode": f'{LAUNCHER} setup --scope system --or-wait --containers-later --join-code "[JOINCODE]" [NodeNameArgument]',
        "SetupWithUrl": f'{LAUNCHER} setup --scope system --coordinator "[COORDINATOR]" [NodeNameArgument]',
        # the waiting service: no code, no coordinator
        "SetupWaiting": f"{LAUNCHER} setup --scope system [NodeNameArgument]",
    }
    for action, command in commands.items():
        assert _set(pkg, action).get("Value") == command, action
        assert _set(pkg, action).get("Before") == action and _set(pkg, action).get("Sequence") == "execute"
        ca = _ca(pkg, action)
        assert (ca.get("BinaryRef"), ca.get("DllEntry"), ca.get("Execute"), ca.get("Impersonate"), ca.get("Return")) == \
            ("Wix4UtilCA_$(sys.BUILDARCHSHORT)", "WixQuietExec", "deferred", "no", "check"), action
        assert ca.get("HideTarget") == ("yes" if action == "SetupWithCode" else "no"), action
    # --name only when NAME is set, never on an upgrade; private (mixed case), so the command line cannot set it
    name = _set(pkg, "NodeNameArgument")
    assert name.get("Value") == '--name "[NAME]"' and name.get("Sequence") == "execute"
    assert name.get("Condition") == "NAME AND NOT WIX_UPGRADE_DETECTED"
    assert name.get("Id") != name.get("Id").upper()
    steps = _steps(pkg)
    assert [steps[a].get("After") for a in ("RollbackContainers", "SetupWithFile", "SetupWithCode", "SetupWithUrl", "SetupWaiting",
                                            "ScheduleContainers")] == \
        ["InstallFiles", "RollbackContainers", "SetupWithFile", "SetupWithCode", "SetupWithUrl", "SetupWaiting"]


def test_exactly_one_setup_runs_on_a_first_install_the_plain_one_on_an_upgrade_none_on_repair():
    steps = _steps(_pkg())
    setups = ("SetupWithFile", "SetupWithCode", "SetupWithUrl", "SetupWaiting")
    names = ("JOINCODEFILE", "JOINCODE", "COORDINATOR")
    for given in itertools.product((False, True), repeat=3):
        props = dict(zip(names, given))
        first = [a for a in setups if _holds(steps[a].get("Condition"), props)]
        expected = "SetupWithFile" if props["JOINCODEFILE"] else "SetupWithCode" if props["JOINCODE"] else \
            "SetupWithUrl" if props["COORDINATOR"] else "SetupWaiting"
        assert first == [expected], (props, first)
        # an installed node ignores the properties on a major upgrade, and a repair sets nothing up
        assert [a for a in setups if _holds(steps[a].get("Condition"), {**props, "WIX_UPGRADE_DETECTED": True})] == ["SetupWaiting"]
        assert not [a for a in setups if _holds(steps[a].get("Condition"), {**props, "Installed": True})]


def _order(steps):
    """The execute sequence's custom actions in order, from their After/Before chains (standard actions as anchors)."""
    anchors = {"InstallFiles": 4000, "InstallServices": 5800, "RemoveFiles": 3500}
    pos = dict(anchors)
    pending = dict(steps)
    while pending:
        progressed = False
        for name, c in list(pending.items()):
            ref = c.get("After") or c.get("Before")
            if ref in pos:
                pos[name] = pos[ref] + (0.001 if c.get("After") else -0.001) * (1 + len(pos))
                del pending[name]
                progressed = True
        assert progressed, pending
    return pos


def test_no_custom_action_installs_container_prerequisites_inside_the_msi():
    # the WSL package is itself a Windows Installer package: installing it from a custom action is a nested
    # installation (error 2755/1622, status 1603 on a real PC), so nothing in the MSI runs `containers install`
    pkg = _pkg()
    commands = [e.get("Value") or "" for e in pkg.iter(f"{{{NS['w']}}}SetProperty")] + \
        [e.get("ExeCommand") or "" for e in pkg.iter(f"{{{NS['w']}}}CustomAction")]
    assert not [c for c in commands if "containers install" in c or "oarbank-agent.exe" in c], commands
    assert "InstallContainers" not in _steps(pkg) and _ca(pkg, "InstallContainers") is None
    # no nested-installation custom action types either (7, 23, 39: a package as the action's source)
    assert not [c for c in pkg.iter(f"{{{NS['w']}}}CustomAction") if c.get("PackageRef") or c.get("ProductCode")]


def test_container_support_is_a_task_registered_by_the_msi_cancelled_by_rollback_and_uninstall():
    pkg = _pkg()
    steps = _steps(pkg)
    expected = {"ScheduleContainers": ("container-support schedule", "deferred"),
                "RollbackContainers": ("container-support cancel", "rollback"),
                "CancelContainers": ("container-support cancel", "deferred")}
    for action, (command, execute) in expected.items():
        assert _set(pkg, action).get("Value") == f"{LAUNCHER} {command}", action
        assert _set(pkg, action).get("Before") == action and _set(pkg, action).get("Sequence") == "execute"
        ca = _ca(pkg, action)
        # elevated (LocalSystem registers a LocalSystem task), and never a reason for the install to fail
        assert (ca.get("BinaryRef"), ca.get("DllEntry"), ca.get("Execute"), ca.get("Impersonate"), ca.get("Return")) == \
            ("Wix4UtilCA_$(sys.BUILDARCHSHORT)", "WixQuietExec", execute, "no", "ignore"), action
    when = {a: steps[a].get("Condition") for a in expected}
    cases = {"first install": {}, "first install, CONTAINERS=1": {"CONTAINERS": "1"},
             "upgrade, CONTAINERS=1": {"CONTAINERS": "1", "WIX_UPGRADE_DETECTED": True},
             "repair, CONTAINERS=1": {"CONTAINERS": "1", "Installed": True},
             "uninstall": {"Installed": True, "REMOVE": "ALL"},
             "uninstall, CONTAINERS=1": {"Installed": True, "REMOVE": "ALL", "CONTAINERS": "1"},
             "removed by an upgrade": {"Installed": True, "REMOVE": "ALL", "UPGRADINGPRODUCTCODE": "{X}"},
             "CONTAINERS=0": {"CONTAINERS": "0"}}
    runs = {name: sorted(a for a, c in when.items() if _holds(c, props)) for name, props in cases.items()}
    assert runs == {"first install": ["RollbackContainers"],
                    "first install, CONTAINERS=1": ["RollbackContainers", "ScheduleContainers"],
                    "upgrade, CONTAINERS=1": ["RollbackContainers", "ScheduleContainers"],
                    "repair, CONTAINERS=1": ["ScheduleContainers"],
                    "uninstall": ["CancelContainers"], "uninstall, CONTAINERS=1": ["CancelContainers"],
                    # the old product's removal during a major upgrade keeps the new product's task
                    "removed by an upgrade": [],
                    "CONTAINERS=0": ["RollbackContainers"]}, runs
    order = _order(steps)
    # the rollback comes before everything that may register the task (a code's flag in setup, CONTAINERS=1), and
    # after the files it runs; the uninstall cancels before the node and the files go
    for registers in ("SetupWithFile", "SetupWithCode", "ScheduleContainers"):
        assert order["InstallFiles"] < order["RollbackContainers"] < order[registers], registers
    assert order["CancelContainers"] < order["RemoveNode"] < order["RemoveFiles"]


def test_the_launcher_owns_the_task_and_the_agent_never_installs_inside_another_installation():
    rs = SUPPORT_RS.read_text(encoding="utf-8")
    # the task's events name this package's product
    product = re.search(r'pub const PRODUCT: &str = "([^"]+)";', rs).group(1)
    assert _pkg().get("Name") == product
    assert "EventID=1033 or EventID=1035" in rs and "<BootTrigger>" in rs and "<UserId>S-1-5-18</UserId>" in rs
    assert '"containers", "install", "--wait"' in rs
    # setup schedules it only for the installer's --containers-later; oarbank-node join installs directly, outside any MSI
    setup = SETUP_RS.read_text(encoding="utf-8")
    assert '"--containers-later"' in setup and "c.containers()" in setup and "container_support::schedule()" in setup
    node = NODE_RS.read_text(encoding="utf-8")
    assert '["containers", "install", "--wait", "600"]' in node and '"--containers-later"' not in node
    # the agent waits for, or refuses during, another installation (Global\_MSIExecute) and exits 1618 then
    main = AGENT_MAIN_RS.read_text(encoding="utf-8")
    assert "wslc::wait_for_installer(" in main and "EXIT_INSTALLER_BUSY" in main


# MARK: what it installs

def test_oarbank_node_is_installed_and_on_the_system_path():
    pkg = _pkg()
    comp = pkg.find(".//w:Component[@Id='NodeCli']", NS)
    assert comp.find("w:File", NS).get("Source") == r"$(var.BinDir)\oarbank-node.exe"
    env = comp.find("w:Environment", NS)
    assert {k: env.get(k) for k in ("Name", "Value", "Action", "Part", "System", "Permanent")} == \
        {"Name": "PATH", "Value": "[INSTALLFOLDER]", "Action": "set", "Part": "last", "System": "yes", "Permanent": "no"}


def test_the_tray_app_its_shortcut_and_its_closing_on_upgrade():
    pkg = _pkg()
    tray = pkg.find(".//w:File[@Id='NodeTray']", NS)
    assert (tray.get("Name"), tray.get("Source")) == ("Oarbank Node.exe", r"$(var.BinDir)\Oarbank Node.exe")
    shortcut = tray.find("w:Shortcut", NS)
    assert (shortcut.get("Name"), shortcut.get("Directory"), shortcut.get("Advertise")) == ("Oarbank Node", "ProgramMenuFolder", "no")
    assert pkg.find("w:StandardDirectory[@Id='ProgramMenuFolder']", NS) is not None
    assert pkg.find(".//w:File[@Id='NodeIcon']", NS).get("Name") == "oarbank.ico"     # the tray's icon, loaded beside it
    close = pkg.find("util:CloseApplication", NS)
    assert close.get("Target") == "Oarbank Node.exe" and close.get("CloseMessage") == "yes"


def test_the_join_window_ships_beside_the_runtime():
    pkg = _pkg()
    folder = pkg.find(".//w:Directory[@Id='INSTALLFOLDER']/w:Directory[@Id='JOINFOLDER']", NS)
    assert folder.get("Name") == "join"
    files = {f.get("Directory"): f.get("Include") for f in pkg.findall("w:Feature/w:Files", NS)}
    assert files == {"RUNTIMEFOLDER": r"$(var.RuntimeDir)\**", "JOINFOLDER": r"$(var.JoinDir)\**"}


def test_the_oarbank_link_handler():
    pkg = _pkg()
    key = pkg.find(".//w:Component[@Id='NodeProtocol']/w:RegistryKey", NS)
    assert (key.get("Root"), key.get("Key"), key.get("ForceDeleteOnUninstall")) == ("HKCR", "oarbank", "yes")
    values = {v.get("Name"): v.get("Value") for v in key.findall("w:RegistryValue", NS)}
    assert values == {None: "URL:Oarbank", "URL Protocol": ""}
    sub = {k.get("Key"): k.find("w:RegistryValue", NS).get("Value") for k in key.findall("w:RegistryKey", NS)}
    assert sub == {"DefaultIcon": '"[INSTALLFOLDER]Oarbank Node.exe",0',
                   r"shell\open\command": '"[INSTALLFOLDER]Oarbank Node.exe" --link "%1"'}


def test_every_component_is_in_the_feature():
    pkg = _pkg()
    components = {c.get("Id") for c in pkg.iter(f"{{{NS['w']}}}Component")}
    refs = {r.get("Id") for r in pkg.findall("w:Feature/w:ComponentRef", NS)}
    assert components == refs and {"NodeCli", "NodeTray", "NodeProtocol"} <= refs


# MARK: the attended install

def test_the_join_page_takes_the_code_in_a_password_field_and_works_without_one():
    pkg = _pkg()
    page = _dialog(pkg, "JoinDlg")
    code = page.find("w:Control[@Property='JOINCODE']", NS)
    assert (code.get("Type"), code.get("Password")) == ("Edit", "yes")
    name = page.find("w:Control[@Property='NAME']", NS)
    assert name.get("Type") == "Edit" and name.get("Password") is None
    containers = page.find("w:Control[@Property='CONTAINERS']", NS)
    assert (containers.get("Type"), containers.get("CheckBoxValue")) == ("CheckBox", "1")
    assert "installs WSL components after setup; may need a restart" in containers.get("Text")
    texts = " ".join(c.get("Text") or "" for c in page.findall("w:Control", NS))
    assert "Paste the join code from your Oarbank console, or leave it empty to join later from Oarbank Node." in texts
    install = page.find("w:Control[@Id='Install']", NS)
    ends = [p for p in install.findall("w:Publish", NS) if p.get("Event") == "EndDialog"]
    assert ends and all("JOINCODE" not in (p.get("Condition") or "") for p in ends)    # an empty field goes on
    # only a first install shows it (an upgrade gets its own page; repair and removal the maintenance pages)
    shows = {s.get("Dialog"): s for s in pkg.findall("w:UI/w:InstallUISequence/w:Show", NS)}
    assert shows["JoinDlg"].get("Condition") == "NOT Installed AND NOT WIX_UPGRADE_DETECTED"
    assert shows["UpgradeDlg"].get("Condition") == "NOT Installed AND WIX_UPGRADE_DETECTED"
    assert {s.get("Before") for s in shows.values()} == {"ProgressDlg"}


def test_the_last_page_opens_oarbank_node_at_the_join_window_only_when_asked():
    pkg = _pkg()
    assert _prop(pkg, "WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT").get("Value") == "Open Oarbank Node to join this PC"
    # ticked by default only when there is still a join to do and NOLAUNCH is not 1
    tick = next(p for p in _dialog(pkg, "JoinDlg").find("w:Control[@Id='Install']", NS).findall("w:Publish", NS)
                if p.get("Property") == "WIXUI_EXITDIALOGOPTIONALCHECKBOX")
    assert tick.get("Value") == "1"
    assert not _holds(tick.get("Condition").replace('NOLAUNCH <> "1"', "NOT NOLAUNCH_IS_1"), {"JOINCODE": True})
    assert _holds(tick.get("Condition").replace('NOLAUNCH <> "1"', "NOT NOLAUNCH_IS_1"), {})
    assert not _holds(tick.get("Condition").replace('NOLAUNCH <> "1"', "NOT NOLAUNCH_IS_1"), {"NOLAUNCH_IS_1": True})
    finish = {p.get("Event"): p for p in pkg.findall("w:UI/w:Publish[@Dialog='ExitDialog'][@Control='Finish']", NS)}
    assert finish["DoAction"].get("Value") == "LaunchNodeTray"
    assert finish["DoAction"].get("Condition") == "WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 AND NOT Installed"
    assert int(finish["DoAction"].get("Order")) < int(finish["EndDialog"].get("Order"))
    # the installed tray app with --join, as the person installing (an immediate action in the UI, never elevated)
    launch = _ca(pkg, "LaunchNodeTray")
    assert (launch.get("FileRef"), launch.get("ExeCommand"), launch.get("Return")) == ("NodeTray", "--join", "asyncNoWait")
    assert launch.get("Execute") in (None, "immediate") and launch.get("Impersonate") != "no"
    # nothing in the execute sequence (a silent install) launches anything
    assert "LaunchNodeTray" not in _steps(pkg)


def test_the_dialog_chain_is_complete():
    pkg = _pkg()
    ui = pkg.find("w:UI", NS)
    assert pkg.find("w:UIRef[@Id='WixUI_Common']", NS) is not None
    local = {d.get("Id"): d for d in ui.findall("w:Dialog", NS)}
    assert set(local) == {"JoinDlg", "UpgradeDlg"}
    known = WIXUI_DIALOGS | set(local)
    for ref in ui.findall("w:DialogRef", NS):
        assert ref.get("Id") in WIXUI_DIALOGS, ref.get("Id")
    publishes = [(None, p) for p in ui.findall("w:Publish", NS)] + \
        [(d, p) for d in local.values() for c in d.findall("w:Control", NS) for p in c.findall("w:Publish", NS)]
    for dialog, p in publishes:
        if p.get("Event") in ("NewDialog", "SpawnDialog", "SpawnWaitDialog"):
            assert p.get("Value") in known, p.attrib
        if dialog is None:
            assert p.get("Dialog") in known, p.attrib
    for s in ui.findall("w:InstallUISequence/w:Show", NS):
        assert s.get("Dialog") in local
    for d in local.values():
        ids = [c.get("Id") for c in d.findall("w:Control", NS)]
        assert len(ids) == len(set(ids)), d.get("Id")
        buttons = [c for c in d.findall("w:Control", NS) if c.get("Type") == "PushButton"]
        assert sum(c.get("Default") == "yes" for c in buttons) == 1 and sum(c.get("Cancel") == "yes" for c in buttons) == 1
        cancel = next(c for c in buttons if c.get("Cancel") == "yes").find("w:Publish", NS)
        assert (cancel.get("Event"), cancel.get("Value")) == ("SpawnDialog", "CancelDlg")
    # the text styles the dialogs name are defined
    styles = {t.get("Id") for t in ui.findall("w:TextStyle", NS)}
    for d in local.values():
        for c in d.findall("w:Control", NS):
            for style in re.findall(r"\{\\(\w+)\}", c.get("Text") or ""):
                assert style in styles, style
    assert ui.find("w:Property[@Id='DefaultUIFont']", NS).get("Value") in styles


# MARK: the Group Policy template

def _strings():
    adml = ET.parse(ADML).getroot()
    strings = {s.get("id"): (s.text or "") for s in adml.findall("p:resources/p:stringTable/p:string", GP)}
    presentations = {p.get("id"): p for p in adml.findall("p:resources/p:presentationTable/p:presentation", GP)}
    return adml, strings, presentations


def test_the_admx_template_is_well_formed_and_every_reference_resolves():
    admx = ET.parse(ADMX).getroot()
    adml, strings, presentations = _strings()
    for root in (admx, adml):
        assert root.get("revision") == "1.0" and root.get("schemaVersion") == "1.0"
    target = admx.find("p:policyNamespaces/p:target", GP)
    assert target.get("prefix") == "oarbank" and target.get("namespace") == "Codonic.Policies.Oarbank"
    assert admx.find("p:resources", GP).get("minRequiredRevision") == "1.0"
    text = ADMX.read_text(encoding="utf-8")
    for ref in re.findall(r"\$\(string\.([^)]+)\)", text):
        assert ref in strings and strings[ref].strip(), ref
    for ref in re.findall(r"\$\(presentation\.([^)]+)\)", text):
        assert ref in presentations, ref
    supported = {d.get("name") for d in admx.findall("p:supportedOn/p:definitions/p:definition", GP)}
    categories = {c.get("name"): c for c in admx.findall("p:categories/p:category", GP)}
    # Codonic > Oarbank > Node
    parent = lambda name: (categories[name].find("p:parentCategory", GP).get("ref") if categories[name].find("p:parentCategory", GP) is not None else None)  # noqa: E731
    assert (parent("Node"), parent("Oarbank"), parent("Codonic")) == ("Oarbank", "Codonic", None)
    for policy in admx.findall("p:policies/p:policy", GP):
        assert policy.get("class") == "Machine" and policy.get("key") == POLICY_KEY
        assert policy.find("p:parentCategory", GP).get("ref") == "Node"
        assert policy.find("p:supportedOn", GP).get("ref") in supported
        pres = policy.get("presentation")
        elements = policy.findall("p:elements/*", GP)
        if elements:
            refs = {t.get("refId") for t in presentations[re.fullmatch(r"\$\(presentation\.(.+)\)", pres).group(1)].findall("*", GP)}
            assert refs == {e.get("id") for e in elements}, policy.get("name")


def test_the_admx_values_are_the_ones_the_agent_reads():
    admx = ET.parse(ADMX).getroot()
    policies = {p.get("name"): p for p in admx.findall("p:policies/p:policy", GP)}
    texts, switches = {}, {}
    for name, p in policies.items():
        for t in p.findall("p:elements/p:text", GP):
            texts[t.get("valueName")] = name
        if p.get("valueName"):
            switches[p.get("valueName")] = (p.find("p:enabledValue/p:decimal", GP).get("value"),
                                            p.find("p:disabledValue/p:decimal", GP).get("value"))
    assert set(texts) == {"JoinCode", "Coordinator", "Name", "ManagedByOrganizationName"}
    assert switches == {"Containers": ("1", "0"), "AllowUserJoin": ("1", "0"), "ShowStatusIcon": ("1", "0")}  # REG_DWORD 1 / 0
    rust = POLICY_RS.read_text(encoding="utf-8")
    assert POLICY_KEY in rust
    for value in texts:
        assert f's("{value}")' in rust, value
    for value in switches:
        assert f'b("{value}")' in rust, value


# MARK: the tray app

def test_the_tray_app_reads_the_status_document_and_policy_and_runs_the_join_window():
    src = TRAY.read_text(encoding="utf-8")
    assert '"Oarbank", "status", "node.json"' in src and "CommonApplicationData" in src
    assert f'@"{POLICY_KEY}"' in src and '"AllowUserJoin"' in src and '"ManagedByOrganizationName"' in src
    for item in ('"Join this PC…"', '"Status…"', '"Hide from notification area"', '"This PC\'s node keeps running"', '"Oarbank Node"'):
        assert item in src, item
    # one setting (docs/design/node-enrollment.md, "Menu bar and tray"): shown = the HKCU Run value; never "Quit"
    assert "Start at sign-in" not in src and '"Quit Oarbank Node"' not in src
    assert 'PolicyValue("ShowStatusIcon")' in src and "ApplySetting(!background)" in src
    assert "SetStartup(false); } catch" in src and "Close();" in src
    assert "if(!test && (ShowPolicy() == false || (background && !StartupEnabled())))" in src
    for state in ("Not joined", "Waiting for approval", "Connected to ", "Offline", "Joining failed: "):
        assert state in src, state
    for arg in ('"--join"', '"--link"', '"--background"', '"--self-test"'):
        assert arg in src, arg
    assert '"runtime", "pythonw.exe"' in src and '"join", "join-window.py"' in src and '" --launcher "' in src
    assert '"oarbank-node.exe"' in src and "--link" in src
    assert 'RunName = "OarbankNode"' in src and '" --background"' in src
    assert "FastRefresh = 5000, SlowRefresh = 30000" in src
    assert '"Local\\\\OarbankNodeTray-"' in src                      # one tray per session
    assert 'GetEnvironmentVariable("GITHUB_ACTIONS") != "true"' in src  # the self-test is for CI runners only


def test_the_tray_app_tells_what_became_of_container_support_as_oarbank_node_does():
    src = TRAY.read_text(encoding="utf-8")
    rs = SUPPORT_RS.read_text(encoding="utf-8")
    key = re.search(r'pub const KEY: &str = r"([^"]+)";', rs).group(1)
    assert f'ContainerSupportKey = @"{key}"' in src and "RegistryView.Registry64" in src
    assert 'GetValue("State")' in src and 'GetValue("Detail")' in src
    # the same line for each state in both (container_support.rs `line`, NodeTray.cs `ContainerLine`)
    for state in ("scheduled", "installing", "waiting", "restart"):
        rust = re.search(rf'"{state}" => "([^"]+)"\.into\(\)', rs).group(1)
        assert f'case "{state}": return "{rust}";' in src, state
    assert '"Container support failed: " + detail' in src and 'format!("Container support failed: {detail}")' in rs
    assert 'ContainerLine("restart", "") == "Restart Windows to finish container support"' in src


def test_the_tray_app_is_csharp_5_for_the_net_framework_compiler():
    # %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe compiles C# 5 only
    code = re.sub(r'@"(?:[^"]|"")*"', '""', TRAY.read_text(encoding="utf-8"))       # verbatim strings, then the others
    code = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', code)
    code = re.sub(r"//[^\n]*", "", code)
    assert "?." not in code and '$"' not in code and "nameof(" not in code and "out var " not in code
    # no expression-bodied members (C# 6): a member declaration never continues with =>
    members = [l for l in code.splitlines() if re.match(r"\s*(static|internal|public|private|protected|override)\b", l)]
    assert not [l for l in members if re.search(r"\)\s*=>", l.split("{")[0])], members
    manifest = ET.parse(WINDOWS / "node-tray.manifest").getroot()
    level = next(e for e in manifest.iter() if e.tag.endswith("requestedExecutionLevel"))
    assert level.get("level") == "asInvoker"                          # the tray never asks for administrator rights


@pytest.mark.skipif(not shutil.which("mcs"), reason="Mono's compiler is not installed (Windows CI compiles the tray app)")
def test_the_tray_app_compiles(tmp_path):
    r = subprocess.run(["mcs", "-langversion:5", "-target:winexe", "-r:System.Windows.Forms.dll", "-r:System.Drawing.dll",
                        "-r:System.Web.Extensions.dll", "-r:System.ServiceProcess.dll", f"-out:{tmp_path / 'tray.exe'}", str(TRAY)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


# MARK: the build and CI

def test_the_package_build_makes_the_node_parts():
    text = PACKAGE.read_text(encoding="utf-8")
    assert 'Copy-Item "$Bin\\oarbank-launcher.exe" "$Bin\\oarbank-node.exe"' in text
    assert text.index('Sign "$Bin\\oarbank-launcher.exe"') < text.index('"$Bin\\oarbank-node.exe"')   # the copy is signed
    compile_line = next(l for l in text.splitlines() if l.startswith("& $Csc "))
    for part in ("/target:winexe", "/codepage:65001", "/reference:System.Web.Extensions.dll", "/reference:System.ServiceProcess.dll",
                 '"/win32icon:$Repo\\deploy\\icons\\oarbank.ico"', '"/win32manifest:$Repo\\deploy\\windows\\node-tray.manifest"',
                 '"/out:$Tray"', '"$Repo\\deploy\\windows\\NodeTray.cs"'):
        assert part in compile_line, part
    assert '$Tray = "$Bin\\Oarbank Node.exe"' in text and "Sign $Tray" in text
    assert "join-window.py" in text and "join-window.html" in text and "is missing: the MSI ships the join window" in text
    wix = next(l for l in text.splitlines() if l.startswith("wix build"))
    assert "-ext WixToolset.Util.wixext -ext WixToolset.UI.wixext" in wix and '-d "JoinDir=$JoinDir"' in wix
    # the Group Policy template ships zipped, and its hash is in the sums file
    assert '$Admx = "$Out\\oarbank-agent-$Version-windows-admx.zip"' in text
    sums = text[text.index("$Sums ="):text.index("SHA256SUMS-agent-")]
    assert "$Admx" in sums


def test_the_msi_workflow_adds_the_ui_extension_and_watches_the_join_window():
    text = WORKFLOW.read_text(encoding="utf-8")
    util = re.search(r"wix extension add --global WixToolset\.Util\.wixext/([0-9.]+)", text).group(1)
    assert f"wix extension add --global WixToolset.UI.wixext/{util}" in text
    assert "      - deploy/node/**\n" in text and "      - deploy/windows/**\n" in text


def test_the_msi_ci_checks_the_waiting_node_and_its_parts():
    text = CI.read_text(encoding="utf-8")
    assert re.search(r'Msi "/i" \$First "install-unjoined\.log"\s*\n', text)                 # no properties at all
    assert '$d.state -eq "unjoined"' in text and r"Oarbank\status\node.json" in text
    assert '$d.error.code -eq "E_TCP"' in text and "COORDINATOR=https://127.0.0.1:9" in text
    assert '[Environment]::GetEnvironmentVariable("Path", "Machine")' in text and "status --json" in text
    assert r"HKEY_CLASSES_ROOT\oarbank" in text and '"--self-test"' in text
    assert text.count("CheckNodePartsGone") >= 3 and text.count("CheckNodeParts ") >= 3


def test_the_msi_ci_installs_with_containers_and_checks_the_task():
    text = CI.read_text(encoding="utf-8")
    rs = SUPPORT_RS.read_text(encoding="utf-8")
    assert 'Msi "/i" $First "install-containers.log" @("CONTAINERS=1", "COORDINATOR=https://127.0.0.1:9")' in text
    assert "if ($p.ExitCode -notin 0, 3010)" in text                     # never 1603
    task = re.search(r'pub const TASK: &str = "([^"]+)";', rs).group(1)
    key = re.search(r'pub const KEY: &str = r"([^"]+)";', rs).group(1)
    assert f'$SupportTask = "{task}"' in text and f'$SupportKey = "HKLM:\\{key}"' in text
    assert "ScheduleContainers" in text and "containers install" in text
    assert "started by itself once the installer had ended" in text
    assert "the task deleted itself after its outcome" in text and "the task stays for the next start of Windows" in text
    assert "no WSL installation began inside the agent's" in text
    assert 'Msi "/x" $First "uninstall-containers.log"' in text
    assert "the uninstall removes the container support task and its record" in text
