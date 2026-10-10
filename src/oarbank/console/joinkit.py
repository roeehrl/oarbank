"""What the console shows once a join code is made (docs/design/node-enrollment.md, "Console" and "Channels").

For every channel the design names, the console fills the new code in: download links for this version's node
packages (the asset names scripts/package-macos.sh, package-linux.sh and package-windows.ps1 produce, on the GitHub
release `v<version>`), the attended steps, the command lines, and for MDM a macOS configuration profile, the Windows
Intune command and detection rule, the Group Policy key, `/etc/oarbank/policy.json` and an Ansible task.

Everything here is computed from the operation's result for one response and never stored: the code exists in the
browser that asked for it and nowhere else (the coordinator keeps only its secret's hash). The profile is offered as a
`data:` link for the same reason, so there is no download route that would have to hold the code.
"""
import base64
import plistlib
import uuid

from .. import __version__

REPO = "https://github.com/roeehrl/oarbank"
INSTALL_SH = f"{REPO}/releases/latest/download/oarbank-install.sh"
INSTALL_PS1 = f"{REPO}/releases/latest/download/oarbank-install.ps1"
POLICY_DOMAIN = "dev.codonic.oarbank.agent"          # managed preferences (macOS) and the policy's name everywhere
LABEL_PREFIX = "dev.codonic.oarbank"                 # every launchd job the node package installs starts with this
GPO_KEY = r"HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent"
WINDOWS_JOINED = r"%ProgramData%\Oarbank\status\joined"
LINUX_JOINED = "/var/lib/oarbank/status/joined"
LINUX_POLICY = "/etc/oarbank/policy.json"
MOBILECONFIG_TYPE = "application/x-apple-aspen-config"


def assets(version: str = __version__) -> dict:
    """{key: (file name, download URL)} of the node packages for `version`."""
    names = {
        "mac_arm64": f"oarbank-agent-{version}-macos-arm64.pkg",
        "mac_x86_64": f"oarbank-agent-{version}-macos-x86_64.pkg",
        "deb_amd64": f"oarbank-agent_{version}_amd64.deb",
        "deb_arm64": f"oarbank-agent_{version}_arm64.deb",
        "rpm_x86_64": f"oarbank-agent-{version}-1.x86_64.rpm",       # nFPM's rpm name: <name>-<version>-<release>.<arch>
        "rpm_aarch64": f"oarbank-agent-{version}-1.aarch64.rpm",
        "msi_x64": f"oarbank-agent-{version}-windows-x64.msi",
        "msi_arm64": f"oarbank-agent-{version}-windows-arm64.msi",
    }
    return {k: (n, f"{REPO}/releases/download/v{version}/{n}") for k, n in names.items()}


def sq(s: str) -> str:
    """`s` as one single-quoted POSIX shell word (a code has no quotes, but a snippet must never depend on that)."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def mobileconfig(code: str, *, code_id: str, name: str = "", coordinator: str = "") -> bytes:
    """A macOS configuration profile that joins a Mac: the code (and a name, for a single machine) as forced managed
    preferences for the node's policy domain, which the node's policy job reads whether the profile arrives before or
    after the package; and a managed login items rule for the node's launchd jobs, so macOS does not ask the person to
    allow them in the background (System Settings, Login Items). Fresh PayloadUUIDs on each call: two codes' profiles
    never replace each other."""
    settings = {"JoinCode": code}
    if name:
        settings["Name"] = name
    ident = f"{POLICY_DOMAIN}.join.{code_id}"
    prefs = {"PayloadType": "com.apple.ManagedClient.preferences", "PayloadVersion": 1,
             "PayloadIdentifier": f"{ident}.preferences", "PayloadUUID": str(uuid.uuid4()).upper(),
             "PayloadDisplayName": "Oarbank Node join code",
             "PayloadContent": {POLICY_DOMAIN: {"Forced": [{"mcx_preference_settings": settings}]}}}
    items = {"PayloadType": "com.apple.servicemanagement", "PayloadVersion": 1,
             "PayloadIdentifier": f"{ident}.login-items", "PayloadUUID": str(uuid.uuid4()).upper(),
             "PayloadDisplayName": "Oarbank Node background items",
             "Rules": [{"RuleType": "LabelPrefix", "RuleValue": LABEL_PREFIX,
                        "Comment": "The Oarbank Node agent and its helpers"}]}
    profile = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": ident,
               "PayloadUUID": str(uuid.uuid4()).upper(), "PayloadScope": "System",
               "PayloadDisplayName": f"Oarbank Node: join {name or coordinator or 'this coordinator'}",
               "PayloadDescription": "Joins this Mac to an Oarbank coordinator with a join code, and allows the Oarbank "
                                     "Node background items. Remove the profile once the Mac has joined if you like: "
                                     "the node stays joined.",
               "PayloadOrganization": "Oarbank", "PayloadRemovalDisallowed": False,
               "PayloadContent": [prefs, items]}
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def kit(result: dict, version: str = __version__) -> dict:
    """The result page's model for the operation result of nodes.join_code (code, id, expires_at, label, uses, approve,
    system, containers): links, steps and every snippet with the code filled in."""
    code, label = result["code"], result.get("label") or ""
    multi = int(result.get("uses") or 1) > 1
    a = assets(version)
    q = sq(code)
    # a multi-use code's label names the code, not each machine (core.enroll): never give every machine one name
    name = "" if multi else label
    from ..coordinator import joincodes
    try:
        coordinator = joincodes.decode(code)["urls"][0]
    except (joincodes.JoinError, IndexError):
        coordinator = ""
    env = f"OARBANK_JOIN_CODE={q}" + (" OARBANK_CONTAINERS=1" if result.get("containers") else "")
    msi_props = " CONTAINERS=1" if result.get("containers") else ""
    snippets = {
        "mac_install": f"sudo installer -pkg {a['mac_arm64'][0]} -target /\nprintf '%s' {q} | sudo oarbank-node join --code-stdin",
        "mac_oneliner": f"curl -fsSL {INSTALL_SH} | sudo {env} sh",
        "deb": f"sudo {env} apt install ./{a['deb_amd64'][0]}",
        "rpm": f"sudo {env} dnf install ./{a['rpm_x86_64'][0]}",
        "linux_join": f"printf '%s' {q} | sudo oarbank-node join --code-stdin",
        "linux_oneliner": f"curl -fsSL {INSTALL_SH} | sudo {env} sh",
        "msi": f"msiexec /i {a['msi_x64'][0]} /qn JOINCODE={code}{msi_props}",
        "msi_file": f"msiexec /i {a['msi_x64'][0]} /qn JOINCODEFILE=C:\\ProgramData\\Oarbank\\join-code.txt{msi_props}",
        "win_oneliner": f"irm {INSTALL_PS1} | iex",
        "intune_install": f"msiexec /i {a['msi_x64'][0]} /qn JOINCODE={code}{msi_props}",
        "intune_detect": WINDOWS_JOINED,
        "gpo": f"{GPO_KEY}\n  JoinCode (REG_SZ) = {code}" + ("\n  Containers (REG_DWORD) = 1" if result.get("containers") else ""),
        "policy_json": "{\"JoinCode\": \"" + code + "\"}",
        "ansible": (
            "- name: Join this machine to Oarbank\n"
            "  ansible.builtin.shell: >-\n"
            "    printf '%s' \"{{ oarbank_join_code }}\" |\n"
            "    oarbank-node join --code-stdin --no-input --wait 600\n"
            "  args:\n"
            f"    creates: {LINUX_JOINED}\n"
            "  become: true\n"
            "  no_log: true\n"
            "  vars:\n"
            "    # better: keep the code in Ansible Vault\n"
            f"    oarbank_join_code: \"{code}\""),
    }
    profile = mobileconfig(code, code_id=result.get("id") or "code", name=name, coordinator=coordinator)
    return {"code": code, "deep_link": "oarbank://join?code=" + code, "multi": multi, "name": name,
            "coordinator": coordinator, "version": version, "assets": a, "snippets": snippets,
            "mobileconfig_href": f"data:{MOBILECONFIG_TYPE};base64," + base64.b64encode(profile).decode(),
            "paths": {"windows_joined": WINDOWS_JOINED, "linux_joined": LINUX_JOINED, "linux_policy": LINUX_POLICY,
                      "gpo": GPO_KEY, "domain": POLICY_DOMAIN}}
