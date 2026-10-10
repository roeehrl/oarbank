# Installing Oarbank

One coordinator, any number of nodes. The coordinator can also be a node. Nodes reach the coordinator over any
network you choose (a LAN, Tailscale, ZeroTier, a VPN); the coordinator never reaches into nodes.

## What you need

- Nodes: macOS 15 or later on Apple silicon or Intel (one package each), Linux with systemd and glibc 2.39 or newer on x86-64 or arm64 ([Linux nodes](#linux-nodes)), or Windows 10 1809 or later on x64
  or arm64 ([Windows nodes](#windows-nodes)).
- For the coordinator: macOS 15 or later on Apple silicon (Intel can run a source checkout), Linux with systemd
  and glibc 2.39 or newer on x86-64 or arm64, or a Windows machine (x64: Windows 10 1809 / Windows Server 2019 or later; arm64: Windows 11;
  [Windows coordinator](#windows-coordinator)) that stays on, reachable by the nodes on one address
  (port 7443/tcp).
- Whatever the installed modules' doctors check (their READMEs say: a JDK, Homebrew tools, containers through the
  agent's own Colima, and so on). A Mac that runs containers needs `brew install colima docker`, and Rosetta 2 on
  Apple silicon for linux/amd64 images ([Containers on Mac nodes](#containers-on-mac-nodes)). On Apple silicon,
  krunkit gives GPU containers Vulkan on the Mac's GPU, in a second agent-owned Colima VM: `brew tap slp/krun && brew
  trust slp/krun && brew install krunkit` (Homebrew asks you to trust a third-party tap).

## The packages

| File | Built by | What |
|---|---|---|
| `oarbank-coordinator-<v>-macos-arm64.pkg` | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-macos.sh` | `/Applications/Oarbank Coordinator.app`, bundled Python/core, CLI, uv and browser setup wizard; `oarbank` and `oarbank-setup` on the PATH (`/usr/local/bin`). A first install starts no service (the wizard does); an upgrade restarts the system service, or moves a 2.8 per-user coordinator to it |
| `oarbank-coordinator-<v>-linux-amd64.deb`, `.rpm` (also `linux-arm64`) | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-linux.sh` | `/opt/oarbank/coordinator`, application menu entry, and `oarbank` and `oarbank-setup` in `/usr/bin`; as on macOS, an upgrade restarts or migrates an existing coordinator |
| `oarbank-coordinator-<v>-windows-x64.msi` (also `windows-arm64`) | `scripts\build-coordinator.ps1`, then `scripts\package-coordinator-windows.ps1` | Software-only installer: `C:\Program Files\Oarbank\Coordinator\package`, Start menu tray application, `oarbank` on the system PATH |
| `oarbank-coordinator-<v>-<os>-<arch>.tar.gz` | `scripts/build-coordinator.sh` or `scripts\build-coordinator.ps1` | Advanced relocatable build for signed coordinator moves and manual setup; includes its service installer and guided setup |
| `oarbank-agent-<v>-macos-arm64.pkg`, `oarbank-agent-<v>-macos-x86_64.pkg` | `scripts/package-macos.sh [<v>] [arm64\|x86_64]` | the node, for Macs with Apple silicon or Intel Macs (each refuses the other): `/Library/Oarbank/bin/{oarbank-agent, oarbank-launcher, oarbank-uninstall}`, the node runtime `runtime/` (CPython 3.12 with the module SDK, and uv: what modules get from the host), the join window, `/Applications/Oarbank Node.app` (menu bar) and `/usr/local/bin/oarbank-node` |
| `oarbank-agent_<v>_amd64.deb`, `oarbank-agent-<v>-1.x86_64.rpm` (also arm64) | `scripts/package-linux.sh` | the node for Linux: `/usr/lib/oarbank`, `/usr/bin/oarbank-node`, the **Oarbank Node** desktop entry |
| `oarbank-agent-<v>-windows-x64.msi` (also arm64), `oarbank-agent-<v>-windows-admx.zip` | `scripts\package-windows.ps1` | the node for Windows: `C:\Program Files\Oarbank`, `oarbank-node.exe` on PATH, the **Oarbank Node** tray app; the Group Policy template |
| `oarbank-install.sh`, `oarbank-install.ps1` | `scripts/package-install-scripts.sh` | one-line installers: download this release's node package for the computer, verify and install it, and join with a code they are given |
| `oarbank-agent-<v>-darwin-arm64`, `oarbank-agent-<v>-darwin-amd64` | `scripts/package-macos.sh` | the same agent binary, for the coordinator's update channel (`oarbank agent upload`) |

Signing the packages is the owner's: `OARBANK_CODESIGN_IDENTITY` (Developer ID Application) for the binaries,
`OARBANK_INSTALLER_IDENTITY` (Developer ID Installer) for the pkg, `OARBANK_NOTARY_PROFILE` (a `notarytool` keychain
profile) to notarize and staple it. Without them the binaries are signed ad hoc, which is fine on your own Macs. The
x86_64 package builds on Apple silicon with the `x86_64-apple-darwin` Rust target (`rustup target add`) and Rosetta 2
(`softwareupdate --install-rosetta`), which runs its interpreter and agent for the build's checks.

## 1. The coordinator

Download the native coordinator installer for your computer from the
[2.8.0 release](https://github.com/roeehrl/oarbank/releases/tag/v2.8.0) and verify it against its `SHA256SUMS` file.
On macOS, double-click the `.pkg` and follow Installer, then open **Oarbank Coordinator** in Applications.
On Linux, install the `.deb` or `.rpm` with your package manager, then launch **Oarbank Coordinator** from the
application menu or run `oarbank-coordinator`. On Windows, run the `.msi`, then open **Oarbank Coordinator** from Start.
Click the menu bar/tray icon and choose **Open web app**; a desktop without tray support shows the same controls in a window.
Setting up, or recovering stopped services, asks for an administrator once (macOS's administrator prompt, polkit on Linux,
elevation on Windows); opening a configured, running web app needs none. Package installation needs administrator
privileges; on macOS/Linux, launch setup as the ordinary user who will own the coordinator.

The package installs the software (and upgrades an existing coordinator). The first-run browser wizard lets you select a LAN or Tailscale IP address
assigned to this computer, enter an administrator name and password (at least 12 characters), and confirm the
password. Choose an address reachable by your nodes, not loopback for a multi-computer fleet. Submitting starts
the services (the administrator prompt) and creates your account. Scan the displayed QR code with an authenticator app and verify its current
six-digit code. The wizard creates and pins two owner signing keys; copy the backup key to secure offline storage.
It then opens the console. No cloud account or separately installed Python or uv is required.

The coordinator is a system service on every OS ([design/coordinator-system-service.md](design/coordinator-system-service.md)):
it starts at boot, before anyone logs in, and keeps running when you log out. On macOS the services are the launchd
daemons `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console` in `/Library/LaunchDaemons`, run by the
hidden account `_oarbankd`, with state in `/Library/Application Support/Oarbank/coordinator` (only `_oarbankd` may
enter it). Linux uses the systemd system units of the same names, run by the `oarbankd` account, with state in
`/var/lib/oarbank/coordinator`; no lingering is needed. Windows uses two services under virtual accounts and protected
`C:\ProgramData\Oarbank\coordinator` state. Your owner signing keys stay yours: `~/Library/Application
Support/Oarbank/keys` on macOS, `${XDG_CONFIG_HOME:-~/.config}/oarbank/keys` on Linux; the service never reads them.
The person who sets it up joins the coordinator's owners' group (`_oarbankadmin` on macOS, `oarbank-admin` on Linux),
which is what lets their `oarbank` reach the coordinator without a token; add another owner with
`sudo dseditgroup -o edit -a <user> -t user _oarbankadmin` (macOS) or `sudo usermod -aG oarbank-admin <user>` (Linux,
effective at that person's next login).

Choose an agent address that exists before anyone logs in: a LAN address, or a tailnet address from a Tailscale that
runs at boot (on macOS the `tailscaled` variant, such as Homebrew's `tailscale` service; the App Store and Standalone
apps connect only after a login). Until the address exists the coordinator retries every 10 seconds.

With FileVault on, a Mac that lost power waits at the disk unlock screen until someone types a password: nothing on
the disk runs before that, the coordinator included. Restarts that unlock the disk for you (macOS updates that do,
`sudo fdesetup authrestart`) bring the coordinator back with nobody logged in.

On macOS the coordinator's menu bar item has one setting, **Show Oarbank Coordinator in the menu bar** (Settings…):
on, the item is shown and the app opens when you log in (it is on after the app's first launch); **Hide from Menu
Bar** (⌘Q) turns it off and quits the app. The coordinator's services keep running either way. Settings… says how the
coordinator runs ("Runs as a system service — starts with the Mac, before anyone logs in, as _oarbankd"). Open the app from
Applications to get its window back. When the node package is installed on the same Mac, this menu also shows **This
Mac's Node**, and Oarbank Node keeps out of the menu bar ([Menu bar and tray](design/node-enrollment.md#menu-bar-and-tray)).
On Windows and Linux, the companion's **Preferences** has **Start automatically at sign-in**; **Quit** closes the
companion and leaves coordinator services running.

If you close the wizard before verification, choose **Open web app** again. The saved address and account are shown;
enter the original password to continue. Existing accounts and keys are preserved. Reopening completed setup opens the console login.
Upgrading the package restarts the services on the new build by itself (on macOS and Linux the package writes them
again from the record of the install). If the services stopped, run the bundled `oarbank-setup` helper
(on the PATH: `/usr/local/bin/oarbank-setup` on macOS, `/usr/bin/oarbank-setup` on Linux; on Windows,
`C:\Program Files\Oarbank\Coordinator\package\oarbank-setup.ps1`); it asks for an administrator and starts them
again without creating a new fleet.

**Local Network privacy (macOS 15 and later).** The coordinator announces itself on the local network for
`oarbank-agent discover`. macOS lets launchd daemons use the local network without asking (Apple's TN3179), so the
coordinator's daemons never wait for an answer. A coordinator run by hand from a checkout on python.org's or Homebrew's
Python, which runs as an app, makes macOS ask about "Python"; the coordinator's log says so when it is refused or not
answered yet ([architecture.md](design/architecture.md#network-and-access)).

**Command line.** The packages put the coordinator's CLI on the PATH as `oarbank` (open a new terminal after
installing). On macOS `/usr/local/bin/oarbank` links to
`/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin/oarbank` (an existing `oarbank` there that is
not a link is left alone); on Linux `/usr/bin/oarbank` links to `/opt/oarbank/coordinator/bin/oarbank`. On Windows the
MSI adds `C:\Program Files\Oarbank\Coordinator\package\cli` to the system PATH: its `oarbank.cmd` runs
`C:\Program Files\Oarbank\Coordinator\current\bin\oarbank.cmd`, the build the services use (before setup, the
package's own). `oarbank` and the full path behave the same: the CLI uses the coordinator's local admin channel when
the account that runs it is one of the coordinator's owners (the owners' group on macOS and Linux; an elevated prompt
on Windows). Otherwise, sign in with `oarbank console login` or use a personal access token (`oarbank token create`).
The wizard performs the initial owner signing setup; see [release-signing.md](release-signing.md) for ongoing
release signing and key recovery.

**Advanced archive setup.** For signed moves or scripted deployment, unpack a coordinator archive and run its
bundled helper as root: `sudo bash install-oarbankd.sh --build <archive> --agent-bind <address>` (Windows: elevated
`install-oarbankd.ps1 -Build <archive> -AgentBind <address>`). This creates the system services without the wizard's
account, authenticator or owner-key ceremony; perform those explicitly with the CLI. `--dry-run` / `-DryRun` shows the
plan, `--refresh` writes the services again from the record of the install, `--uninstall` removes them and keeps the
home. A developer runs `oarbankd` from the checkout's virtualenv directly, with `OARBANKD_HOME` pointing at a scratch
home.

**The console from another device.** By default it answers only on 127.0.0.1. To reach it remotely, put it behind
something that terminates TLS for a name you control (`tailscale serve`, your own reverse proxy) and add that name
to **Settings → Access → Console host names** (`oarbank settings set console_hosts oarbank.example.ts.net`). Passkeys
need such a name; TOTP works everywhere.

## 2. Nodes

Every node package installs the node and asks nothing; joining is a separate step with one command,
`oarbank-node join`, that every way of installing ends in ([design/node-enrollment.md](design/node-enrollment.md)).
Nothing needs a hand-made file, and the join code is never typed on a command line.

**Make a join code** in the console (Fleet, **Add machine…**) or on the coordinator:
```bash
oarbank join-code --label <node>                       # one machine: single use, approved at once, 4 hours
oarbank join-code --uses 50 --ttl 604800              # many machines (MDM, images): each waits for approval
```
A code names the coordinator's addresses and pins its identity key and certificate authority, so the node checks it is
talking to your coordinator before it sends anything. The label names the node: it appears under that name and keeps
it whatever host name its agent reports. Without a label the node takes the name its agent reports (or `--name`).
`oarbank join-codes` lists outstanding codes and the machines that used them; `oarbank join-code revoke <id>` revokes
one (machines that already joined stay).

**Join, attended.** Open the package. On macOS **Oarbank Node** opens in the menu bar at its join window when Installer
finishes; on Windows the installer's join page takes the code (or leave it empty and use **Oarbank Node** from Start
afterwards); on a Linux desktop open **Oarbank Node** from your applications. Paste the code: the window shows the
coordinator it names and checks the network (DNS, the port, the coordinator's identity and certificate authority, the
clock) before joining, then follows the node until it is approved and connected. Joining as the system service (and
leaving it) asks for an administrator with the system's own prompt: on macOS "Oarbank Node wants to join this Mac to an
Oarbank fleet." with the app's icon (the package's root helper, `dev.codonic.oarbank.agent.helper`, runs the join once
an administrator has authenticated), on Linux "Oarbank Node wants to join this computer to an Oarbank fleet." (polkit),
on Windows the UAC prompt. A console's **Open in Oarbank Node**
link (`oarbank://join?code=…`) fills the code in and asks you to confirm the coordinator first.

**Oarbank Node in the menu bar or tray.** The node itself is a service that starts with the computer, before anyone
signs in; Oarbank Node only shows it. Its one setting, **Show Oarbank Node in the menu bar** (Windows: **in the
notification area**), is on after the app first opens: the icon is shown and the app opens at login. **Hide from Menu
Bar** (⌘Q; Windows: **Hide from notification area**) turns it off and quits the app: the node keeps running and stays
joined. To show it again, open Oarbank Node from Applications (its window has the setting) or from the Start menu. On a
Mac that also runs the coordinator, the coordinator's menu shows this Mac's node instead. If macOS says the node is
turned off in **Login Items → Allow in the Background**, the window offers **Open Login Items…**: switch **Oarbank
Node** back on there. Managed policy `ShowStatusIcon` (below) hides or pins the icon fleet-wide.

**Join from a terminal or SSH** (the code is read hidden, from standard input or from a file):
```bash
sudo installer -pkg oarbank-agent-<v>-macos-arm64.pkg -target /      # an Intel Mac: …-macos-x86_64.pkg
sudo oarbank-node join                                                # prompts for the code
printf '%s' 'OB2-…' | sudo oarbank-node join --code-stdin           # scripts
```
On macOS `sudo oarbank-node join` installs the system service, run by a dedicated `_oarbank` account (it starts at
boot, before anyone logs in); `oarbank-node join` without sudo, or `--scope personal`, sets the node up for the user
running it (a LaunchAgent). A system install also puts the session helper `dev.codonic.oarbank.agent.session` in
`/Library/LaunchAgents`: launchd starts it in every GUI login, and it tells host protection what the `_oarbank` account
may not read about that person's processes and the app in front, over a socket in
`/Library/Application Support/Oarbank/run`.

`oarbank-node join` checks the code and the network first and then waits for the node to join (`--no-wait` returns
once the code is staged; the service keeps retrying a coordinator it cannot reach until the code expires). Its exit
codes: 0 joined, 2 malformed code, 3 waiting for approval, 4 code expired, used or revoked, 5 the coordinator's
identity or certificate authority does not match the code, 6 network, 7 already joined to another coordinator, 8 needs
root or an administrator. `oarbank-node check` runs the checks without joining, `oarbank-node status [--follow]` shows
where the node is, `oarbank-node leave` forgets the coordinator, and `oarbank-node doctor` adds the container runtime.

**One line** (downloads the release's package for this computer, verifies its SHA-256 and installs it; with the
console's command, which fills in `OARBANK_JOIN_CODE`, it also joins; otherwise run `sudo oarbank-node join`
afterwards):
```bash
curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh | sudo sh
```
Piped into `sudo sh`, the script never asks for the code itself: sudo 1.9.14 and later runs it on a terminal of its own
and leaves yours echoing, so a pasted code would show. Join with `sudo oarbank-node join`, which hides it.
```powershell
irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1 | iex
```

**Without a code (device code).** `sudo oarbank-node join --coordinator https://<host>:7443` checks the coordinator,
prints its certificate authority's fingerprint to compare with the console's, and enrolls; the node then shows an
8-letter code (like `WDJB-MJHT`) that the owner enters on the Fleet page under **Approve a machine by its code**
(`oarbank node approve-code <CODE>`).

**MDM and configuration management.** Deploy the package unchanged and give it a code through managed policy; a node
that has not joined reads it and joins as the system service. Use a multi-use code: its machines wait for your
approval on the Fleet page unless you made it approve automatically.

| Where | macOS | Windows | Linux |
|---|---|---|---|
| Policy | a configuration profile for the domain `dev.codonic.oarbank.agent` (the console's **Add machine** offers one; it also pre-approves the background items) | `HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent` (Group Policy with the release's ADMX template, or Intune) | `/etc/oarbank/policy.json` |
| Keys | `JoinCode`, `Coordinator`, `Name`, `Containers` (Windows), `AllowUserJoin` (false hides Join and Leave in the app), `ManagedByOrganizationName`, `ShowStatusIcon` (false hides Oarbank Node's menu bar or tray icon on every account; true keeps it shown) | the same names (REG_SZ, REG_DWORD) | the same names (JSON; `ShowStatusIcon` has no effect: Linux has no node tray) |
| Settings (tighten-only) | a `Settings` dictionary in the same domain, keyed by the setting's key | values under the `Settings` subkey (the ADMX template's **Node settings (tighten-only)**: one policy per key) | a `"Settings"` object |

**Managed settings: stricter, never looser.** Managed policy may also tighten the coordinator's settings on a machine
(docs/design/settings.md, "Managed on this machine"). The agent applies a managed value only where it is stricter than
what the coordinator sends, so an organization can guarantee, say, that a laptop never runs jobs on battery, while the
owner still lowers caps from the console. The keys and which way each tightens:

| Key | Type | Stricter |
|---|---|---|
| `run_on_battery` | boolean | off |
| `screen_sharing_present`, `mem_in_use_bound`, `hard_limits` | boolean | on |
| `user_present_slots`, `max_slots`, `jobs`, `vm_cpus` | integer | lower |
| `cpu_cores`, `mem_gb`, `vm_mem_gb`, `disk_gb`, `staging_mbps` | number | lower |
| `os_reserve_gb`, `user_reserve_gb`, `user_idle_s` | number | higher |
| `enforce` | `soft` or `hard` | hard |

A looser value has no effect, a key not in the table is refused, and both show on the node's Settings tab ("Managed on
this machine: off (applies)") and on **Settings → Applied drift**; `oarbank-agent policy` prints what the machine's
policy sets. A macOS profile payload:
```xml
<dict>
  <key>PayloadType</key><string>dev.codonic.oarbank.agent</string>
  <key>ManagedByOrganizationName</key><string>Example Org</string>
  <key>Settings</key>
  <dict>
    <key>run_on_battery</key><false/>
    <key>jobs</key><integer>2</integer>
    <key>os_reserve_gb</key><real>8</real>
  </dict>
</dict>
```
Windows (Group Policy with the template, or directly): `reg add HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent\Settings /v
run_on_battery /t REG_DWORD /d 0` (a decimal number as REG_SZ: `/v os_reserve_gb /t REG_SZ /d 8.5`). Linux:
`{"Settings": {"run_on_battery": false, "jobs": 2}}` in `/etc/oarbank/policy.json`.

Linux packages also read the installing command's environment, and Windows MSIs take properties:
```bash
sudo OARBANK_JOIN_CODE='OB2-…' apt install ./oarbank-agent_<v>_amd64.deb      # also OARBANK_JOIN_CODE_FILE, OARBANK_NAME
```
```powershell
msiexec /i oarbank-agent-<v>-windows-x64.msi /qn JOINCODEFILE=C:\path\join-code.txt   # or JOINCODE=, COORDINATOR=, NAME=, CONTAINERS=1
```
For Intune, deploy the MSI as a Win32 app with that command and the detection rule "file
`%ProgramData%\Oarbank\status\joined` exists" (the agent writes it once the node has joined). With Ansible:
`printf '%s' "{{ oarbank_join_code }}" | oarbank-node join --code-stdin --no-input --wait 600` with `no_log: true`
and `creates: /var/lib/oarbank/status/joined`.

The node enrolls with its own key (it never leaves the node), gets a client certificate, installs its release (there is
none until a module is enabled: its card says "waiting for a release: install and enable a module"),
runs each module's doctor and golden jobs, and then takes work. Host protection starts in `moderate` with no
rules; add rules on the node's Protection page.

**How much work a node takes.** Each node card says why in one line, for example "2 slots while someone is using
this Mac (14 when idle) · 9.2 GB free for jobs (apps and the system use 46 GB)". A slot is a performance core, or
two efficiency cores (hardware threads never count). Jobs only get memory the machine has free now, less a margin
that keeps the memory guard from stepping in, and never more than the memory kept for the system and for the
person using it allows. The settings behind it are on the node's **Settings** tab, each with the value in effect and
where it comes from (this machine's default and why, the fleet's value, a group's, or the node's own); **Override** sets
a value for that node and **Reset to inherited** takes it back. Fleet-wide defaults are under **Settings → Node
defaults**, which shows the nodes a change reaches before it saves. From a terminal: `oarbank settings get --node
<node>`, `oarbank settings set <key> <value> [--node <node>]`, `oarbank settings reset <key> --node <node>`. On a Mac,
a Screen Sharing session counts as someone using it unless you turn off "Screen sharing counts as someone using it". `oarbank-agent discover` lists coordinators announcing themselves
on the local network, a hint for the URL only.

**Local Network privacy (macOS 15 and later).** The personal scope's LaunchAgent is not exempt: a macOS that applies
Local Network privacy to it asks once, naming `oarbank-launcher` and saying why, before the agent first reaches a
coordinator at a LAN address or browses for one. A tailnet or VPN address is not "local network". The system scope (a
launchd daemon) is exempt. If macOS refuses, `oarbank-agent discover` says so; allow the launcher in System Settings,
Privacy & Security, Local Network. On Macs no one is at, macOS 15.5 and later accept an administrator's exemption for
whole networks (`sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array
"<cidr>"`, then restart), and the system scope avoids the question.

## 3. Modules

The core runs no work of its own: a module brings it. From the console's **Modules** page or the CLI:

1. **Install** the module's bundle (`oarbank module install <bundle>.mfb`). Installing enables nothing.
2. **Approve its sandbox grants** if it asks for any: network hosts, host tools, containers
   (`oarbank module approve <name>@<version>`, previewed first).
3. **Enable** it (`oarbank module enable <name>@<version>`). Oarbank builds a release for every platform of the
   fleet: the module's bundle (or none, where it does not run) for the nodes of that platform.
4. **Sign each platform's release.** With release signing on (the default) nothing reaches a node until the owner
   signs its release offline, on the machine that holds the owner key:
   ```bash
   oarbank release list                          # each release's platform, status and contents; the waiting ones
   oarbank release sign <release> --promote      # once per platform it names
   ```
   Until then the Fleet and Modules pages show a banner naming every waiting release with its command, an alert
   (`release_awaiting_owner`) opens after five minutes, and the nodes stay "release needs your signature".
   [release-signing.md](release-signing.md) has the details.
5. **Finish what the module's checklist asks.** The module's page opens with **Getting this module running**
   (`oarbank module ready <name>` prints the same): every step with its status, why and the fix, among them the host
   tools it asks for (how many nodes have a version it accepts, and the install command for the others), the nodes
   each stage can run on and why the others cannot (a capability not reported, no container runtime, a platform the
   module does not support), certification, and the module's first operations.

### Host tools

A module that needs a program installed on the node (a JDK, a Python, a tool such as samtools) asks for it by tool id
and version (`jdk >=17`); each node finds its own installations and reports them, and the module's **Nodes** tab and
each node's **Host tools** section show what was found, what each module gets and the fix for the rest
([design/host-tools.md](design/host-tools.md)):

- **Install it on the node** with the command shown (`brew install openjdk@17`, `sudo apt install
  openjdk-17-jdk-headless`, `winget install EclipseAdoptium.Temurin.17.JDK`), then **Re-detect** (`oarbank tools detect
  <node>`; nodes also look again every hour and after every release).
- **Somewhere unusual?** Add a search path for the OS in Settings → Tools (`oarbank tools define jdk --search
  darwin=/opt/java/*/Contents/Home`), or set the path on one node (`oarbank settings set tool.jdk.path <path> --node <node>`, or the node page's Set path). A path
  the node did not find itself goes into its signed statement (`oarbank node sign <node>` in signing mode), and the node
  checks it before granting it.
- **As the node's owner**, list extra candidates in `tool-hints.json` in the agent's home (`{"jdk":
  ["/Users/me/jdks/zulu-17"]}`); the agent verifies them like anything it finds. Set `OARBANK_TOOLS_BUILTIN_SEARCH=0`
  in the agent's environment to search only the fleet's paths, your hints and paths set for the node.
- `oarbank tools` lists the definitions and what every node found; `oarbank tools --module <name>` prints a module's
  node-by-node matrix with the fixes.

## Updating

- **Nodes** update themselves: `oarbank agent upload <binary>`, `oarbank agent sign <build>`, then
  `canary --node <node>` and `promote`. The launcher keeps the previous version and rolls back a build that does not
  confirm itself within 10 minutes. Installing a newer pkg replaces the launcher and restarts the service.
- **The coordinator**: run the installer again with the new build; `current` moves and the services restart (agents
  reconnect by themselves), and modules' Python environments made by the previous build are rebuilt on the new
  build's interpreter when it starts. Earlier builds stay beside it for going back.
- **Moving the coordinator** to another node: `oarbank coordinator prepare --to <node>`, then `move` (and `sign` with
  the owner key). The node's agent fetches and verifies the signed coordinator build; since a node's agent is
  unprivileged and system services are root's, it then reports the one command to run on that machine
  (`sudo bash …/install-oarbankd.sh --build … --pair <code> --from … --from-ca …`), as on Windows. Agents verify the
  move and follow it after its time lock (docs/design/coordinator-move.md).

### Upgrading a coordinator from 2.8 or earlier

Before 2.9 the macOS and Linux coordinator ran as its owner's LaunchAgents or systemd user units, in that person's
home, with its keys in their login Keychain (macOS). Installing the 2.9 package moves it to the system service once
([design/coordinator-system-service.md](design/coordinator-system-service.md#migration-from-the-per-user-form)):

- **macOS, double-clicked while you are logged in:** the package exports the coordinator's keys from your Keychain
  into its file store (as you, in your session), stops the LaunchAgents, copies the home to
  `/Library/Application Support/Oarbank/coordinator` (an APFS clone: instant), starts the daemons, checks that they
  serve the same fleet, and removes the LaunchAgents. Nodes reconnect by themselves; running jobs continue.
- **When the package cannot reach your Keychain** (nobody logged in, an install over ssh or MDM): the coordinator keeps
  running as before, and Oarbank Coordinator shows **Move the coordinator to a system service…** (the console and
  `oarbank coordinator status` say it is waiting). Click it, or run `oarbank coordinator migrate` in Terminal; macOS
  asks for an administrator once.
- **Linux:** the package moves it at once (the keys were files already); lingering is no longer needed, and the
  package leaves it as you set it.
- Each step is recorded in `/Library/Application Support/Oarbank/coordinator-migration.json`
  (`/var/lib/oarbank/coordinator-migration.json` on Linux). If anything fails, the system services are removed and the
  per-user coordinator starts again on its untouched home. On success the old home stays, renamed
  `coordinator.migrated-<time>`, and the old Keychain items stay in your Keychain: delete them once you are content.

## Removing

- A node: `sudo oarbank-node leave` forgets its coordinator (the node's key, certificate, caches and logs go); retire
  the node on the Fleet page. To remove the programs too: `sudo /Library/Oarbank/bin/oarbank-uninstall --purge` on
  macOS (also **Oarbank Node.app**), your package manager on Linux (`apt remove` keeps `/var/lib/oarbank`, `apt purge`
  deletes it), Installed apps on Windows.
- The coordinator: `sudo bash "/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/install-oarbankd.sh"
  --uninstall --keep-programs` stops and removes the two daemons. Its state stays in
  `/Library/Application Support/Oarbank/coordinator` until you delete it (with `sudo`), as do the `_oarbankd` account
  and the `_oarbankadmin` group (`sudo dscl . -delete /Users/_oarbankd`, `/Groups/_oarbankd`, `/Groups/_oarbankadmin`).
  Then delete `/Applications/Oarbank Coordinator.app` and the package's `oarbank` and `oarbank-setup` links, which
  point into it: `sudo find /usr/local/bin -lname '/Applications/Oarbank Coordinator.app/*' -delete`. Keep your
  `~/Library/Application Support/Oarbank/keys` unless deliberately destroying your owner keys.
- Linux coordinator: remove `oarbank-coordinator` through your package manager (this also removes `/usr/bin/oarbank`
  and `/usr/bin/oarbank-setup`). Its removal hook stops and removes the system units, then any per-user units of an
  earlier release that still run its payload. It keeps `/var/lib/oarbank/coordinator`, the `oarbankd` account and the
  `oarbank-admin` group. If cleanup fails, removal stops so you can correct the service problem and retry.
- Windows coordinator: uninstall **Oarbank Coordinator** from Installed apps. It stops/removes both services and
  the firewall rule and takes `oarbank` off the PATH, while preserving the coordinator's state and signing keys.

## Containers on Mac nodes

Containers run in the agent's own Colima VM ([design/macos-containers.md](design/macos-containers.md)). Install the
tools once, as the administrator who owns Homebrew; the agent does the rest:
```bash
brew install colima docker                                         # Colima brings Lima; Docker Desktop is not needed
softwareupdate --install-rosetta --agree-to-license                # Apple silicon: linux/amd64 images run under Rosetta
brew tap slp/krun && brew trust slp/krun && brew install krunkit   # optional, Apple silicon: GPU containers (Vulkan)
```
The agent finds them in `/opt/homebrew/bin` or `/usr/local/bin` whatever its PATH (a tool in a person's home is not
one the `_oarbank` account may run). When a release first wants containers it creates and starts its own profile,
`oarbank`, in its home (`/Library/Application Support/Oarbank/agent/colima` for a system install, `~/.colima` for a
personal one), sized from the Mac's memory and mounting only its work and modules-data directories; the first start
downloads the VM image and takes a few minutes. Never start or delete the `oarbank` or `oarbank-gpu` profiles
yourself; your own Colima profiles are untouched.

The node reports the runtime in its facts (`oarbank node show <node>`: `containers: colima ready`, or `missing` with
each piece and its fix, or `failed` with the end of the Colima log) and offers the `containers` pool only while it is
ready. On the node, as the agent's account:
```bash
sudo -u _oarbank /Library/Oarbank/bin/oarbank-agent --home "/Library/Application Support/Oarbank/agent" containers doctor [--probe [--gpu]]
```
prints the same report (exit 3 while something is missing); `--probe` starts the runtime and runs real containers
through it. GPU containers (`containers.gpu = "virtio-gpu:venus"`) are offered only once the runtime is ready and
krunkit is installed; their VM starts with the first GPU job.

## Linux nodes

Built for x86-64 and arm64; the sandbox needs Linux 6.2 or later (6.12 for every capability: see the SDK's
spec/sandbox/backends/linux.md), and `systemd`. The published 2.8.0 Linux binaries require glibc 2.39 or newer; they are built and checked on Ubuntu 24.04.

```bash
scripts/package-linux.sh                     # on a Linux machine with nFPM: dist/*.deb, *.rpm and a tarball
sudo apt install ./oarbank-agent_<v>_amd64.deb        # or: sudo dnf install ./oarbank-agent-<v>-1.x86_64.rpm
sudo oarbank-node join
```
The package creates the `oarbank` account, sets up `/var/lib/oarbank/agent`, installs and starts the systemd unit
`dev.codonic.oarbank.agent.service` (with a delegated cgroup, so jobs get cgroup leaves), which waits for a code, and
adds **Oarbank Node** to the desktop's applications. It also enables, for every person's user manager, the session
helper `dev.codonic.oarbank.agent.session.service` (`/etc/systemd/user`), which tells host protection what the
`oarbank` account may not read about that person's processes and display; it starts at each person's next login (or
at once with `systemctl --user start dev.codonic.oarbank.agent.session.service`). The node's status is in
`/var/lib/oarbank/status/node.json`. Containers use rootless Podman when
it is installed (the `oarbank` account needs subordinate ids: `sudo usermod --add-subuids 100000-165535
--add-subgids 100000-165535 oarbank`), else Docker Engine.

GPU jobs need the GPU's device files: add the `oarbank` account to the groups that own them (`sudo usermod -aG
render,video oarbank`, then restart the agent). `oarbank-agent gpu-apis` (run as `oarbank`: `sudo -u oarbank
oarbank-agent gpu-apis`) prints the GPU APIs the node provides and why any is missing; the node's doctor reports the
same list, and work is placed by it ([gpu-placement.md](design/gpu-placement.md)).

For a Linux coordinator, install the native package and run its wizard as described above. The coordinator's
module sandbox has the same kernel requirements. The published coordinator payload, including its sandbox launcher, requires glibc 2.39 or newer and is built and checked on Ubuntu 24.04.

## Windows nodes

Windows 10 1809 or later, x64 or arm64.

```powershell
scripts\package-windows.ps1 [-Arch arm64]    # on Windows with Rust, uv and WiX 5: dist\oarbank-agent-<v>-windows-<arch>.msi
msiexec /i oarbank-agent-<v>-windows-arm64.msi          # attended: the join page takes the code
```
The script builds for `-Arch` (`x64` or `arm64`), by default the machine's own architecture, which it asks Windows for
(`IsWow64Process2`, in `scripts\windows-arch.ps1`): an x64 PowerShell on Windows on Arm still builds the arm64 MSI. The
binaries are built for that target whatever the Rust toolchain's own host is (`rustup target add` the target's standard
library), and what it packages is checked first (`scripts\check-package.py`: no links, no path of the build machine, no
native file for another architecture, and the node runtime runs from another directory). For arm64 the build also needs clang (the `ring` crate does not build
with MSVC alone there): Visual Studio's "C++ Clang Compiler for Windows" component
(`Microsoft.VisualStudio.Component.VC.Llvm.Clang`) or a standalone LLVM. The script finds either through
`scripts\windows-clang.ps1`, which adds the Visual Studio component when run with `-Install`.

The MSI installs `C:\Program Files\Oarbank`, the elevated helper service (`OarbankHelper`, which lets module sandboxes
reach only their job's egress proxy, keeps a session helper running in each person's session that tells host
protection that session's foreground window, last input and command lines, and lists the sessions for host protection,
which the agent's account may not read), and the agent as the service
`dev.codonic.oarbank.agent` run by its virtual account, with its home in `C:\ProgramData\Oarbank\agent`. Both services start automatically about two minutes after
boot (Automatic, Delayed Start), and the service manager restarts either one that crashes or stops with an error.
It adds `C:\Program Files\Oarbank` to the system PATH (`oarbank-node`), the **Oarbank Node** tray app and the
`oarbank://` link handler. Silent installs take `JOINCODEFILE=`, `JOINCODE=`, `COORDINATOR=`, `NAME=` and `NOLAUNCH=1`
([2. Nodes](#2-nodes)); `JOINCODE` is never written to the installer's log (unless the Windows Installer `Debug` policy
is 7, which logs every command-line value). The node's status is in `C:\ProgramData\Oarbank\status\node.json`.
Module processes run in AppContainers.

Containers run in a WSL containers session the agent creates and owns (a VM of its own, [design/windows-containers.md](design/windows-containers.md)):
they need Windows 10 2004 or later, WSL 2.9.3 or later and the Virtual Machine Platform, on a machine with hardware virtualization (nested
virtualization in a VM). `CONTAINERS=1` on the `msiexec` command line (or the join page's "Run container jobs" box, or
a join code made for container jobs) installs both unattended right after the installer has finished: the MSI
registers the one-shot task `OarbankContainerSupport`, which runs as LocalSystem once the installation has ended (the
WSL package is itself an installer package and never runs inside another one), records the outcome and deletes
itself. The MSI exits 0 either way; Oarbank Node and `oarbank-node status` then show "Restart Windows to finish
container support" or "Container support failed: …" until it is done (the record is
`HKLM\SOFTWARE\Codonic\Oarbank\ContainerSupport`). `oarbank-agent containers install` (administrator) does the same
later. `oarbank-agent containers
doctor` prints the runtime's state and each missing piece with its fix, and `--probe` runs a container through it.
The node offers the `containers` pool only while its session is ready.

## Windows coordinator

On x64: Windows 10 1809 or later, Windows 11, or Windows Server 2019 or later. On arm64: Windows 11. The coordinator
runs as two Windows services; its bundled Python is x64 on both architectures, because one dependency has no
Windows on Arm wheels. [Windows 11 provides x64 emulation; Windows 10 on Arm does not](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation).
This coordinator requirement does not change the native ARM64 agent's Windows 10 floor.

Install `oarbank-coordinator-<v>-windows-<arch>.msi`, then open **Oarbank Coordinator** from Start.
Click its tray icon and choose **Open web app**. The tray and Preferences run without elevation;
unfinished setup requests elevation before opening the browser wizard. Its native package installs at
`C:\Program Files\Oarbank\Coordinator\package`; service setup points `current` at that installed payload.
The services `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console` each run under their own virtual
account, start automatically about two minutes after boot, and are restarted after a crash.
The coordinator's state is in `C:\ProgramData\Oarbank\coordinator`, which only SYSTEM, administrators and the two
services can open; its logs are in its `logs` folder. An inbound firewall rule lets nodes reach the agent port (7443)
of the oarbankd service; the console and the admin API answer on loopback only. `-DryRun` prints every step.

After wizard setup, in an elevated prompt on the coordinator (it talks to oarbankd over a named pipe only administrators and the
services can open, so it needs no token). The MSI puts `oarbank` on the system PATH, so a prompt opened after installing finds it:
```powershell
oarbank join-code --label <node>
```
A module's own CLI (`oarbank cli <module>`) is limited to the admin API through the elevated helper the agent's MSI
installs; install the agent on the coordinator too to use one. Module processes run in AppContainers, as on a Windows
node.

**Updating:** install the new native package; the MSI restarts existing coordinator services with the updated payload.
For explicit service recovery, run `C:\Program Files\Oarbank\Coordinator\package\oarbank-setup.ps1`; it requests elevation.
For an archive installation, run the helper with the new build; earlier archive builds remain beside it. **Moving the coordinator to a Windows machine:** prepare the move with that machine's URL
(`oarbank coordinator prepare --to https://<host>:7443`) and run the installer there with the printed pairing code:
`install-oarbankd.ps1 -Build … -AgentBind <host> -Pair <code> -From <old url> -FromCa <pin>` (an agent on a Windows node
cannot install services, so a move never installs one there by itself). **Removing:** uninstall the native package through Installed apps. For an archive installation,
`install-oarbankd.ps1 -Uninstall` removes the services, the firewall rule and the programs; the state stays in
`C:\ProgramData\Oarbank\coordinator` until you delete it.
