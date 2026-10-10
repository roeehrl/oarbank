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
- Whatever the installed modules' doctors check (their READMEs say: a JDK, Homebrew tools, Docker through the
  agent's own Colima, and so on). On a Mac with Apple silicon, krunkit gives GPU containers Vulkan on the Mac's GPU,
  in a second agent-owned Colima VM: `brew tap slp/krun && brew trust slp/krun && brew install krunkit` (Homebrew asks
  you to trust a third-party tap).

## The packages

| File | Built by | What |
|---|---|---|
| `oarbank-coordinator-<v>-macos-arm64.pkg` | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-macos.sh` | Software-only installer: `/Applications/Oarbank Coordinator.app`, bundled Python/core, CLI, uv and browser setup wizard; `oarbank` and `oarbank-setup` on the PATH (`/usr/local/bin`) |
| `oarbank-coordinator-<v>-linux-amd64.deb`, `.rpm` (also `linux-arm64`) | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-linux.sh` | Software-only installer: `/opt/oarbank/coordinator`, application menu entry, and `oarbank` and `oarbank-setup` in `/usr/bin` |
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
Windows requests elevation when setting up or recovering stopped services; opening a configured, running web app needs none. Package installation needs administrator privileges; on macOS/Linux,
launch setup as the ordinary user who will own the coordinator.

The package installs software only. The first-run browser wizard lets you select a LAN or Tailscale IP address
assigned to this computer, enter an administrator name and password (at least 12 characters), and confirm the
password. Choose an address reachable by your nodes, not loopback for a multi-computer fleet. Submitting starts
the services and creates your account. Scan the displayed QR code with an authenticator app and verify its current
six-digit code. The wizard creates and pins two owner signing keys; copy the backup key to secure offline storage.
It then opens the console. No cloud account or separately installed Python or uv is required.

On macOS the services are LaunchAgents `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console`, running
while that user is logged in. State is in `~/Library/Application Support/Oarbank/coordinator`, and owner keys in
`~/Library/Application Support/Oarbank/keys`. Linux uses systemd user services with state in
`${XDG_DATA_HOME:-~/.local/share}/oarbank/coordinator` and keys in `${XDG_CONFIG_HOME:-~/.config}/oarbank/keys`.
Enable lingering with `sudo loginctl enable-linger <user>` if the Linux coordinator should run from boot without
that user's login. Windows uses system services and protected `C:\ProgramData\Oarbank\coordinator` state.

In **Preferences**, enable **Start automatically at sign-in** if you want the companion to launch quietly for your account.
**Quit** closes the companion and leaves coordinator services running.

If you close the wizard before verification, choose **Open web app** again. The saved address and account are shown;
enter the original password to continue. Existing accounts and keys are preserved. Reopening completed setup opens the console login.
If services need restarting after an upgrade or relocation, explicitly run the bundled `oarbank-setup` helper
(on the PATH: `/usr/local/bin/oarbank-setup` on macOS, `/usr/bin/oarbank-setup` on Linux; on Windows,
`C:\Program Files\Oarbank\Coordinator\package\oarbank-setup.ps1`).
The helper refreshes an existing wizard-managed installation without creating a new fleet. An older manually configured
coordinator keeps its existing console; stop/start or migrate its services explicitly.

**Local Network privacy (macOS 15 and later).** The coordinator announces itself on the local network for
`oarbank-agent discover`. LaunchAgents are not exempt from Local Network privacy, so a macOS that applies it to them
asks once whether the program may use the local network (macOS 27.0.1 did not ask for these standalone programs; a
coordinator run from a checkout on python.org's or Homebrew's Python, which runs as an app, makes macOS ask about
"Python"). If macOS refuses, or holds the request because no one has answered yet, the coordinator's log says so: allow
it in System Settings, Privacy & Security, Local Network, or enroll nodes with join codes, which name the coordinator's
address and need no discovery
([architecture.md](design/architecture.md#network-and-access)).

**Command line.** The packages put the coordinator's CLI on the PATH as `oarbank` (open a new terminal after
installing). On macOS `/usr/local/bin/oarbank` links to
`/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin/oarbank` (an existing `oarbank` there that is
not a link is left alone); on Linux `/usr/bin/oarbank` links to `/opt/oarbank/coordinator/bin/oarbank`. On Windows the
MSI adds `C:\Program Files\Oarbank\Coordinator\package\cli` to the system PATH: its `oarbank.cmd` runs
`C:\Program Files\Oarbank\Coordinator\current\bin\oarbank.cmd`, the build the services use (before setup, the
package's own). `oarbank` and the full path behave the same: the CLI uses the coordinator's local owner channel for the
account that runs it; Windows requires an elevated prompt. Outside that local account, sign in with
`oarbank console login` or use a personal access token (`oarbank token create`).
The wizard performs the initial owner signing setup; see [release-signing.md](release-signing.md) for ongoing
release signing and key recovery.

**Advanced archive setup.** For signed moves or scripted deployment, unpack a coordinator archive and run its
bundled helper: `bash install-oarbankd.sh --build <archive> --agent-bind <address>` (Windows: elevated
`install-oarbankd.ps1 -Build <archive> -AgentBind <address>`). This creates services without the wizard's account,
authenticator or owner-key ceremony; perform those explicitly with the CLI. `--dry-run` / `-DryRun` shows the plan.
For a developer checkout, use `--checkout`; it requires the development toolchain and is not the native install path.

**The console from another device.** By default it answers only on 127.0.0.1. To reach it remotely, put it behind
something that terminates TLS for a name you control (`tailscale serve`, your own reverse proxy) and add that name
to the setting `console_hosts`. Passkeys need such a name; TOTP works everywhere.

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
| Keys | `JoinCode`, `Coordinator`, `Name`, `Containers` (Windows), `AllowUserJoin` (false hides Join and Leave in the app), `ManagedByOrganizationName` | the same names (REG_SZ, REG_DWORD) | the same names (JSON) |

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

The node enrolls with its own key (it never leaves the node), gets a client certificate, installs its release,
runs each module's doctor and golden jobs, and then takes work. Host protection starts in `moderate` with no
rules; add rules on the node's Protection page. `oarbank-agent discover` lists coordinators announcing themselves
on the local network, a hint for the URL only.

**Local Network privacy (macOS 15 and later).** The personal scope's LaunchAgent is not exempt: a macOS that applies
Local Network privacy to it asks once, naming `oarbank-launcher` and saying why, before the agent first reaches a
coordinator at a LAN address or browses for one. A tailnet or VPN address is not "local network". The system scope (a
launchd daemon) is exempt. If macOS refuses, `oarbank-agent discover` says so; allow the launcher in System Settings,
Privacy & Security, Local Network. On Macs no one is at, macOS 15.5 and later accept an administrator's exemption for
whole networks (`sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array
"<cidr>"`, then restart), and the system scope avoids the question.

## Updating

- **Nodes** update themselves: `oarbank agent upload <binary>`, `oarbank agent sign <build>`, then
  `canary --node <node>` and `promote`. The launcher keeps the previous version and rolls back a build that does not
  confirm itself within 10 minutes. Installing a newer pkg replaces the launcher and restarts the service.
- **The coordinator**: run the installer again with the new build; `current` moves and the services restart (agents
  reconnect by themselves), and modules' Python environments made by the previous build are rebuilt on the new
  build's interpreter when it starts. Earlier builds stay beside it for going back.
- **Moving the coordinator** to another node: `oarbank coordinator prepare --to <node>`, then `move` (and `sign` with
  the owner key). The node's agent installs the standby from a signed coordinator build; agents verify the move and
  follow it after its time lock (docs/design/coordinator-move.md).

## Removing

- A node: `sudo oarbank-node leave` forgets its coordinator (the node's key, certificate, caches and logs go); retire
  the node on the Fleet page. To remove the programs too: `sudo /Library/Oarbank/bin/oarbank-uninstall --purge` on
  macOS (also **Oarbank Node.app**), your package manager on Linux (`apt remove` keeps `/var/lib/oarbank`, `apt purge`
  deletes it), Installed apps on Windows.
- The coordinator: `launchctl bootout gui/$(id -u)/dev.codonic.oarbank.oarbankd` (and `.console`), then remove the
  two plists from `~/Library/LaunchAgents`. Its state stays in `~/Library/Application Support/Oarbank/coordinator`
  until you delete it. Then delete `/Applications/Oarbank Coordinator.app` and the package's `oarbank` and
  `oarbank-setup` links, which point into it:
  `sudo find /usr/local/bin -lname '/Applications/Oarbank Coordinator.app/*' -delete`. Repeat the service cleanup
  for each user who configured it. Keep the `Oarbank/keys` directory unless deliberately destroying your owner keys.
- Linux coordinator: remove `oarbank-coordinator` through your package manager (this also removes `/usr/bin/oarbank`
  and `/usr/bin/oarbank-setup`). Its removal hook stops and removes
  user services that reference its installed payload, including registered custom XDG unit locations. It preserves
  data, keys, logs and lingering. If cleanup fails, removal stops so you can correct the service problem and retry.
- Windows coordinator: uninstall **Oarbank Coordinator** from Installed apps. It stops/removes both services and
  the firewall rule and takes `oarbank` off the PATH, while preserving the coordinator's state and signing keys.

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
