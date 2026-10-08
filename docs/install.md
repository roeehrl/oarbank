# Installing Oarbank

One coordinator, any number of nodes. The coordinator can also be a node. Nodes reach the coordinator over any
network you choose (a LAN, Tailscale, ZeroTier, a VPN); the coordinator never reaches into nodes.

## What you need

- Nodes: macOS 15 or later on Apple silicon or Intel (one package each), Linux with systemd on x86-64 or arm64 ([Linux nodes](#linux-nodes)), or Windows 10 1809 or later on x64
  or arm64 ([Windows nodes](#windows-nodes)).
- For the coordinator: macOS 15 or later on Apple silicon (Intel can run a source checkout), Linux with systemd
  on x86-64 or arm64, or a Windows machine (Windows 10 1809, Windows 11 or Windows Server 2019 or later;
  [Windows coordinator](#windows-coordinator)) that stays on, reachable by the nodes on one address
  (port 7443/tcp).
- Whatever the installed modules' doctors check (their READMEs say: a JDK, Homebrew tools, Docker through the
  agent's own Colima, and so on). On a Mac with Apple silicon, krunkit gives GPU containers Vulkan on the Mac's GPU,
  in a second agent-owned Colima VM: `brew tap slp/krun && brew trust slp/krun && brew install krunkit` (Homebrew asks
  you to trust a third-party tap).

## The packages

| File | Built by | What |
|---|---|---|
| `oarbank-coordinator-<v>-macos-arm64.pkg` | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-macos.sh` | Software-only installer: `/Applications/Oarbank Coordinator.app`, bundled Python/core, CLI, uv and browser setup wizard |
| `oarbank-coordinator-<v>-linux-amd64.deb`, `.rpm` (also `linux-arm64`) | `scripts/build-coordinator.sh`, then `scripts/package-coordinator-linux.sh` | Software-only installer: `/opt/oarbank/coordinator`, application menu entry and `oarbank-setup` |
| `oarbank-coordinator-<v>-windows-x64.msi` (also `windows-arm64`) | `scripts\build-coordinator.ps1`, then `scripts\package-coordinator-windows.ps1` | Software-only installer: `C:\Program Files\Oarbank\Coordinator\package`, Start menu setup launcher |
| `oarbank-coordinator-<v>-<os>-<arch>.tar.gz` | `scripts/build-coordinator.sh` or `scripts\build-coordinator.ps1` | Advanced relocatable build for signed coordinator moves and manual setup; includes its service installer and guided setup |
| `oarbank-agent-<v>-macos-arm64.pkg`, `oarbank-agent-<v>-macos-x86_64.pkg` | `scripts/package-macos.sh [<v>] [arm64\|x86_64]` | the node, for Macs with Apple silicon or Intel Macs (each refuses the other): `/Library/Oarbank/bin/{oarbank-agent, oarbank-launcher, oarbank-uninstall}` and the node runtime `runtime/` (CPython 3.12 with the module SDK, and uv: what modules get from the host) |
| `oarbank-agent-<v>-darwin-arm64`, `oarbank-agent-<v>-darwin-amd64` | `scripts/package-macos.sh` | the same agent binary, for the coordinator's update channel (`oarbank agent upload`) |

Signing the packages is the owner's: `OARBANK_CODESIGN_IDENTITY` (Developer ID Application) for the binaries,
`OARBANK_INSTALLER_IDENTITY` (Developer ID Installer) for the pkg, `OARBANK_NOTARY_PROFILE` (a `notarytool` keychain
profile) to notarize and staple it. Without them the binaries are signed ad hoc, which is fine on your own Macs. The
x86_64 package builds on Apple silicon with the `x86_64-apple-darwin` Rust target (`rustup target add`) and Rosetta 2
(`softwareupdate --install-rosetta`), which runs its interpreter and agent for the build's checks.

## 1. The coordinator

Download the native coordinator installer for your computer from the
[2.6.0 release](https://github.com/roeehrl/oarbank/releases/tag/v2.6.0) and verify it against its `SHA256SUMS` file.
On macOS, double-click the `.pkg` and follow Installer, then open **Oarbank Coordinator** in Applications.
On Linux, install the `.deb` or `.rpm` with your package manager, then launch **Oarbank Coordinator** from the
application menu or run `oarbank-setup`. On Windows, run the `.msi`, then open **Oarbank Coordinator** from Start
and accept the administrator prompt. Package installation needs administrator privileges; on macOS/Linux,
launch setup as the ordinary user who will own the coordinator.

The package installs software only. The first-run browser wizard lets you select a LAN or Tailscale IP address
assigned to this computer, enter an administrator name and password (at least 12 characters), and confirm the
password. Choose an address reachable by your nodes, not loopback for a multi-computer fleet. Submitting starts
the services and creates your account. Add the displayed secret to an authenticator app and verify its current
six-digit code. The wizard creates and pins two owner signing keys; copy the backup key to secure offline storage.
It then opens the console. No cloud account or separately installed Python or uv is required.

On macOS the services are LaunchAgents `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console`, running
while that user is logged in. State is in `~/Library/Application Support/Oarbank/coordinator`, and owner keys in
`~/Library/Application Support/Oarbank/keys`. Linux uses systemd user services with state in
`${XDG_DATA_HOME:-~/.local/share}/oarbank/coordinator` and keys in `${XDG_CONFIG_HOME:-~/.config}/oarbank/keys`.
Enable lingering with `sudo loginctl enable-linger <user>` if the Linux coordinator should run from boot without
that user's login. Windows uses system services and protected `C:\ProgramData\Oarbank\coordinator` state.

If you close the wizard before verification, open it again and resume with the same address, account name and
password. Existing accounts and keys are preserved. Reopening a completed setup opens the console. After an upgrade or relocation, or when services are stopped,
it refreshes the service definitions before opening the console. An older manually configured coordinator opens its existing console; stop/start or migrate
its services explicitly rather than treating it as a new fleet.

**Local Network privacy (macOS 15 and later).** The coordinator announces itself on the local network for
`oarbank-agent discover`. LaunchAgents are not exempt from Local Network privacy, so a macOS that applies it to them
asks once whether the program may use the local network (macOS 27.0.1 did not ask for these standalone programs; a
coordinator run from a checkout on python.org's or Homebrew's Python, which runs as an app, makes macOS ask about
"Python"). If macOS refuses, or holds the request because no one has answered yet, the coordinator's log says so: allow
it in System Settings, Privacy & Security, Local Network, or enroll nodes with join codes, which name the coordinator's
address and need no discovery
([architecture.md](design/architecture.md#network-and-access)).

**Command line.** The bundled CLI is at
`/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin/oarbank` on macOS,
`/opt/oarbank/coordinator/bin/oarbank` on Linux, and
`C:\Program Files\Oarbank\Coordinator\current\bin\oarbank.cmd` on Windows. The CLI uses the coordinator's
local owner channel; Windows requires an elevated prompt. Outside that local account, sign in with
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

Make a join code on the coordinator (one per node; it names the coordinator's addresses, pins its CA and approves
the node when it is used):
```bash
oarbank join-code --label <node>
```
The label names the node: it appears under that name, and keeps it whatever host name its agent reports (a renamed
machine, `OARBANK_NODE_NAME`). Without `--label`, the node takes the name its agent reports and follows it.

**With the pkg (also MDM).** Put the code where the installer looks, then install:
```bash
sudo mkdir -p /Library/Oarbank/etc
echo 'OB1-…' | sudo tee /Library/Oarbank/etc/join-code >/dev/null
sudo installer -pkg oarbank-agent-<v>-macos-arm64.pkg -target /     # an Intel Mac: oarbank-agent-<v>-macos-x86_64.pkg
```
The postinstall sets the node up for the console user (a LaunchAgent) and deletes the code file. Add an empty
`/Library/Oarbank/etc/system` file first to install it as a system service run by a dedicated `_oarbank` account
instead (it starts at boot, before anyone logs in). A system install also puts the session helper
`dev.codonic.oarbank.agent.session` in `/Library/LaunchAgents`: launchd starts it in every GUI login (and the install
in the sessions open now), and it tells host protection what the `_oarbank` account may not read about that person's
processes and the app in front, over a socket in `/Library/Application Support/Oarbank/run`. A `coordinator` file
with a URL works instead of a code; the owner then approves the node on the Fleet page.

**By hand.** Install the pkg without those files, then:
```bash
/Library/Oarbank/bin/oarbank-launcher setup --join-code 'OB1-…'      # or: sudo … setup --scope system --join-code …
```

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

- A node: `/Library/Oarbank/bin/oarbank-uninstall` unloads the service; `--purge` also deletes the node's home (its
  key, certificate, caches and logs); run it with `sudo` to remove the programs too. Retire the node on the Fleet page.
- The coordinator: `launchctl bootout gui/$(id -u)/dev.codonic.oarbank.oarbankd` (and `.console`), then remove the
  two plists from `~/Library/LaunchAgents`. Its state stays in `~/Library/Application Support/Oarbank/coordinator`
  until you delete it. Then delete `/Applications/Oarbank Coordinator.app`; repeat the service cleanup for each user
  who configured it. Keep the `Oarbank/keys` directory unless deliberately destroying your owner keys.
- Linux coordinator: remove `oarbank-coordinator` through your package manager. Its removal hook stops and removes
  user services that reference its installed payload, including registered custom XDG unit locations. It preserves
  data, keys, logs and lingering. If cleanup fails, removal stops so you can correct the service problem and retry.
- Windows coordinator: uninstall **Oarbank Coordinator** from Installed apps. It stops/removes both services and
  the firewall rule, while preserving the coordinator's state and signing keys.

## Linux nodes

Built for x86-64 and arm64; the sandbox needs Linux 6.2 or later (6.12 for every capability: see the SDK's
spec/sandbox/backends/linux.md), and `systemd`.

```bash
scripts/package-linux.sh                     # on a Linux machine with nFPM: dist/*.deb, *.rpm and a tarball
sudo install -d /etc/oarbank && echo 'OB1-…' | sudo tee /etc/oarbank/join-code >/dev/null
sudo apt install ./oarbank-agent_<v>_amd64.deb        # or: sudo dnf install ./oarbank-agent-<v>.x86_64.rpm
```
The postinstall creates the `oarbank` account, sets up `/var/lib/oarbank/agent`, installs the systemd unit
`dev.codonic.oarbank.agent.service` (with a delegated cgroup, so jobs get cgroup leaves) and deletes the code file. It
also enables, for every person's user manager, the session helper `dev.codonic.oarbank.agent.session.service`
(`/etc/systemd/user`), which tells host protection what the `oarbank` account may not read about that person's
processes and display; it starts at each person's next login (or at once with `systemctl --user start
dev.codonic.oarbank.agent.session.service`).
Without a code: `sudo oarbank-launcher setup --scope system --join-code 'OB1-…'`. Containers use rootless Podman when
it is installed (the `oarbank` account needs subordinate ids: `sudo usermod --add-subuids 100000-165535
--add-subgids 100000-165535 oarbank`), else Docker Engine.

GPU jobs need the GPU's device files: add the `oarbank` account to the groups that own them (`sudo usermod -aG
render,video oarbank`, then restart the agent). `oarbank-agent gpu-apis` (run as `oarbank`: `sudo -u oarbank
oarbank-agent gpu-apis`) prints the GPU APIs the node provides and why any is missing; the node's doctor reports the
same list, and work is placed by it ([gpu-placement.md](design/gpu-placement.md)).

For a Linux coordinator, install the native package and run its wizard as described above. The coordinator's
module sandbox has the same kernel requirements. The bundled interpreter also needs a compatible glibc;
use a distribution supported by the release build and verify its runtime before production deployment.

## Windows nodes

Windows 10 1809 or later, x64 or arm64.

```powershell
scripts\package-windows.ps1 [-Arch arm64]    # on Windows with Rust, uv and WiX 5: dist\oarbank-agent-<v>-windows-<arch>.msi
msiexec /i oarbank-agent-<v>-windows-arm64.msi /qn JOINCODEFILE=C:\path\join-code.txt
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
`JOINCODE=` or `COORDINATOR=` work instead of a file. Module
processes run in AppContainers.

Containers run in a WSL containers session the agent creates and owns (a VM of its own, [design/windows-containers.md](design/windows-containers.md)):
they need Windows 10 2004 or later, WSL 2.9.3 or later and the Virtual Machine Platform, on a machine with hardware virtualization (nested
virtualization in a VM). `CONTAINERS=1` on the `msiexec` command line installs both unattended (restart Windows if the
Virtual Machine Platform was new); `oarbank-agent containers install` does the same later. `oarbank-agent containers
doctor` prints the runtime's state and each missing piece with its fix, and `--probe` runs a container through it.
The node offers the `containers` pool only while its session is ready.

## Windows coordinator

Windows 10 1809 or later, Windows 11 or Windows Server 2019 or later, x64 or arm64. The coordinator runs as two
Windows services; its Python is x64 on both architectures (on arm64 under Windows' own emulation), because one of its
libraries publishes no Windows on Arm builds.

Install `oarbank-coordinator-<v>-windows-<arch>.msi`, then open **Oarbank Coordinator** from Start. The launcher
asks for elevation and opens the same browser setup wizard. Its native package installs at
`C:\Program Files\Oarbank\Coordinator\package`; service setup points `current` at that installed payload.
The services `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console` each run under their own virtual
account, start automatically about two minutes after boot, and are restarted after a crash.
The coordinator's state is in `C:\ProgramData\Oarbank\coordinator`, which only SYSTEM, administrators and the two
services can open; its logs are in its `logs` folder. An inbound firewall rule lets nodes reach the agent port (7443)
of the oarbankd service; the console and the admin API answer on loopback only. `-DryRun` prints every step.

After wizard setup, in an elevated prompt on the coordinator (it talks to oarbankd over a named pipe only administrators and the
services can open, so it needs no token):
```powershell
& "C:\Program Files\Oarbank\Coordinator\current\bin\oarbank.cmd" join-code --label <node>
```
A module's own CLI (`oarbank cli <module>`) is limited to the admin API through the elevated helper the agent's MSI
installs; install the agent on the coordinator too to use one. Module processes run in AppContainers, as on a Windows
node.

**Updating:** install the new native package, then reopen Oarbank Coordinator to refresh and restart its services.
For an archive installation, run the helper with the new build; earlier archive builds remain beside it. **Moving the coordinator to a Windows machine:** prepare the move with that machine's URL
(`oarbank coordinator prepare --to https://<host>:7443`) and run the installer there with the printed pairing code:
`install-oarbankd.ps1 -Build … -AgentBind <host> -Pair <code> -From <old url> -FromCa <pin>` (an agent on a Windows node
cannot install services, so a move never installs one there by itself). **Removing:** uninstall the native package through Installed apps. For an archive installation,
`install-oarbankd.ps1 -Uninstall` removes the services, the firewall rule and the programs; the state stays in
`C:\ProgramData\Oarbank\coordinator` until you delete it.
