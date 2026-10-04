# Installing Oarbank

One coordinator, any number of nodes. The coordinator can also be a node. Nodes reach the coordinator over any
network you choose (a LAN, Tailscale, ZeroTier, a VPN); the coordinator never reaches into nodes.

## What you need

- Nodes: macOS 15 or later on Apple silicon (Intel Macs run the universal agent when it is built with the x86_64
  target), Linux with systemd on x86-64 or arm64 ([Linux nodes](#linux-nodes)), or Windows 10 1809 or later on x64
  or arm64 ([Windows nodes](#windows-nodes)).
- For the coordinator: a Mac or a Linux machine that stays on, reachable by the nodes on one address (port 7443/tcp).
- Whatever the installed modules' doctors check (their READMEs say: a JDK, Homebrew tools, Docker through the
  agent's own Colima, and so on). On a Mac with Apple silicon, krunkit gives GPU containers Vulkan on the Mac's GPU,
  in a second agent-owned Colima VM: `brew tap slp/krun && brew trust slp/krun && brew install krunkit` (Homebrew asks
  you to trust a third-party tap).

## The packages

| File | Built by | What |
|---|---|---|
| `oarbank-coordinator-<v>-darwin-arm64.tar.gz` | `scripts/build-coordinator.sh` | the coordinator: a relocatable Python with the compiled core, `bin/oarbankd`, `bin/oarbank`, `bin/oarbank-console` |
| `oarbank-agent-<v>-macos.pkg` | `scripts/package-macos.sh` | the node: `/Library/Oarbank/bin/{oarbank-agent, oarbank-launcher, oarbank-uninstall}` and the node runtime `runtime/` (CPython 3.12 with the module SDK, and uv: what modules get from the host) |
| `oarbank-agent-<v>-darwin-<arch>` | `scripts/package-macos.sh` | the same agent binary, for the coordinator's update channel (`oarbank agent upload`) |

Signing the packages is the owner's: `OARBANK_CODESIGN_IDENTITY` (Developer ID Application) for the binaries,
`OARBANK_INSTALLER_IDENTITY` (Developer ID Installer) for the pkg, `OARBANK_NOTARY_PROFILE` (a `notarytool` keychain
profile) to notarize and staple it. Without them the binaries are signed ad hoc, which is fine on your own Macs.

## 1. The coordinator

```bash
deploy/oarbankd/install-oarbankd.sh --build oarbank-coordinator-<v>-darwin-arm64.tar.gz --agent-bind <address>
```
`<address>` is where nodes reach this machine (its LAN, VPN or tailnet address). The script unpacks the build under
`~/Library/Application Support/Oarbank/coordinator-app/`, points `current` at it, and loads two LaunchAgents:
`dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console`. The coordinator's state is in
`~/Library/Application Support/Oarbank/coordinator` (owner-only). `--dry-run` prints every step instead.

Then, on the coordinator:
```bash
B=~/Library/Application\ Support/Oarbank/coordinator-app/current/bin
"$B/oarbank" account create <you> --role admin --password    # asks for a password; prints the TOTP secret for your authenticator
open http://127.0.0.1:7400
```
The CLI on the coordinator's own account talks to oarbankd over its local socket and needs no token. Elsewhere, sign
in once with `oarbank console login` or use a personal access token (`oarbank token create`).

**Signing.** It is on (docs/release-signing.md). Make the owner keys and pin them before the first module:
`oarbank release keygen`, a backup key with `--key <path>`, then `oarbank owner set --key … --backup-key …`.

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
sudo installer -pkg oarbank-agent-<v>-macos.pkg -target /
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
  until you delete it.

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

A Linux coordinator works too: `scripts/build-coordinator.sh` on Linux, then `deploy/oarbankd/install-oarbankd.sh
--build … --agent-bind …` writes systemd user units (run `loginctl enable-linger` once so they start at boot).

## Windows nodes

Windows 10 1809 or later, x64 or arm64.

```powershell
scripts\package-windows.ps1                  # on Windows with Rust, uv and WiX 5: dist\oarbank-agent-<v>-windows-<arch>.msi
msiexec /i oarbank-agent-<v>-windows-arm64.msi /qn JOINCODEFILE=C:\path\join-code.txt
```
The script builds for the machine it runs on: an x64 MSI on x64, an arm64 MSI on arm64. On arm64 the build also needs
clang (the `ring` crate does not build with MSVC alone there): Visual Studio's "C++ Clang Compiler for Windows"
component (`Microsoft.VisualStudio.Component.VC.Llvm.Clang`) or a standalone LLVM. The script finds either through
`scripts\windows-clang.ps1`, which adds the Visual Studio component when run with `-Install`.

The MSI installs `C:\Program Files\Oarbank`, the elevated helper service (`OarbankHelper`, which lets module sandboxes
reach only their job's egress proxy, keeps a session helper running in each person's session that tells host
protection that session's foreground window, last input and command lines, and lists the sessions for host protection,
which the agent's account may not read), and the agent as the service
`dev.codonic.oarbank.agent` run by its virtual account, with its home in `C:\ProgramData\Oarbank\agent`. Both services start automatically about two minutes after
boot (Automatic, Delayed Start), and the service manager restarts either one that crashes or stops with an error.
`JOINCODE=` or `COORDINATOR=` work instead of a file. Module
processes run in AppContainers; containers are not available on Windows yet.
