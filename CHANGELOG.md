# Changelog

What changed in each Oarbank release, for the people who run a fleet. The module SDK has its own changelog in
[roeehrl/oarbank-sdk](https://github.com/roeehrl/oarbank-sdk/blob/main/CHANGELOG.md); the documentation is at
[docs.codonic.dev/oarbank](https://docs.codonic.dev/oarbank).

## 2.9.0 (unreleased)

Module SDK: **oarbank-sdk 1.6.0**. Read [What changes when you upgrade](#what-changes-when-you-upgrade) before you
install it: the macOS and Linux coordinator moves to a system service, settings move to a new model by themselves, and
a few old commands are gone.

### What's new

**One settings model for the whole fleet.** Every owner setting now lives in one place and resolves the same way on the
console, the CLI and the agent: a value for the fleet, a group of nodes or one node, the most specific one winning.

- **Groups and labels.** Make node groups by OS, architecture, label, host name, battery or RAM, or by listing members;
  give nodes labels; rank groups when a node is in several. The console's Groups page previews the members live.
- **Locks.** A fleet or group value can be locked so no narrower scope (and no campaign) overrides it.
- **Bulk changes and canaries.** Change many nodes at once, or try a value on one group first and **Promote to fleet**
  when it holds (`oarbank settings promote`).
- **Campaign overrides.** A campaign can override the settings its module marks as overridable, while it runs and only
  for its own jobs; safety settings can only be tightened.
- **Settings as code.** `oarbank settings export` and `oarbank settings import` (with `--dry-run`) round-trip a scope's
  settings as one reviewable file.
- **Reports.** `oarbank settings shadowed` lists values that change nothing; `oarbank settings drift` lists nodes not
  yet running their latest settings, and machines whose managed policy tightens a setting.
- **Managed settings (MDM).** A machine's management profile can set the `Settings` dictionary (macOS
  `dev.codonic.oarbank.agent`, the Windows ADMX template, Linux `/etc/oarbank/policy.json`). It can only make a
  setting stricter, never looser, and the console shows which machines it binds on.
- **Secrets and protection on the same chain.** Protection's mode (lockable) and rules (combined across every scope)
  are settings like the others. The ntfy token is a write-only secret.
- **Explained everywhere.** Every value shows where it comes from, its default with the reason, and **Reset**.
  `oarbank settings get | set | reset | explain | overrides | schema` cover all of it from the terminal.

**Host tools by version.** A module asks for a tool by name and version (`{ id = "jdk", version = ">=17" }`) and each
node detects what it has: a JDK from its `release` file without running it, other tools through a version command in
the sandbox. Admins define more tools and search paths, pin a path per node or per module, and **Re-detect** after
installing one. A job that needs a tool a node lacks waits with `TOOL_NOT_FOUND`, `TOOL_VERSION_UNMET` or
`TOOL_REFUSED` and the exact install command for that OS. `oarbank tools` shows the fleet's matrix.

**Module settings.** Modules declare their own settings with a type, default, limits, help text and scope (fleet or per
node). They appear on the module's Settings tab and in each node's Settings, are validated on every write, and a module
can mark one required: its work waits with `SETTINGS_NOT_SET` until you set it.

**The coordinator runs as a system service on macOS and Linux.** It starts at boot, with nobody logged in, as its own
account (`_oarbankd` on macOS, `oarbankd` on Linux), with its home in `/Library/Application Support/Oarbank/coordinator`
or `/var/lib/oarbank/coordinator`. People in the owners' group (`_oarbankadmin`, `oarbank-admin`) use the `oarbank` CLI
without a token. Owner signing keys stay with the person. A coordinator move installs its standby the same way.

**Menu bar and tray.** Oarbank Node and Oarbank Coordinator have their own icons, one item per Mac, and no Quit that
sounds like stopping the service. System Settings, Login Items, Allow in the Background lists the background jobs
under the app they belong to. The managed policy `ShowStatusIcon` hides or pins the icon on every account.

**Nodes stop their jobs cleanly.** When the agent is stopped or restarted (an upgrade, a reboot, `launchctl`,
`systemctl`, the Windows service manager) it asks every job to stop as a release does (checkpointing first), releases
each attempt as `AGENT_STOPPED` (requeued, charged to no one), and only then exits. The service definitions give it
60 seconds. An agent that is killed leaves no job processes behind: a watchdog and the next agent end them.

**Protection.**

- A pause rule now keeps its work off the node while it is active (`paused` and `paused_by` in the node's capacity,
  `PROTECTION_ACTIVE` in Explain), so a released job is not granted straight back.
- A process whose path or arguments cannot be read matches a rule only from its second sighting, and a process that
  execs is identified by its new program.

**Getting a module running.** Each module gets a readiness checklist ("Getting this module running": release,
signature, host tools per OS, nodes per stage and why the others can't, certification, first operations). Releases
waiting for the owner's signature show a banner, an alert and the exact `oarbank release sign … --promote` command;
the release list shows platform, status and contents.

**Stages that need no certification.** A bootstrap stage, or a stage that compares nothing and needs no capability or
pool, now runs before the module is certified on a node. A failed doctor check named after a capability withdraws only
that capability, so one missing dependency no longer blocks every stage. Explain names each reason with its nodes by
platform, and doctor failures keep their detail.

**Containers on macOS.** Mac nodes report their container runtime (absent, starting, ready, missing with the fix,
failed), start their own Colima VM (Apple Virtualization with Rosetta for amd64 images, sized from capacity) as soon as
a release needs containers, and offer container work only while it is ready. Container GPU APIs are reported only when
the runtime and krunkit are both there.

**Also in this release.**

- macOS: Oarbank Node asks for administrator rights as itself, through a small root helper, instead of a script prompt.
- macOS: module code can load third-party native wheels (numpy, pysam) under the Developer ID signature.
- Windows: container support installs after the MSI finishes, through a one-time SYSTEM task, so a WSL update can no
  longer break the install.
- The coordinator's `oarbank` CLI is on the PATH on macOS, Linux and Windows.
- The piped one-line installer never prompts for a join code.
- Honest capacity: "GB free for jobs" counts what the machine's own apps use, cores are physical cores, and the
  Windows memory guard reads the paging files.
- The console shows progress for every wait, lays out on any width, and versions its scripts so a browser never runs
  an old one after an upgrade.
- `oarbank-agent policy` shows a managed join code as `(set)`.
- New reason codes: `AGENT_STOPPED`, `CAMPAIGN_SETTING_HOLDS`, `NO_RELEASE`, `RELEASE_UNSIGNED`, `SETTINGS_NOT_SET`,
  `TOOL_NOT_FOUND`, `TOOL_REFUSED`, `TOOL_VERSION_UNMET` (`TOOL_UNAVAILABLE` is gone).

### What changes when you upgrade

- **The macOS and Linux coordinator moves to a system service, once.** On macOS, double-clicking the 2.9.0 pkg while
  you are logged in exports the coordinator's keys from your Keychain, copies its home (an APFS clone), starts the
  daemons, checks that they serve the same fleet and removes the old LaunchAgents. If the package cannot reach your
  Keychain (nobody logged in, ssh, MDM), the coordinator keeps running as before and Oarbank Coordinator offers **Move
  the coordinator to a system service…** (or run `oarbank coordinator migrate`). On Linux the package moves it at once.
  Every step is recorded in `coordinator-migration.json`; any failure removes the system services and restarts the old
  coordinator on its untouched home. The old home stays, renamed `coordinator.migrated-<time>`, until you delete it.
- **Settings move by themselves.** The first 2.9 coordinator converts the old per-node policies, caps, module settings
  and protection sections into the new store, keeping only real choices (values that differ from what a node would
  inherit). Anything it cannot keep is named in the `settings_migrated` event.
- **Removed, with their replacements:**
  - `oarbank node policy` and `oarbank node limits`: use `oarbank settings get | set | reset | explain`.
  - The operations `settings.update` (use `settings.apply`), `modules.set_pipeline` (the setting `[module] pipeline`),
    `protection.rules.canary` and `protection.rules.restore` (a canary is a group value, then **Promote to fleet**).
  - The tool registry (`settings.tools.update`) and its `trust` setting: tools are fleet definitions with versions.
    Old registry entries become definitions automatically.
- **Modules that asked for a registry id** such as `java17` cannot be converted: their jobs wait with `TOOL_NOT_FOUND`
  and the readiness checklist says they need a new module version that asks for `{ id = "jdk", version = ">=17" }`.
  Approve the new version once.
- **Modules built with SDK 1.6** that use a tool version or architecture, or node, required or campaign settings, need
  core 2.9 (`requires.core >= 2.9`); an older coordinator refuses them.
- **Node packages render the agent's service again.** Upgrading a node by package (pkg, deb or rpm) rewrites its
  launchd job or systemd unit with the new settings (the 60 s stop time) and restarts it; a Windows MSI upgrade
  recreates the service. Nodes still update their agent through the coordinator as before.

### Upgrade steps

Upgrade the coordinator first, then the nodes. Running jobs continue; nodes reconnect by themselves.

- **macOS coordinator:** log in as the person who runs it and double-click `oarbank-coordinator-2.9.0-macos-arm64.pkg`.
  When it finishes, Oarbank Coordinator's status should read *system*. If it offers **Move the coordinator to a system
  service…**, click it (macOS asks for an administrator once). Check with `oarbank coordinator status`.
- **Linux coordinator:** `sudo apt install ./oarbank-coordinator-2.9.0-linux-<arch>.deb` (or `sudo dnf install` the
  rpm). The package migrates the per-user coordinator; log out and back in so your account's new `oarbank-admin`
  membership applies to the CLI.
- **Windows coordinator:** run `oarbank-coordinator-2.9.0-windows-<arch>.msi`. It stays a Windows service, as before.
- **Nodes:** let the coordinator update the agents (`oarbank agent upload`, `sign`, `canary --node <node>`, `promote`),
  or install the 2.9.0 node package over the old one (macOS pkg, `apt`/`dnf`, MSI), which also renders the service
  definition again. Nothing needs to rejoin.
- **Modules:** open each module's readiness checklist. Publish a new version of any module that asked for a tool
  registry id, and set any settings a module marks required.

### Known limitations

Not yet verified on real systems (see [docs/design/coordinator-system-service.md](docs/design/coordinator-system-service.md)
and [docs/design/macos-containers.md](docs/design/macos-containers.md)):

- The system-service coordinator under Developer ID signing (Allow in the Background lists unsigned builds as "Unknown
  Developer"), FileVault's unlock path, the administrator prompt from the setup wizard and the app, group membership
  for a wizard that is already running, Linux's pkexec prompt, the deb and rpm as built by nFPM, and Intel Macs.
- Containers on macOS under the system account, end to end: the Colima VM starting from the LaunchDaemon, amd64 images
  through Rosetta in that VM, the VM surviving an agent restart, and krunkit's GPU profile. If the VM cannot start
  there, the documented fallback is a VM in a logged-in person's session.
- Oarbank never installs a missing host tool itself; it shows the install command and a **Re-detect**.
- On Windows the agent gets its 60 s on a service stop or restart, but a system shutdown gives services only the time
  Windows allows.

## 2.8.0 (2026-10-10)

Install, then join: node packages ask nothing; paste the join code into Oarbank Node or run
`sudo oarbank-node join`, and the console's **Add machine…** shows what to run on each system. See the
[release page](https://github.com/roeehrl/oarbank/releases/tag/v2.8.0).
