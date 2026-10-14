# Changelog

What changed in each Oarbank release, for the people who run a fleet. The module SDK has its own changelog in
[roeehrl/oarbank-sdk](https://github.com/roeehrl/oarbank-sdk/blob/main/CHANGELOG.md); the documentation is at
[docs.codonic.dev/oarbank](https://docs.codonic.dev/oarbank).

## Unreleased

### Added

- **Approve a machine with what it starts as.** `oarbank node approve` and `approve-code` take `--state paused`,
  `--module-off <module>` (and `--module-on`), `--set key=value` (`<module>:key=value` for a module's own setting),
  `--labels` and `--groups`; the console's waiting card has **Approve with options…** with a review. They are written in
  the same step that creates the node and issues its certificate, so a machine that must run no work is never granted a
  job or a certification golden before you can pause it. A paused node, and a module turned off on a node, get no
  certification goldens.
- **The same machine, reinstalled.** For a waiting machine that looks like a known node but cannot prove it is,
  `--adopt-settings-from <old node>` (console: "This is the same machine: carry over its settings and retire the old
  record") carries the old node's settings, state, module switches, protection, update hold and pin, labels and groups
  over and retires the old record, in one audited step. You type the old node's name to confirm; it is refused while the
  old node is online and for a request that proves a node's key.
- **Safer onboarding.** The fleet settings `new_node_state` (`active` or `paused`) and `new_node_modules` (`all` or
  `none`) set what every new node starts as, a join code's automatic approvals included.

### Fixed

- **A machine whose node was retired joins as a new machine.** A machine that enrolled again from a retired node's
  Tailscale device (reinstalled, with a new key) was taken for a re-enrolment of that node. The waiting card said
  "re-enrolment of" the retired node and that it proved the node's key, and approving it brought the retired record
  back, with its old settings. A join code that approves automatically did this with no one looking. A retired node is
  now never what a request is, by its key or by its Tailscale device, and is no lookalike: the request is a new node
  under the fleet's onboarding policy. `--adopt-settings-from` a retired node is refused (`adopt_refused`, "is
  retired") instead of answering that there is no such node. Naming the old node by its host name now finds that
  node, not the new node being approved under the same name. The waiting card says whether a re-enrolment proves the
  node's key or comes from its Tailscale device. A request already waiting is judged again when it is shown and
  approved, so it needs nothing after the upgrade.
- **A platform no module runs on no longer waits for the owner's signature.** With release signing on, a platform
  none of the enabled modules runs on (a Windows PC when the only module is macOS-only) got a release with no module
  that waited for the owner to sign it: its nodes never became ready, the console showed "1 release waiting for your
  signature" and the `release_awaiting_owner` alert opened, and every module change built that empty release again for
  another signature. The signature exists so nodes run only code the owner approved, and an empty release carries
  none, so it now needs no signature: oarbankd makes it current at once and its nodes are ready with no module. The
  agent installs an unsigned release only after checking it holds no module, no tool definition and no other file, and
  still refuses any release with module code that is not signed. After the upgrade, empty releases still waiting are
  retired, replaced and their alerts resolved; there is nothing to sign. Agents older than this change refuse the
  unsigned empty release until they update.
- **A freshly installed node pins its update trust when it joins.** The package pinned the fleet's owner keys at
  install time, before a fresh node had joined and had any, so `oarbank update plan` showed "no update trust is
  pinned" for it. Upgraded nodes were not affected. Joining as an administrator now leaves the pin pending: with
  `oarbank-node join`, the join window, a management profile or policy, or a join code given to the package. Root's
  update runner then pins the agent's owner keys as soon as it has them, and `oarbank-node join` reports it. Nodes that
  joined with 2.10.3 or 2.10.4 get their trust at their next package install, or with the command the plan now shows:
  `sudo /Library/Oarbank/bin/oarbank-launcher update-trust --from-agent` on macOS,
  `sudo oarbank-launcher update-trust --from-agent` on Linux, and `oarbank-node update-trust --from-agent` in an
  elevated prompt on Windows. Before, the plan showed `update-trust` without `--from-agent`, which only prints usage.
- **The coordinator pins its own update trust after a migration or an upgrade.** A coordinator moved from per-user to
  the system service by the 2.10.3 pkg could miss its update trust, and `oarbank update start` stopped with "no update
  trust on this machine". The pkg's (and deb's and rpm's) postinstall now pins it from the coordinator's owner keys
  once the services run. A home with no owner keys yet leaves the pin pending, and the runner pins it at the first
  update request. The refusal names the runnable command, `sudo "<build>/bin/oarbank-coordupdate" trust --from-home`
  (on macOS the build is inside Oarbank Coordinator.app), instead of a bare `coordupdate`.
- **A rollout halted by a refused coordinator update can go on.** `oarbank update resume` now sends the coordinator a
  new update request when its update was refused or failed (no update trust, a request no runner took), instead of
  reporting the old refusal again. `oarbank update coordinator <version>` and `oarbank update start` also supersede a
  rollout halted in its coordinator ring before any node was told to install, so it no longer needs a rollback.
- **The Windows Group Policy template zip is the same file for both architectures.** The x64 and arm64 jobs each
  built `oarbank-agent-<version>-windows-admx.zip` with different bytes, so the published zip matched only one of the
  two `SHA256SUMS-agent-*-windows-*` files (2.10.3 and 2.10.4). It is now written reproducibly: fixed order, time and
  attributes, and stored entries.
- **A coordinator update is no longer refused while a module re-certifies around running work.** When a canary (or a
  promotion, a platform or OS change, or the periodic re-certification) reached a node, that node's module went to
  `certifying` while the jobs it had been granted on the previous version kept running, as designed. The S8 invariant
  counted those jobs as running uncertified, so `oarbank update start` refused the update ("the new build's self-test
  failed ... S8 attempt ... state=certifying") and the console raised an invariant alert. The certification a job was
  granted under now stands until a new one passes its goldens or the goldens fail. Jobs still running at that point
  are stopped and queued again, uncharged; their results were refused anyway. A job granted while the node was
  certifying, or one recording a version its node's release did not carry, is still a violation. A claim in the moment
  between starting a canary and building its release was granted the canary's version while the node still ran, and
  was certified on, the previous one; it is now granted the version its release carries.
- **A module turned off on a node no longer certifies there.** After a promotion or canary, a module turned off for
  one node (`oarbank settings set enabled false --module <name> --node <node>`) still went to `certifying` there,
  queued golden jobs for it and raised `certifying_stuck` after 30 minutes. It is now shown as `disabled` on that
  node, with no goldens and no alert; an open `certifying_stuck` alert for it resolves. Turned on again, it
  re-certifies.

## 2.10.4 (2026-10-14)

A fix release for 2.10.3. Module SDK: **oarbank-sdk 1.7.0**, unchanged; its runner protocol now spells out how a
runner's `fault` and `retryable` combine, which this release acts on. Coming from 2.8 or earlier, read the
[2.10.3](#2103-2026-10-13) and [2.9.0](#290-shipped-in-2103) sections as well.

### Fixed

- **A machine re-added to the tailnet keeps its node.** Applying a tag in the Tailscale admin console makes a machine a
  new Tailscale device. The coordinator refused the node's certificate from there, and approving the agent's new
  enrollment made a second node with fleet defaults. The paused state, per-node module switches, caps, protection,
  labels and groups stayed on the old, offline record. The new enrollment's CSR is signed with the node's existing key,
  and the coordinator now recognises it. Approving it keeps the node id, settings and history, and moves the node to
  the new device. A machine that cannot prove a node's key but has a known node's host name still becomes a new node.
  The approval preview, `oarbank status` and the console say so and offer to retire the old record.
- **Module readiness no longer fails when a node's container runtime is missing pieces.** The readiness API and
  `oarbank module ready` returned an error for modules that need the `containers` pool; they now name each missing
  piece with the fix the agent reported.
- **Missing container prerequisites are re-checked, and stale Colima instances recover.** A runtime piece installed
  after the agent started is picked up within a minute, on a doctor run or on Re-detect, without a restart. A Colima
  instance left broken by a killed VM is force-stopped and started again, a bounded number of times, and a failed start
  is retried with a backoff instead of on every protection tick. A stopping agent stops its VMs.
- **Probes and services run again when a module's tool grants change.** A probe that ran before its host tool was
  resolved no longer stays `undetected` until its period ends.
- **A job whose runner declares it can never succeed ends at once.** `fault: "job"` (or exit 2 with `failure.json`) or
  `retryable: false` now fails the job immediately: it is not retried on other nodes and not quarantined.
  `fault: "job"` with `retryable: true` spends one of the stage's retries, as `fault: "job"` did before. The failure's
  reason, code and detail are kept and shown by `oarbank job show`, Explain, the campaign summary and the console, and
  modules receive them in `campaign.tick` and `host.jobs.query`. A golden job that ends this way fails the module's
  certification on that node.
- **Protected processes are evaluated fail-safe without a session helper.** On macOS a person's processes are listed
  and matched even when their session helper is not connected; facts that cannot be read count as holding, and usage
  that cannot be measured counts within bounded reservations. Linux covers inactive sessions and accounts whose helper
  went away the same way.
- **Session helpers are served after an upgrade.** The agent makes the helpers' socket directory when it is missing,
  keeps retrying to serve them, and reports when they are not served (`PROTECTION_SESSION_HELPER_UNAVAILABLE`, and a
  failing `helpers` row in `oarbank-node doctor`). The macOS package makes the directory on upgrade.
- **Presence counts what a person is actually doing.** On macOS a Screen Sharing viewer counts only while one is
  connected, not whenever the daemon runs. On Linux ssh logins are ignored, as on macOS. The why line names the signal
  that counted someone present.
- **Apple silicon cores are classed by level name.** Chips whose levels are named "Super" and "Performance" (with no
  efficiency cores) were given half their capacity for the second level; they now get full slots, and the why line and
  console name each level.
- **`max_slots` is described as a CPU-slot budget,** not a job count, and settings warn when it is below an enabled
  stage's `resources.cpu`. `jobs` limits how many jobs run at once.
- **The macOS node and coordinator apps' settings window has a right margin.**

### New

- **Open the console from another device.** `console_listen` (Settings → Access) chooses where the console listens:
  `localhost`, `tailscale`, IP addresses or `all`. `console_https` set to `tailscale` serves the console over https on
  the machine's tailnet name through `tailscale serve`, so passkeys work from other devices.
- **An account menu in the console header,** with clearer password and sign-in help on the Access page.

### Changes on upgrade

- Nodes that already re-enrolled as a second record before this release stay two records: set the new node's settings
  again, then retire the old one.
- On Macs whose CPU levels are named "Super" and "Performance", the node's slot count rises and its co-tenancy
  certificates are earned again once, since their hardware string changes.
- A setting of `max_slots 1` meant to run one job at a time should become `jobs 1`.

## 2.10.3 (2026-10-13)

2.10.0, 2.10.1 and 2.10.2 were not published. 2.10.2's macOS listener check connected immediately after
a simulated router reboot, before the fake gateway had restored its TCP forwarder. The check now waits up to
60 seconds for the exact service reply; a mapping that never recovers still fails the release checks.

2.10.1's release checks found a port-mapping failure: a listener that moved
back to an address it had mapped from before asked PCP with a new nonce, was refused, and NAT-PMP made a second
mapping beside the first. A listener now takes over what the journal holds for it whenever its address or settings
change, not only after a restart. A search of a million random runs then found four more rare ways one listener
could end up with two router mappings, or a mapping the node forgot. A releasing lease is renewed when its listener
is wanted again. A lost mapping is asked for again at its port. A renewal is journaled before it is sent. Each case
is a deterministic test now.

2.10.0 itself was not published because macOS fleet-update acceptance uncovered two failures. The acceptance script now
waits for the update runner's first result instead of exiting on an absent file. The updater gives macOS package tools a
`.pkg` filename for its verified cached package, so the system installer accepts it; digest and signature verification
still apply to those same bytes. Regression tests cover polling under `errexit` and `pipefail`, and package metadata
reads through the verified cache path.

The changes below ship in 2.10.3, including the 2.9.0 upgrade steps.

Module SDK: **oarbank-sdk 1.7.0**. This release lets fleet work earn beside the people who use the machines: modules
can accept connections from the internet, run long-lived daemons that are the work itself, and share a GPU with a
protected program at a measured, certified level. It also updates the whole fleet from the coordinator, with one click:
every node's full package and the coordinator itself, ring by ring, with automatic rollback. 2.9.0 was not published on
its own, so if you run 2.8, read the [2.9.0 section](#290-shipped-in-2103) as well: its upgrade steps apply.

### What's new

**Fleet updates: every node's whole package, and the coordinator, from one place.** Before 2.10 the coordinator could
replace only the agent binary on a node; the launcher, helpers, node app, service definitions and Python runtime
changed only when someone installed the node package on each machine, and the coordinator could not update itself
([docs/design/fleet-updates.md](docs/design/fleet-updates.md), D56–D62).

- **One signed fleet release per version.** `oarbank-fleet-<version>.json` (written by CI beside the release assets)
  lists every package, agent binary and coordinator build with its sha256. Import it with its assets (`oarbank update
  import <dir>`, `oarbank update fetch <version>`, or the console's Updates page), and in signing mode sign it once
  (`oarbank update sign <version>`).
- **Full node package updates on macOS, Linux and Windows.** The agent downloads and verifies the package, lets running
  jobs finish, and hands it to a root update runner that runs outside the agent's service (`oarbank-launcher
  update-run`, started by a launchd job, a systemd path unit, or the Windows helper as a detached copy). The runner
  verifies its own copy against owner keys pinned by root, installs it with the OS's tool (`installer`, `msiexec`,
  `dpkg`, `rpm`, or a tarball), and keeps the new version only once its agent has confirmed itself; otherwise it
  reinstalls the previous package.
- **The coordinator updates itself, with a safety net.** It snapshots its database and runs the new build's
  migrations on a copy first; a root runner then stops the services, keeps its own copy of the database, installs the
  new build beside the old one and starts it on probation (`GET /v1/health`). If it is not healthy within five minutes
  the old version and the database copy come back by themselves.
- **Rollouts in rings.** `oarbank update start <version>` (or **Update fleet** on the Updates page, with a preview of
  every ring) updates the coordinator first, then the `canary`, `early` and `broad` rings (`update_ring`), a node or
  two at a time (`max_unavailable`), each ring baked before the next. A failure halts the rollout and rolls back the
  nodes it moved; `pause`, `resume`, `halt`, `rollback` and `skip` are one click or command away. A node updates only
  while it is online, inside its `update_window`, not held or pinned elsewhere, with no protected phase on, and never
  ahead of the coordinator.
- **Policy.** `update_auto` (`notify` by default; `on` starts a rollout when a signed release is ready), holds and
  pins with a reason and an expiry (`oarbank update hold|pin`), and managed policy that may hold a machine or turn
  automatic updates off for it. The menu bar and tray say "Updating to …" and "Update failed: back on …".
- Invariants S29–S31 (`oarbank verify`) and the TLA+ model `specs/OarbankRollout.tla` check the slot rule, the ring
  order, the coordinator-first rule and the eligibility of every update.

**Inbound listeners and port mapping.** A module can accept TCP connections from the internet without ever holding a
socket: the node's agent owns the listener and relays each connection to the module's endpoint service or workload.

- A listener opens only when the module version's `[sandbox].net.inbound` grant is approved, you assign it to the node
  (`oarbank listener set <node> <module>/<listener>`, operation `listeners.configure`; in signing mode the node applies
  it only after `oarbank node sign <node>`), the module runs there, and no kill switch or managed policy forbids it.
  A compromised coordinator cannot open a port.
- The agent maps its own ports on the router with PCP, NAT-PMP or UPnP IGD (v1 and v2): short leases renewed early, a
  journal written before every request, every mapping verified, and re-mapping after a router reboot, a new public
  address, a network change or sleep. It never maps a port below 1024 or for another address, and never deletes a
  mapping it did not make. Forwarding the port by hand (`mapping = "manual"`) and machines with a public address
  (`mapping = "none"`) are first-class.
- Reachability is proven by a dial-back from outside: another node of the fleet on a different network, or an
  endpoint you run (`oarbank-agent probe-endpoint`, setting `listener_probe_endpoint`). The node page's **Network**
  card says in words what the router, the firewall and the probe found: `DOUBLE_NAT` (with the bridge-mode fix),
  `CGNAT`, `NO_MAPPING_PROTOCOL`, `PORT_TAKEN`, `MAPPED_UNREACHABLE`, `FIREWALL_BLOCKED`.
- `oarbank listener list|show|mappings|set|remove|probe`, and `oarbank listener disable --node <node> | --all` as the
  kill switch (`resume` undoes it). Node settings `inbound_listeners` (managed policies can force it off),
  `listener_port_range` and `listener_probe_endpoint`. Alerts `listener_unreachable` and `listener_saturated`.
  Invariant S24: every listener and mapping a node reports has an approved grant, an assignment and the statement the
  node applied.
- macOS: the node package adds the agent to the Application Firewall's allowed list when the firewall is on
  (`oarbank-agent firewall status|allow`); the Windows helper adds the listener's firewall rule. Uninstalling a node,
  and retiring an online one, releases its router mappings (`oarbank-agent portmap status|release-all`).

**Workloads: long-running daemons that are the work.** A module can declare `[[workloads]]`, such as a node of a
peer-to-peer network or a public inference server. You assign one to nodes (`oarbank workload assign
<module>/<workload> --node <node>`, previewed with the secrets it receives, the listeners it opens and the protection
rules that act on it); the agent runs it in the module sandbox in a process container of its own, restarts it with
backoff and withdraws it after repeated failures (alert `workload_withdrawn` with the last error and log tail).

- **One seat per identity.** A workload that runs under one identity per node holds a coordinator seat lease with a
  fence, named by the keyed fingerprints of the secrets it receives, so two nodes given the same key never run it at
  once (invariant S26). Leases last 30 minutes and are renewed with every heartbeat; workloads survive an agent restart
  by adoption and a coordinator outage until their lease runs out.
- **Protection treats a workload as fleet work** with its own ladder: no new seats, throttle, lower, pause up to the
  workload's declared tolerance, then stop and hold while the cause lasts.
- The module page's **Workloads** tab and the node page's **Workloads** card show each assignment, its seat, lease,
  state, last error and log tail; `oarbank workload list|assign|unassign|restart|logs`. Node setting `workloads`
  (managed policies can force it off). Containment: macOS sandbox identity, a Linux cgroup (a node without a delegated
  cgroup is not offered workloads), a Windows Job Object.

**Delegated processes.** Behind the node setting `delegated_processes` (off by default, and a managed policy can force
it off), an owner protection rule can mark the owner's own programs `delegate = {actions = ["pause", "lower"]}`, so
protection pauses and lowers them for a protected process the way it does fleet work. Only matchers a module cannot
spoof count (a code-signing identity on macOS, a trusted exact path on Linux and Windows); they are never stopped, and
every action is journaled. On a system install the person's session helper acts on the person's processes.

**Co-tenancy you can measure.** Protection reacts faster and can prove that fleet work does not slow a protected
program down.

- **Event-driven owner sources.** Progress and phase sources (JSONL events, log lines, field phases, process triggers)
  are watched, not polled, and follow the newest of a program's rotating files. A rule marked `immediate = true` pauses
  fleet work within milliseconds of a phase starting, between the two-second ticks (invariant S25). An unreadable phase
  counts as on, never looser (`PROTECTION_SOURCE_UNREADABLE`).
- **Sources in a person's home now work on a system install.** `~/...` and `/Users/<name>/...` sources are read by
  that person's session helper, which sends counts and phase states, never file contents. With nobody logged in such a
  source is unreadable and the node says so (`PROTECTION_SOURCE_NEEDS_HELPER`).
- **The paired on/off harness** (`oarbank protection ab start <node> --rule <id> [--work cpu|gpu|all|<module>]`)
  measures what given fleet work costs the protected program in randomised ON and OFF blocks and decides at your margin
  (default 2 %): no slowdown shown, slowdown, or inconclusive, with the blocks still needed. Confounded blocks (a
  restart, sleep, a power change) are dropped and repeated; a guard aborts a run that harms. The run's page draws the
  blocks and states the result in words.
- **Co-tenancy certificates.** A run that shows no slowdown becomes a certificate for that node, rule and fleet
  configuration, valid 14 days and bound to the hardware, OS, agent version and the protected program's signature
  (`oarbank protection certificates`; the protection page's **Co-tenancy** card). `oarbank protection ab sweep` finds
  the highest GPU duty that passes.
- **GPU duty governor** under the new `gpu_jobs = "certified"`: cooperative GPU work (jobs and workloads that declare
  `cooperative_throttle`) runs beside a protected GPU program at a budget an AIMD loop sets on the program's own
  progress, never above the certificate, and each unit's measured GPU time is checked against its `gpu_duty`: a unit
  over its duty is paused, then stopped and not trusted for an hour (`GPU_DUTY_EXCEEDED`, `GPU_DUTY_UNVERIFIED`).
  `oarbank protection duty [<node>]` and the protection page's **GPU duty** card show the budget, its baseline and each
  unit's asked and measured duty. Without a valid certificate `certified` behaves as `when_no_gpu_protected`
  (`GPU_NOT_CERTIFIED`). Invariant S28 checks it from the journal.
- **A GPU-using `progress_rate` rule now holds GPU work back** like a `gpu_share` rule (D3d), except under
  `gpu_jobs = always`.

**Sites: nodes that share one internet line** (`oarbank sites`, the console's **Sites** page). While a protected process
at a site is in a phase its rule tags `uplink`, the agents' transfers (staging, uploads, checkpoints) and network-heavy
jobs and workloads (`resources.network = "heavy"`) pause on every node of the site within 5 s; outside such phases a
per-site budget limits transfers and network-heavy work at once. Sites are suggested from keyed network fingerprints,
never stored addresses. Explain names `SITE_UPLINK_BUSY` and `SITE_UPLINK_BUDGET`; invariant S27 checks the leases. A
node's `staging_mbps` cap is now enforced.

**Module SDK 1.7.0.** Inbound listeners in the manifest (`sandbox.net.inbound`, `services[].listeners`) with the
`publicecho` reference module; `[[workloads]]`, the workload protocol, `oarbank_sdk.workload.Supervisor` and
`examples/workload`; `oarbank_sdk.duty` to hold a GPU duty, conformance duty specs, and `examples/llmserve`, which runs
language-model batches on MLX or llama.cpp that hold their duty; network-heavy stages. Modules that use any of these
need `requires.core >= 2.10`.

**Also in this release.**

- New reason codes: listeners (`LISTENER_UNAVAILABLE`, `PORT_TAKEN`, `DOUBLE_NAT`, `CGNAT`, `NO_MAPPING_PROTOCOL`,
  `MAPPED_UNREACHABLE`, `FIREWALL_BLOCKED`), workloads (`WORKLOAD_*`), delegation (`DELEGATE_*`), co-tenancy
  (`AB_*`, `GPU_NOT_CERTIFIED`, `GPU_DUTY_*`, `PROTECTION_PHASE_ON|OFF`, `PROTECTION_SOURCE_UNREADABLE`,
  `PROTECTION_SOURCE_NEEDS_HELPER`), sites (`SITE_*`, `TRANSFER_PAUSED`, `TRANSFER_RESUMED`, `PREEMPT_SITE`) and
  `MEMORY_HARD_FLOOR_WORKLOAD`.
- The managed policy templates (the macOS profile keys, the Windows ADMX, Linux `policy.json`) gain `workloads`,
  `delegated_processes` and `inbound_listeners`.
- `oarbank verify` checks the new invariants S24 to S28 with the others.

### What changes when you upgrade

- **A node package install now makes the package's agent current**, on macOS and Linux as on Windows: the package is
  the unit an update moves, so a manual install and a fleet update can no longer disagree about the agent's version.
- **Installing 2.10 pins update trust on each machine** (`oarbank-launcher update-trust --from-agent` in the node
  package, `python -m oarbank.coordupdate trust --from-home` in the coordinator's): the owner keys the node or the
  coordinator already trusts become root's trust for later updates. A node that joins after its package was installed
  needs `sudo oarbank-launcher update-trust --from-agent` once.
- **The coordinator's database gains its new tables by itself** on the first start of 2.10 (from a 2.8 or 2.9 home);
  nothing is converted or removed.
- **Nodes need the 2.10 agent** for listeners, workloads, delegated processes, event-driven sources, harness runs,
  the GPU duty and site holds. Older agents keep running jobs as before: the console says "agent ... is older than this
  coordinator", a listener assignment is refused (`agent_unsupported`), a workload assigned to it does not start
  until it runs the 2.10 agent, and the Sites page shows such a node as "not reported (update its agent)".
- **A GPU trainer protected by its progress now holds fleet GPU work back.** Before, only `gpu_share` rules did, so a
  rule with `protect.metric = "progress_rate"` on a GPU-using program let fleet GPU work run beside it. Under the default
  `gpu_jobs = "when_no_gpu_protected"` that work now waits; to run it alongside, earn a certificate and set
  `gpu_jobs = "certified"`.
- **Sources in a person's home are read for real on a system install.** Before 2.10 such a source could never be read
  and held fleet work back for good; now it is read while the person is logged in and still holds fleet work back
  while nobody is.
- **`staging_mbps` is enforced.** A node cap that was set but had no effect now limits its transfers.
- **Modules built with SDK 1.7** that declare inbound listeners, workloads, duty specs or network-heavy stages need core
  2.10 (`requires.core >= 2.10`); an older coordinator refuses them.
- **The macOS node package edits the Application Firewall's list**: when the firewall is on, the agent is added as
  allowed, so the first inbound connection does not wait on a prompt.

### Upgrade steps

Upgrade the coordinator first, then the nodes. Running jobs continue; nodes reconnect by themselves. This is the last
release you install machine by machine: from 2.10 on, import the next release and start a rollout from the Updates
page (or `oarbank update start <version>`).

- **Coordinator:** install `oarbank-coordinator-2.10.3-<os>-<arch>` (macOS pkg, deb or rpm, Windows MSI) over the old
  one. From 2.8, the 2.9.0 steps below apply (the macOS and Linux coordinator moves to a system service once).
- **Nodes:** let the coordinator update the agents (`oarbank agent upload`, `sign`, `canary --node <node>`, `promote`),
  or install the 2.10.3 node package over the old one. Nothing needs to rejoin.
- **To use the new features:** approve the module versions that ask for them, then assign listeners (`oarbank listener
  set`, and `oarbank node sign` in signing mode) and workloads (`oarbank workload assign`); group nodes on one line into
  sites from the Sites page's suggestions; for GPU co-tenancy, give the protected program a `progress_rate` rule, run
  `oarbank protection ab sweep`, then set the node's `gpu_jobs = "certified"`.

### Known limitations

Built and tested against simulations and fakes; the owner verifies these on real systems before relying on them:

- **Fleet updates on real machines.** The update runner, the rollout and the rollback run end to end in CI with a
  tarball install on Linux, and the deb and rpm, MSI and pkg updates have CI jobs on GitHub's runners. Still to see on
  the owner's machines: a signed and notarized pkg through the runner with the team pin, a coordinator self-update on a
  copy of the live coordinator including a forced probation failure, and a Windows node's MSI update through the
  helper. After a coordinator self-update on Windows, a later manual MSI install does not move the `current` junction.

- **Port mapping on real routers.** Every test talks to fake PCP, NAT-PMP and UPnP gateways on loopback. Still to see
  on real networks: a single NAT with UPnP (map, renew, router reboot, network change, sleep, uninstall leaving nothing
  behind on the router's own page), NAT-PMP and PCP routers, a double NAT and a CGNAT line, a dial-back between two
  networks, and IPv6 pinholes ([docs/design/inbound-listeners.md](docs/design/inbound-listeners.md#what-remains-to-verify-on-real-routers)).
- **Firewalls.** The macOS Application Firewall was checked with an ad hoc–signed agent only: a Developer ID–signed
  agent with "allow downloaded signed software", and whether the allowance follows the agent across self-updates, are
  not yet measured; nor is the Windows Defender Firewall rule the helper adds.
- **Real GPU backends.** `examples/llmserve` conforms in CI with its CPU stand-in; MLX and llama.cpp with a real model
  are for the owner to run.
- **A real protected program.** The harness, certificates and the duty governor ran against synthetic protected
  processes and a simulated plant. The first certificate comes from a run against a real protected program in a window
  the owner frees for it ([docs/design/gpu-cotenancy.md](docs/design/gpu-cotenancy.md#running-the-first-measurement-against-a-real-protected-program)).
- **Linux and Windows** gateway fingerprints (sites), workload containment (cgroups, Job Objects) and delegation are
  compiled and unit-tested on the development Mac and first exercised on those systems in CI.
- Not in this release: container workloads, UDP listeners, a relay node for nodes that cannot be reached, stopping a
  delegated process, and multi-node (gang) jobs. On Windows delegated processes are matched by trusted path only, and
  only in the agent's own session. Releases, agent updates and container image pulls are not held by a site.

## 2.9.0 (shipped in 2.10.3)

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
