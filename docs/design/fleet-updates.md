# Fleet updates: whole packages on every node, and the coordinator itself

Status: designed for **core 2.10.0** (PLAN D56–D62; invariants S29–S31; TLA+ `specs/OarbankRollout.tla`).

## The problem

Agent self-update ([protocol.md](../protocol.md), "Agent self-update") replaces one file: the `oarbank-agent` binary.
A node also runs:
- the launcher;
- the root helper (macOS) or the elevated helper (Windows);
- the session helper;
- the node app and menu bar or tray;
- the service definitions;
- the bundled Python runtime and the join assets.

Since 2.9, much of a release lives in those files. They change only when someone installs the node package on each
machine by hand. The macOS pkg and the deb/rpm postinstalls also deliberately leave the agent version alone ("the
coordinator's to change"). So a package install and a self-update are two half-updates that can disagree.

The coordinator has no self-update at all. Its programs are root's (D44, coordinator-system-service.md decision 3), it
runs unprivileged, and an upgrade means rerunning its package on the coordinator machine.

For a fleet of a handful of machines that is still a manual install per machine and per release, twice over. The owner's requirement for
2.10: the easiest, seamless way to update the whole fleet, safely.

## What the research says

Sources are summarized in the references at the end. The design takes these points from them:

- **Two signatures over one hash (TUF, Uptane).** The vendor attests that an artifact exists and what its hash is; the
  owner attests that this fleet should run it. A node installs only when both agree. Fleet/orbit runs TUF this way, and
  Uptane splits the "director" (what to install) from the "image repository" (what exists) for the same reason: a
  stolen online key cannot push an arbitrary build.
- **Install → pending → commit, with an automatic rollback deadline** (Mender's ArtifactCommit, RAUC/SWUpdate
  "mark good", Chrome's updater qualification, our own launcher trial). Nothing is final until the new version proves
  itself on the machine.
- **The thing being replaced never supervises its own replacement.**
  - Tailscale on Windows copies its exe and runs the MSI from a detached copy.
  - Sparkle installs through a separate installer launcher.
  - On Linux, a package's postinst restarting its own service kills a `dpkg` the service started; a transient
    `systemd-run` unit survives.
  - On macOS, run `installer -pkg` from a launchd job of its own.
- **MSI upgrades.** Use `MajorUpgrade` with `Schedule="afterInstallInitialize"`, so removing the old product happens
  inside the install transaction and a failed upgrade restores it. Treat 1618 as "another install is running, retry
  later" and 3010/1641 as success with a reboot pending. Pin the Authenticode signer, because WinVerifyTrust alone
  accepts any valid signature.
- **macOS pkgs.** Check them with `pkgutil --check-signature`, pinning the Developer ID Installer team. `spctl -a -t
  install` is advisory; it has rejected valid notarized pkgs.
- **Rollout pace is policy, not clicks** (Google SRE canarying, AWS hands-off deployments, Microsoft safe
  deployment, Windows Update rings, Kubernetes `maxUnavailable` and `progressDeadline`, Argo Rollouts analysis):
  - small rings first, then bake for **time and evidence**, then widen;
  - halt automatically on a failed gate, an exhausted failure budget, or a fleet that was already unhealthy;
  - treat an inconclusive gate as *pause*, never *proceed*;
  - roll back automatically where it is safe.
- **Control plane first, nodes never ahead of it** (Kubernetes version-skew policy). Older nodes catch up when they
  return, through required "stop" versions when a format boundary demands it.
- **A server that updates itself** (GitLab, Mattermost, Home Assistant) takes an automatic database backup before
  migrating. It updates side by side and swaps a pointer, health-checks the new version, and restores the backup
  automatically when the new version fails its probation.
- **Holds and pins carry a reason and an expiry** (Windows Update for Business deferrals and pauses, Fleet holds).
  A forgotten hold turns into a silently stale machine.

## The decisions

| # | Decision |
|---|---|
| D56 | **One signed fleet release per version.** `oarbank-fleet-<v>.json` lists every artifact of the release: node packages per OS/arch/format, the agent binary per platform and the coordinator builds per platform. For each it gives the sha256, size, platform, format and role, plus the version's skew and stop rules. CI writes it beside the release assets. In signing mode, the owner signs it (`oarbank update sign`) with the owner key set; agents and the root update runners built with the vendor TUF root also require the vendor's targets to list it with the same hash. The owner signature is what makes it installable here, and the manifest hash is authoritative. Native OS signatures (Developer ID Installer with a pinned team, Authenticode with a pinned subject) are checked on top where the build pins them. |
| D57 | **Whole-package node updates through a root update runner.** The agent never installs anything: it downloads the package from the coordinator, verifies it and drains. It then writes a request into its spool (`<agent home>/updates/request.json`), which starts the root **update runner** (`oarbank-launcher update-run`) as a job of its own: a launchd `WatchPaths` daemon on macOS, a systemd `.path` unit on Linux, or the elevated helper starting a detached copy on Windows. The runner trusts nothing in the request. It copies the package into its own root-only directory and verifies the copy against its root-owned trust (`<system data>/update/trust.json`: owner anchors pinned by an administrator's install, plus the build's vendor root and native signature pins). It installs with the OS's own tool (`installer -pkg`, `msiexec /i … /qn`, `dpkg -i`, `rpm -U`, or unpacking a tarball), points `current` at the package's agent and waits for the new agent to confirm (first hello and heartbeat, 600 s). Otherwise it reinstalls the previous package it kept and points `current` back. The package is the unit: the launcher, helpers, apps, runtime and agent move together. |
| D58 | **Coordinator self-update with a snapshot and automatic restore.** oarbankd checks the build and copies its database (SQLite backup API) to `updates/snapshots/`. It checks that the copy is sound (integrity check, migrated by the new build's own `--self-test` in a scratch home), then writes a request that starts the root **coordinator update runner** (`python -m oarbank.coordupdate run`, from root's programs): a launchd `WatchPaths` job, a systemd `.path` unit, or a SYSTEM scheduled task on Windows. The runner verifies against its own root-owned trust, stops the services and takes its own root-owned copy of the database. It then installs the build side by side (`PROGRAMS/<v>-<sha12>`, the same layout `install-oarbankd --build` uses), flips `current`, refreshes the service definitions and starts them. Probation follows: `GET /v1/health` must report the new version, migrations done and the tick running, within 300 s and holding for 60 s. If probation fails, the runner stops the new version, restores the database copy, flips `current` back, starts the old one and records why. Data written during probation is lost; probation is short and the coordinator admits no new work while it lasts. |
| D59 | **Rollouts: rings, a canary, `max_unavailable`, bake gates, automatic halt and rollback.** A rollout takes the fleet to one release:
| | 1. The coordinator updates first (ring 0).
| | 2. Then the node rings `canary` → `early` → `broad`, a node's ring being the `update_ring` setting.
| | 3. Within a ring, at most `max_unavailable` nodes are between *draining* and *confirmed* at once.
| | 4. The next ring starts only after the ring finished and baked: its bake time passed **and** each updated node heartbeated at least 10 times on the new version **and** no node of the ring was unhealthy.
| | 5. Install failures are counted against the ring's failure budget: 0 for canary, 1 after that. Exceeding it halts the rollout, and with `auto_rollback` (default on) the updated nodes go back to the previous release through the same machinery.
| | 6. A node updates only when every one of these holds:
| |   - it is online (heartbeat within 120 s);
| |   - it is inside its `update_window`;
| |   - it is not held;
| |   - it is not pinned elsewhere;
| |   - no protected phase is on there (`protection.any_phase_on`);
| |   - its site is not holding uplink-heavy work (only while downloading);
| |   - it holds no per-node workload seat it would have to give up (seats are adopted across the restart, so a running workload only defers past its renewal).
| | 7. Running attempts finish during the drain. After `drain_timeout` (default 30 min) the node is released back to work and retried later, never killed.
| | 8. A rollout does not start while more than a third of the fleet's online nodes are unhealthy. |
| D60 | **Update policy on the settings chain.**
| | - `update_auto` (`off`, `notify`, `on`; fleet, group, node): whether a newly imported signed release starts a rollout by itself.
| | - `update_ring` (`canary`, `early`, `broad`).
| | - `update_window` (the schedule type).
| | - `update_hold` (`{reason, until}`, or none).
| | - `update_pin` (a version, with a reason and an expiry).
| | Managed policy may only tighten: `update_auto` towards `off` and `update_hold` on. Holds and pins expire; the console flags an expired one and the node rejoins the rollout. A coordinator in signing mode needs owner-signed releases for `on`. The default is `notify`: the coordinator says a release is ready and the owner starts it with one click. |
| D61 | **Version skew and catch-up.** No node is ever assigned a release newer than the running coordinator (S30). A release names its `stops`: versions a node must pass through. The coordinator assigns the next stop to a node older than it, and keeps every stop's artifacts while a node needs them. A node that was offline joins the rollout's current ring when it returns, or gets the release directly once the rollout is done (still under its window, hold and `max_unavailable`). A node older than the coordinator's `agent_min` is refused work until it updates (`AGENT_TOO_OLD`). |
| D62 | **One click, and visible everywhere.**
| | - The console's **Updates** page shows the coordinator and every node by version and update state, an imported release with its notes, and **Update fleet** (a T2 plan: rings, nodes per ring, windows, holds, order). It also lists the active rollout's rings and gates with **Pause**, **Resume**, **Halt**, **Roll back** and **Skip node**, and the history.
| | - `oarbank update status / import / fetch / sign / start / pause / resume / halt / rollback / hold / unhold / pin / unpin / trust` does the same.
| | - The node's status document carries `update {state, version, error}`, so the menu bar and tray show "Updating to 2.10.0…" or "Update failed; back on 2.9.0".
| | - Halts, rollbacks and nodes stuck over 45 min raise alerts. |

## The fleet release manifest

`oarbank-fleet-<version>.json`. `scripts/fleet-manifest.py <version> <dist>` writes it in CI from the release assets.
It is canonical JSON (keys sorted, no insignificant whitespace), so its bytes are what both signatures sign:

```json
{
  "type": "oarbank-fleet-release", "format": 1,
  "version": "2.10.0", "seq": 21000,
  "released_at": "2026-10-20T00:00:00Z", "expires": null,
  "notes": "https://github.com/roeehrl/oarbank/releases/tag/v2.10.0",
  "agent_min": "2.9.0",
  "stops": ["2.9.0"],
  "artifacts": [
    {"name": "oarbank-agent-2.10.0-macos-arm64.pkg", "role": "node", "platform": "darwin-arm64", "format": "pkg",
     "sha256": "…", "size": 51234567, "agent_version": "2.10.0"},
    {"name": "oarbank-agent_2.10.0_amd64.deb", "role": "node", "platform": "linux-amd64", "format": "deb", …},
    {"name": "oarbank-agent-2.10.0-1.x86_64.rpm", "role": "node", "platform": "linux-amd64", "format": "rpm", …},
    {"name": "oarbank-agent-2.10.0-linux-amd64.tar.gz", "role": "node", "platform": "linux-amd64", "format": "tar", …},
    {"name": "oarbank-agent-2.10.0-windows-x64.msi", "role": "node", "platform": "windows-amd64", "format": "msi", …},
    {"name": "oarbank-agent-2.10.0-darwin-arm64", "role": "agent", "platform": "darwin-arm64", "format": "binary", …},
    {"name": "oarbank-coordinator-2.10.0-darwin-arm64.tar.gz", "role": "coordinator", "platform": "darwin-arm64",
     "format": "tar", …}
  ]
}
```

- **`seq`** rises with every release. It is the anti-rollback counter for automatic installs: a runner refuses a
  manifest whose seq is below the highest it committed, unless the request is a **rollback**. A rollback reinstalls
  exactly the previous package the runner kept, or a release the owner signed with `rollback_to` naming it.
- **`stops`** are versions a node older than them must pass through (D61).
- **`agent_min`** is the oldest agent this coordinator version still serves.
- **`expires`**, when set, makes a manifest uninstallable after that time (freeze protection).
- **Signatures.** The owner's statement is `{"type": "oarbank.fleet-release/v1", "manifest_sha256", "version",
  "seq", "signed_at"}`, signed with Ed25519 like the other owner statements (`signing.py`) and checked against the
  owner key set (`owner.keys`). The vendor's is a TUF target named `oarbank-fleet-<version>.json` with the manifest's
  length and sha256.

`oarbank update import <dir>` stores a release, as do the console's import and `oarbank update fetch <version>`, which
downloads from the release source (`update_source`, by default the project's GitHub releases).
1. The manifest and every artifact the fleet's platforms need are read.
2. Each artifact's sha256 and size are checked.
3. The artifacts are stored content-addressed (`<home>/updates/artifacts/<sha256>`) and registered.
4. Artifacts for platforms no node runs are skipped. They are fetched later if such a node joins.

A release is **ready** when every artifact the current nodes need is present and, in signing mode, the owner's
signature verifies.

## On the node

### The directive and the agent's part

While a node's assigned release (the rollout's ring rules, its pin, its stops) differs from what it reports
running, the heartbeat reply carries:

```json
"node_update": {"release": "2.10.0", "seq": 21000, "go": false,
                "artifact": {"name": "…", "format": "deb", "sha256": "…", "size": 123, "url": "/v1/updates/artifacts/<sha>"},
                "manifest": "<canonical manifest text>", "signature": {"statement": "…", "signature": "…"} | null,
                "rollback": false, "drain_timeout_s": 1800}
```

The agent works through these steps, reporting `node_update {state, release, error, at}` on every heartbeat:
- **`staging`.** It downloads into `<home>/updates/incoming/`, under a site transfer lease where the node has a site. It
  checks size and sha256, checks that the manifest names this exact artifact for its platform and format, and verifies
  the signature (signing mode). Then it reports **`staged`**. A failure is **`failed`** with the reason, and that seq is
  not retried until the coordinator re-issues it.
- **`draining`.** When the directive says `go`, the agent stops claiming. Running attempts finish; services are left
  for the restart to adopt. If `drain_timeout_s` passes first, it reports **`deferred`** and claims again; the
  coordinator gives the slot to another node and retries later.
- **`installing`.** Once drained, it moves the package to `<home>/updates/package` and writes `<home>/updates/request.json`
  (`{id, release, seq, format, sha256, size, manifest, signature, rollback, requested_at}`), then reports `installing`.
  From here the runner owns the outcome; the agent keeps heartbeating until the service manager stops it.
- **Confirmation.** After the package installed, the new agent starts. It reads `<home>/updates/result.json`, where the
  runner says `installed` and waits. After its first hello and heartbeat it writes `<home>/updates/confirmed` and
  reports **`confirming`**. When the runner commits, the agent reports **`done`**. If the runner rolled back, the old
  version, running again, reports **`rolled_back`** with the reason.

The agent's install facts gain `install: {format, scope, updater}`:
- `format` comes from how it was installed: the package database (`dpkg -S`, `rpm -qf`), `/Library/Oarbank` with a pkg
  receipt, an MSI product code, a tarball, or `dev`.
- `scope` is `system` or `personal`.
- `updater` says whether the runner's trigger and trust are in place.

A node whose `updater` is false (a personal install, a dev build, a node with no trust anchor yet) is shown on the
Updates page with the remedy, and gets agent-only self-update as before. The rollout skips it with a reason; it is never
silently left behind.

### The update runner (`oarbank-launcher update-run`)

The runner runs as root (LocalSystem on Windows) in a job of its own, so a package that restarts the agent's service,
or the helper that started it, never kills it. Its state is in `<system data>/update/` (root-only):
- `trust.json`;
- `journal.json`, its state machine, fsynced before every step;
- `packages/<sha256>`, the current and the previous package, two kept;
- `logs/`.

Steps, each journaled:

1. **Take the request.** Read `request.json`. Copy the package into `packages/.incoming` and verify **the copy**, never
   the agent's file:
   - size and sha256;
   - the manifest names it for this machine's platform and the installed format;
   - the manifest's signature against `trust.json`'s owner keys (unless trust says `unsigned`, an explicit
     administrator's choice for test fleets);
   - the vendor targets, where the launcher embeds a vendor root;
   - the native signature where the build pins one: `pkgutil --check-signature` with the pinned team on macOS,
     Authenticode subject on Windows;
   - the seq against `journal.committed_seq`, unless this is a rollback to the package it kept.

   A refusal writes `result.json {state: refused, error}` and stops.
2. **Install** with the OS tool:

   | Format | Command | Notes |
   |---|---|---|
   | pkg | `installer -pkg <copy> -target /` | The pkg's postinstall refreshes and restarts the launcher and helper daemons, and now also points `current` at the package's agent |
   | msi | `msiexec /i <copy> /qn /norestart /L*v <log>` | 1618 retries after 5, 15 and 60 min; 3010/1641 count as success with `reboot_pending`; `MajorUpgrade Schedule="afterInstallInitialize" AllowDowngrades="yes"` |
   | deb | `dpkg -i <copy>` | Waits for the dpkg lock up to 20 min; on a half-configured state, `dpkg --configure -a` once |
   | rpm | `rpm -U --replacepkgs <copy>` | `--oldpackage` for a rollback |
   | tar | unpack into `<prefix>/versions/<version>/`, then an atomic `current` flip | The Linux tarball install, and the test format |

3. **Point the agent.** Run `oarbank-launcher install <the package's agent>`, so the package's agent is `current`, and
   write `result.json {state: installed, release}`. The service is (re)started by the package, or by the runner for the
   tar format.
4. **Probation.** Wait up to 600 s for `<agent home>/updates/confirmed` naming this release, written by an agent whose
   own version is the release's. Absence is a failure; a forged file gains nothing beyond what the agent account could
   already do (keep the version it has).
5. **Commit or roll back.**
   - Commit: `journal.committed_seq = seq`, delete packages but the two latest, `result.json {state: done}`.
   - Roll back: reinstall the kept previous package the same way (macOS and deb/rpm allow the downgrade; the MSI
     allows it), `oarbank-launcher install` its agent, and write `result.json {state: rolled_back, error}`. With no kept
     package (the first fleet update of a node installed by hand), the rollback points `current` back at the previous
     agent binary and says it is partial.
6. **Crash recovery.** A runner that starts and finds a journal mid-step resumes it. `installing` re-runs the install,
   which is idempotent. `probation` continues the wait from its recorded deadline. A reboot mid-update ends in the same
   place.

**Triggers.** Each one is root's and installed by the package:
- **macOS:** `/Library/LaunchDaemons/dev.codonic.oarbank.agent.update.plist` (`WatchPaths` on the request,
  `RunAtLoad` for crash recovery).
- **Linux:** `dev.codonic.oarbank.agent.update.path` (`PathExists`) and its oneshot `.service`.
- **Windows:** the elevated helper (`OarbankHelper`, LocalSystem) watches the spool. It copies the launcher to
  `%ProgramData%\Oarbank\update\runner\` and starts it with `DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB`, because the
  MSI it runs replaces the files and restarts the helper itself.

**Trust.** `trust.json` is written only by root:
- **First pin:** at an administrator's install of a package that has one, `oarbank-launcher update-trust --from-agent`
  in postinstall or the MSI custom action. It copies the owner anchors the agent pinned (D35's trust on first use)
  while the administrator is present.
- **Explicit pin:** `sudo oarbank-launcher update-trust --from-agent` on a node that joined after its package was
  installed, or `--keys` with the fingerprints the console shows.
- **Rotation:** `owner_anchors` statements the agent relays in the request. Like the agent's own rule, the version must
  be +1 and the statement signed by a key of the old set and every new key.

A node with no anchors and no vendor root or native pin has no updater, and says so.

### Why the agent account cannot use the runner to become root

The runner installs only bytes whose hash a manifest names, verified against keys root pinned. Where pinned, the
native signature must also be the vendor's. The agent chooses *when* (it writes the request) and can make the runner
roll back (by not confirming). It cannot choose *what*: the most it can do is install another release the owner
signed, at a seq no lower than the committed one. Request fields are data: the runner reads the package from its own
copy, and paths never come from the request.

## The coordinator

**Ring 0.** A rollout whose release is newer than the coordinator starts by updating the coordinator: `coordupdate`,
D58. The rollout's state says so; nodes wait. The coordinator refuses its own update while any enrolled, non-retired
node runs an agent older than the new release's `agent_min`, unless the node is held. The plan names those nodes.

**Prepare (oarbankd, unprivileged).**
1. Check the build's sha256 and the owner signature.
2. Take a snapshot with `VACUUM INTO <home>/updates/snapshots/<from>-<ts>.sqlite3`, plus `integrity_check`.
3. Self-test: unpack the build into a scratch directory and run its `oarbankd --self-test --home <scratch copy>`, which
   opens a copy of the snapshot, runs its migrations and checks invariants, then exits.
4. Write `coordinator_updates {state: requested}` and the spool request `<home>/updates/coordinator-request.json`.

**Run (root).** `coordupdate run` is triggered by:
- **macOS:** `dev.codonic.oarbank.oarbankd.update` (`WatchPaths`).
- **Linux:** `dev.codonic.oarbank.oarbankd.update.path`.
- **Windows:** the SYSTEM task `\Oarbank\CoordinatorUpdate`, every minute, exiting at once without a request.

It then:
1. Verifies the build against `<system data>/coordinator-update/trust.json` (root's, first pinned by the coordinator package's
   postinstall from the home's owner anchors while an administrator installs it).
2. Stops both services.
3. Copies `oarbank.sqlite3` with SQLite's backup API to `<system data>/coordinator-update/db-<id>.sqlite3` (root's:
   the coordinator account cannot alter its own restore point).
4. Unpacks into `PROGRAMS/<v>-<sha12>`, flips `current`, refreshes the service definitions (`install-oarbankd
   --refresh`) and starts the services.
5. **Probation.** Within 300 s, `GET /v1/health` on the agent port says `{version: <v>, migrated: true, ticking: true}`,
   and it stays so for 60 s.
6. **Commit:** keep the previous programs and the root copy for 14 days. **Fail:** stop, restore the copy, flip back,
   refresh, start, and check health on the old version.
7. Either way, it writes `<home>/updates/coordinator-result.json` (and its own journal). oarbankd reads it at start, records
   `coordinator_update_{done,rolled_back}`, alerts on a rollback, and the rollout continues or halts.

**Moves and D44.** The runner uses the same programs layout and service record as `install-oarbankd`, so a move's
standby (installed by `install-oarbankd --build`) and a self-updated coordinator are the same shape. A coordinator that
is moving (`handed_off`, or a move in progress) refuses to start its own update, and a move refuses to start during
one.

## Rollouts

### Tables

```sql
fleet_releases (version PRIMARY KEY, seq, manifest TEXT, manifest_sha256, signature_json, source, imported_at, imported_by,
                notes, state)                       -- state: incomplete | ready | revoked
fleet_artifacts (sha256 PRIMARY KEY, version, name, role, platform, format, size, path)
rollouts (rollout_id, version, from_versions_json, state, ring, ring_started_at, ring_finished_at, policy_json,
          created_by, created_at, updated_at, halted_reason, kind)       -- kind: update | rollback
rollout_nodes (rollout_id, node_id, ring, state, from_version, attempts, failures, go_at, started_at, finished_at,
               error, PRIMARY KEY (rollout_id, node_id))
coordinator_updates (update_id, version, from_version, state, snapshot, requested_at, finished_at, error)
```

### The rollout state machine

```
planned ─start─▶ running(coordinator) ─done─▶ running(canary) ─finished & baked─▶ running(early) ─▶ running(broad) ─▶ done
running ─pause─▶ paused ─resume─▶ running
running ─failures > budget │ coordinator update rolled back │ fleet unhealthy at a ring's start─▶ halted
halted ─resume─▶ running          halted ─rollback (auto with auto_rollback)─▶ rolling_back ─▶ rolled_back
any ─a newer release's rollout starts─▶ superseded
```

Per node: `pending → waiting(why) → staging → staged → draining → installing → confirming → done`. The exits are:
- `deferred`: the drain timed out; back to `waiting`.
- `failed` / `rolled_back`: counted against the ring's budget.
- `skipped(why)`: unsupported, held, pinned, or retired.

A node offline when its ring runs is `waiting(offline)`. The ring finishes without it, and it catches up later
(D61).

### The tick

The rollout tick runs in the coordinator's background thread, in one transaction per rollout:

1. **Coordinator first.** If the rollout's version is above the running coordinator's and no coordinator update is
   done, request one (once) and wait.
2. **Gate the ring's start.** If more than a third of the online nodes are unhealthy (no heartbeat in 300 s, or
   quarantined), halt with `fleet unhealthy`.
3. **Grant slots.** In the current ring, count nodes in `draining`, `installing` or `confirming`, plus `staged` ones
   with `go`. While that is below `max_unavailable`, grant `go` to the next `staged` node that is eligible (D59). Idle
   nodes go first, then by fewest running attempts and by hostname.
4. **Count failures.** Every `failed` or `rolled_back` node adds to the ring's failures. Above the budget: halt, and with
   `auto_rollback` start a `rollback` rollout to the previous release for the nodes this rollout moved.
5. **Finish and bake.** The ring is finished when every member is `done`, `skipped` or `waiting(offline)`. It is baked
   when `bake_s` has passed since and each `done` node has at least 10 heartbeats on the new version, none of them
   unhealthy since. A node unhealthy during the bake counts as a failure. Then the next ring starts.
6. **Watch for stuck nodes.** A node in `draining`, `installing` or `confirming` for over 45 min raises
   `update_node_stuck`; it still counts against `max_unavailable`.

Default ring policy (an operation's params may override it; a `critical` release may use `fast`):

| Ring | `max_unavailable` | `bake_s` | Failure budget |
|---|---|---|---|
| coordinator | — | 600 | 0 |
| canary | 1 | 1800 (fast: 600) | 0 |
| early | 1 | 7200 (fast: 600) | 1 |
| broad | max(1, 25 %) | 0 | 1 |

An empty ring is skipped. With no `update_ring` set anywhere, every node is `broad`. Then the first broad node to
update acts as the canary: the budget is spent on the first failure, and the rollout halts before a second node
fails.

### Assignment

`fleetupdates.assigned(db, node)` gives a node's target, in this order:
1. Its pin, if one is set and not expired.
2. Nothing, if it is held.
3. The active rollout's version, if the node's ring has started (or the node is catching up).
4. Otherwise its current version.

A target newer than the coordinator is never returned (S30). A target past a stop the node has not reached becomes
that stop.

## Policy (settings)

| Key | Type | Scopes | Default | Tighten / managed |
|---|---|---|---|---|
| `update_auto` | `off` \| `notify` \| `on` | fleet, group, node | `notify` | towards `off`; managed |
| `update_ring` | `canary` \| `early` \| `broad` | group, node | `broad` | — |
| `update_window` | schedule, in the node's local time (its facts' `utc_offset_s`) | fleet, group, node | none (any time) | — |
| `update_hold` | `{reason, until}` \| null | group, node | null | managed (a machine may hold itself) |
| `update_pin` | `{version, reason, until}` \| null | node | null | — |
| `update_source` | URL | fleet | the project's releases | — |
| `update_check_h` | hours (0: never) | fleet | 6 | — |

`update_auto = on` (fleet or group) starts a rollout when a release becomes ready, with the default policy, inside each
node's window. `notify` raises a P4 `update_available` notice and shows the release on the Updates page. `off` does
neither; the owner can still start by hand.

## Console, CLI and the menu bar

**Updates page (`/updates`).**
- **Header:** the coordinator's version and the newest ready release, with its notes link and **Update fleet** (a T2
  plan preview: rings, nodes per ring, windows, holds, what is skipped and why).
- **Release list:** import, fetch, sign.
- **Active rollout:** ring progress, gates (bake time left, heartbeats, failures/budget), with **Pause**, **Resume**,
  **Halt**, **Roll back** and **Skip** for a node.
- **Node table:** version, target, state, ring, window, hold or pin with expiry, updater availability, and the last
  error with its log hint.
- **Coordinator card:** last self-update, snapshots.
- **History.**

The Agent page stays, for agent-only builds (dev fleets, personal installs).

**CLI.** `oarbank update` takes:
`status | releases | import <dir> | fetch <version> | sign <version> | plan <version> | start <version> [--fast] |
pause | resume | halt | rollback | skip <node> | hold <node> --reason … [--until …] | unhold <node> |
pin <node> <version> --reason … [--until …] | unpin <node> | coordinator [status]`.

Operations:

| Operation | Tier |
|---|---|
| `updates.import`, `updates.sign`, `updates.fetch` | T1 |
| `updates.start` | T2 |
| `updates.pause`, `updates.resume`, `updates.halt` | T1 |
| `updates.rollback` | T2 |
| `updates.skip`, `updates.hold`, `updates.unhold`, `updates.pin`, `updates.unpin` | T1 |

The parity registry lists each one.

**Menu bar / tray.** `status/node.json` gains `update: {state, version, error}`. The node app shows "Updating to
<v>…" during `draining` to `confirming`, and "Update failed: back on <v>" for a day after a rollback.

## Failure analysis

| Failure | Detection | Handling |
|---|---|---|
| Tampered artifact | sha256 at the agent and again on the runner's copy | Refused; `failed`; alert on repeat |
| Wrong signer (manifest) | Owner signature / vendor targets mismatch | Refused (`refused`), security alert |
| Wrong signer (package) | `pkgutil` team pin, Authenticode subject pin | Refused |
| Replayed older manifest | seq below the runner's committed seq | Refused unless it is the kept rollback package |
| Agent account compromised | — | Can only delay updates or force a rollback to the kept package; cannot choose bytes (above) |
| Coordinator compromised without the owner key | Owner signature missing | Nodes and the coordinator runner refuse |
| Download cut | Size/sha256 | Retried next heartbeat |
| Disk full | Free-space check before download (2× size) | `failed: disk`, not retried until space returns |
| Node offline mid-rollout | Heartbeat | `waiting(offline)`; catches up later |
| Node dies during install | Runner journal | Resumes at boot (`RunAtLoad`, path unit, helper start) |
| A job that never ends | `drain_timeout` | `deferred`, retried; never killed |
| MSI 1618 | Exit code | Retry later |
| MSI 3010/1641 | Exit code | Success, `reboot_pending` shown |
| MSI 1603 | Exit code | Transaction restored the old product; `failed` with the log |
| dpkg lock held | Lock wait | Wait 20 min, then `failed: busy` and retried |
| dpkg half-configured | `dpkg -s` | `dpkg --configure -a`, then the rollback |
| New agent never confirms | 600 s probation | Runner reinstalls the previous package |
| New launcher crash-loops | Probation (no confirmation) | Same |
| Coordinator migration fails | Self-test on a copy | Aborted before anything changes |
| New coordinator unhealthy | 300 s probation | Restore the copy, flip back |
| Power loss during the coordinator swap | Runner journal at boot | Resumes: rolls back unless committed |
| Bad release across the fleet | Canary budget 0, bake | Halt, roll back the canary |
| Fleet already unhealthy | Ring start gate | The rollout does not proceed |
| Wrong release started | T2 preview | Halt / roll back |
| Expired hold or pin | Tick | Flagged; the node rejoins |

## Interfaces

This section is the contract between the coordinator, the agent, the runners and the packages.

### Paths

| | macOS | Linux | Windows |
|---|---|---|---|
| `<system data>` | `/Library/Application Support/Oarbank` | `/var/lib/oarbank` | `%ProgramData%\Oarbank` |
| Agent home (system scope) | `<system data>/agent` | same | same |
| Agent spool | `<agent home>/updates/` (the agent's account, 0700) | same | same |
| Node runner state (root only) | `<system data>/update/` | same | same |
| Coordinator runner state (root only) | `<system data>/coordinator-update/` | same | same |
| Coordinator spool | `<coordinator home>/updates/` (`_oarbankd`/`oarbankd`) | same | same |

### Signatures

Owner statements are signed like every other owner statement (`signing.py`): Ed25519 over the UTF-8 bytes of the
statement text, base64. The statement text is JSON with sorted keys and `(",", ":")` separators.

```json
{"type":"oarbank.fleet-release/v1","version":"2.10.0","seq":21000,"manifest_sha256":"<hex of the manifest text>","signed_at":1760000000}
```

The manifest travels as its exact text. Everyone computes `manifest_sha256` over those bytes, so no party ever
re-serializes it. A signature object is `{"statement": "<text>", "signature": "<b64>"}`.

### The heartbeat directive (`node_update`)

The directive is `null` while the node is where it should be:

```json
{"release": "2.10.0", "seq": 21000, "go": true, "rollback": false, "drain_timeout_s": 1800,
 "artifact": {"name": "…", "format": "pkg|msi|deb|rpm|tar", "sha256": "…", "size": 1, "url": "/v1/updates/artifacts/<sha256>"},
 "manifest": "<text>", "signature": {"statement": "…", "signature": "…"} | null,
 "owner_anchors": {"statement": "…", "signatures": [{"key": "…", "sig": "…"}]} | null}
```

`GET /v1/updates/artifacts/{sha256}` serves only the artifact of the node's current directive (404 otherwise). It
uses the agent listener and mTLS, like `/v1/agent/builds/{sha}`.

### The agent's report (hello and heartbeat)

```json
"node_update": {"state": "idle|unsupported|staging|staged|draining|deferred|installing|confirming|done|failed|rolled_back|refused",
                "release": "2.10.0", "seq": 21000, "error": null, "at": 1760000000.0},
"install": {"format": "pkg|msi|deb|rpm|tar|dev", "scope": "system|personal", "updater": true, "why": null}
```

### Spool files (agent ↔ node runner)

- **`<agent home>/updates/package`:** the downloaded artifact. The agent writes it, and the runner only copies it.
- **`<agent home>/updates/request.json`:** `{"id", "release", "seq", "format", "sha256", "size", "manifest",
  "signature", "owner_anchors", "rollback", "requested_at"}`. The agent writes it last, atomically through a rename;
  its appearance starts the runner.
- **`<agent home>/updates/result.json`:** the runner writes it and chowns it to the agent's account.
  `{"id", "release", "state": "refused|installing|installed|done|rolled_back|failed", "error", "partial", "reboot_pending",
  "at"}`.
- **`<agent home>/updates/confirmed`:** `{"id", "release", "agent_version", "at"}`. The new agent writes it after its
  first hello and heartbeat.

The runner removes `request.json` when it has taken the request (journaled first). It ignores a request whose `id` it
has already finished.

When `result.json` says `installed` for its request, an agent of another version than the release exits 75, so the
launcher starts the agent `current` now points at (the tarball format has nothing else that restarts it, and a package's
own restart may come before `current` moved). An agent of the release the runner then rolls back exits 75 once, for the
same reason.

### Node runner files

- **`trust.json`:** `{"format": 1, "mode": "signed" | "unsigned", "fleet_id", "owner_version", "owner_keys": [b64…],
  "pinned_at", "pinned_by"}`. `unsigned` is only ever written by `update-trust --unsigned`.
- **`journal.json`:** `{"format": 1, "committed_seq", "committed_release", "current": {sha256, release, format},
  "previous": {sha256, release, format} | null, "active": {"id", "release", "seq", "sha256", "format", "rollback",
  "step": "verified|installing|installed|probation|committing|rolling_back", "deadline", "previous_agent"} | null,
  "finished": [the latest finished request ids]}`. `active` also keeps the step's bookkeeping: `error`, `outcome`
  (`rolled_back` after a failed probation, `failed` after a failed install), `restored` (the MSI transaction put the old
  product back), `busy` and `retry_at` (1618 or a held lock), `reboot_pending`.
- **`packages/<sha256>`:** two packages are kept.
- **`available`:** `{"format": 1, "mode", "fleet_id", "owner_version", "pinned_at"}`, written with `trust.json`. The
  state directory is 0711 and this file 0644, the one file the agent's account may read: it is how the agent knows the
  trust is pinned (`install.updater`). Its absence means no updater.

### Commands

```
oarbank-launcher update-run   [--agent-home P] [--state P] [--prefix P] [--probation-s N] [--once]
oarbank-launcher update-trust (--from-agent | --unsigned | --keys K1,K2 [--fleet F] [--owner-version N])
                              [--agent-home P] [--state P]
python -m oarbank.coordupdate run   [--home P] [--state P] [--programs P] [--probation-s N] [--once]
python -m oarbank.coordupdate trust (--from-home | --unsigned) [--home P] [--state P]
oarbankd --self-test --home <scratch>      (open, migrate, check invariants, exit 0/1; never listens)
```

The defaults are the system paths above. `--prefix` is where the `tar` format installs (Linux tarball installs:
`/opt/oarbank`); naming it also makes the runner treat the node as a tarball install, so `update-run` with explicit
paths works unprivileged (the tests). `--once` handles at most one request and exits, which the triggers use. Without
it, the command watches the spool, which the tests use. `--owner-version` is the explicitly pinned key set's version (1
when not given), which the next rotation must follow.

The agent finds the runner's marker at `<agent home>/../update/available`. Two environment variables let a test run the
runner itself: `OARBANK_INSTALL_FORMAT` names the agent's install format (else detected), and
`OARBANK_UPDATE_TRIGGER=external` says something other than a launchd, systemd or helper trigger runs `update-run`.

### Coordinator health and spool

- **`GET /v1/health`** (agent listener, no authentication): `{"version", "started_at", "migrated": true, "ticking":
  <a background tick within 30 s>, "role"}`.
- **`<coordinator home>/updates/coordinator-request.json`:** `{"id", "version", "sha256", "size", "archive":
  "updates/artifacts/<sha256>", "manifest", "signature", "snapshot", "from_version", "requested_at"}`.
- **`<coordinator home>/updates/coordinator-result.json`:** `{"id", "version", "state": "refused|done|rolled_back",
  "error", "at"}`.

## TLA+ (`specs/OarbankRollout.tla`)

The model has three nodes in two rings and a coordinator. Versions are 1 (old) and 2 (new).

**Actions:**
- `Start`;
- `CoordUpdate` (succeeds or rolls back);
- `Grant` (the slot rule);
- `NodeInstall` (succeeds, fails or rolls back);
- `GoOffline` / `Return`;
- `Finish` / `Bake`;
- `Halt`;
- `Rollback`;
- `Pause` / `Resume`.

**Invariants:**
- `CapRespected`: busy nodes per ring ≤ `MaxUnavailable`.
- `RingOrder`: no node of a later ring is busy or updated by this rollout before every earlier ring finished and baked.
- `NoNodeAheadOfCoordinator` (S30).
- `HaltedStartsNothing`: after a halt, no new `go`.
- `BudgetHalts`: failures above the budget imply halted or rolling back.
- `RolledBackIsOld`: a rolled-back rollout leaves every node it moved on the old version.

**Liveness:** with weak fairness and finitely many failures, every rollout ends `done`, `halted` or `rolled_back`.

**Weakened variants must fail:**
- `_a_nocap` (Grant ignores the cap) → `CapRespected`.
- `_b_noorder` (rings start without baking) → `RingOrder`.
- `_c_coordlast` (nodes before the coordinator) → `NoNodeAheadOfCoordinator`.
- `_d_nohalt` (failures do not halt) → `BudgetHalts`.

The runner's own commit-or-rollback is the second machine in the same spec (`RunnerSafe`: after the runner stops, the
node runs the new version confirmed or the previous one).

## Invariants

| # | Invariant |
|---|---|
| S29 | No ring of a rollout has more nodes between `draining` and `confirming` (or `staged` with `go`) than its `max_unavailable` |
| S30 | No node is assigned, or reports running, a fleet release newer than the coordinator's own version, and no node of a later ring started before every earlier ring of the rollout finished |
| S31 | Every node `go` was granted while the node was eligible: online, inside its window, not held, not pinned to another version (from the rollout journal: `rollout_nodes.go_at` with the eligibility recorded beside it) |

## Tests

- **Unit (Python).**
  - Manifest canonicalization, signing and verification, and refusals.
  - Import, with sha and size refusals.
  - Assignment: pins, holds, stops, skew.
  - Policy resolution and the managed tighten.
  - Every tick rule.
  - Coordinator update prepare and result handling; the `coordupdate` runner against a fake service layer (snapshot,
    swap, probation pass/fail, restore, crash recovery from every journal state).
- **Property (Hypothesis).** A rollout state machine over random fleets, rings, windows, holds, offline periods, install
  outcomes and operator actions. S29–S31 and the TLA+ invariants are checked after every step, and termination is
  checked with fair schedules.
- **Rust.**
  - The runner's state machine over a fake installer: every step's failure, crash and resume, and rollback with and
    without a kept package.
  - Trust checks: owner signature, seq, rollback, `unsigned`.
  - Request parsing as untrusted data.
  - The agent's `node_update` handling: staging, refusals, drain and defer, confirmation.
- **End to end (tests/rust).**
  - A real oarbankd and a real agent under a real launcher. The runner is triggered by the test harness (no root) with
    the `tar` format and a scratch prefix.
  - Two releases, a rollout to the second (confirmed), then a third whose agent crashes on start (rolled back, rollout
    halted, canary budget).
  - Resume after a runner crash mid-install.
- **Packages in CI (free runners).**
  - **Linux:** build the deb and rpm twice (two versions). Install the first in a Debian and a Fedora container, run
    `update-run` for the second (installed), then a rollback (the first again).
  - **Windows:** the MSI major upgrade and downgrade through `update-run` (msi.yml).
  - **macOS:** an unsigned pkg upgrade through `update-run` on the macOS runner (sudo), with the team pin off.
- **Regression.** The agent-only self-update suite still passes. A node without an updater keeps self-updating its
  agent. A manual package install now also makes the package's agent current: the package is the unit (D57).

## Owner-verified (needs the owner's machines)

- The signed and notarized pkg with the team pin through `update-run` on a real Mac.
- A real coordinator self-update on the owner's coordinator from 2.10.0 to a 2.10.1 test build, including a forced probation
  failure (restore).
- A Windows node's MSI update through the elevated helper.

## References

- Sparkle: sparkle-project.org/documentation (EdDSA, phased rollout, installer launcher).
- Chromium updater: chromium.googlesource.com/chromium/src/+/main/docs/updater/design_doc.md and functional_spec.md.
- Tailscale: tailscale.com/kb/1067/update, tailscale.com/kb/1384/auto-update (per-OS mechanisms, detached MSI).
- Fleet: fleetdm.com/docs/deploy/system-d-and-tuf (orbit, TUF channels).
- TUF specification: theupdateframework.github.io/specification/latest; Uptane standard: uptane.org/docs/latest/standard.
- pkgutil, installer(8), spctl(8); Munki wiki; Jamf docs on package installs.
- Mender state machine and ArtifactCommit: docs.mender.io; RAUC: rauc.readthedocs.io; SWUpdate: sbabic.github.io/swupdate.
- WiX MajorUpgrade: wixtoolset.org/docs/schema/wxs/majorupgrade; msiexec exit codes: learn.microsoft.com (MsiExec error
  codes 1618, 1641, 3010).
- systemd-run(1), systemd.path(5); Debian unattended-upgrades; dpkg(1), rpm(8).
- Kubernetes deployments (maxUnavailable, progressDeadlineSeconds) and version skew policy: kubernetes.io/docs; Argo
  Rollouts analysis: argo-rollouts.readthedocs.io.
- Google SRE workbook, "Canarying releases": sre.google/workbook/canarying-releases; AWS Builders' Library, "Automating
  safe, hands-off deployments"; Microsoft safe deployment practices (Azure).
- GitLab, Mattermost and Home Assistant upgrade and backup documentation.
