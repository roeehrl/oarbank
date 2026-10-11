# Workloads: supervised long-running daemons that are the work itself

Status: built in **core 2.10** and **oarbank-sdk 1.6** (PLAN D45, D46; invariants S26 and the widened S16). See
Implementation status at the end for what each operating system can and cannot do, and what is left to verify.

## The problem

Some fleet work is a long-running process that is the work: a node of a peer-to-peer network, a public inference
provider, a worker for a pool that pays per unit of work. Oarbank had two shapes for module processes, and neither fits:

- **Jobs** are finite attempts with leases, results, goldens and certification. A daemon never produces a result, must
  not be retried elsewhere (its identity belongs to one machine) and loses its standing if it is paused for long and then
  released after the ten-minute pause ceiling.
- **Services** are node helpers for jobs. They start for a job's pool or while the module is enabled, receive no secrets,
  no control document, no throttle and no pause, and host protection may only stop a `yieldable` one. Their process tree
  is tracked by process group only, which a daemon that calls `setsid` and forks twice leaves.

Protection could not act on anything it did not start (S16), so a daemon the owner ran by hand counted as the owner's
own load and could never yield to a protected process.

## The decisions

- **D45, workloads.** `[[workloads]]` is a third kind of module process, beside `[[services]]`: the earning unit
  itself. The owner assigns a workload to nodes (`workloads.assign`, T2, with a preview naming the node, the secrets it
  receives, the listeners it opens and the protection rules that act on it). The agent runs the workload's executable as
  one long-running process in the module sandbox, with the module's approved grants, in a process container of its own,
  gives it its listed secrets, the runner control document (`pause`, `threads`, `gpu_duty`, `stop`), a per-run home and
  an event file, restarts it with exponential backoff and full jitter, and withdraws it after `max_failures`. In host
  protection a workload is fleet work with its own ladder: stop admitting new seats, throttle, lower, pause only up to
  its declared `pause_tolerance_s`, then stop and hold for as long as the cause lasts. A workload survives an agent
  restart: the next agent adopts it when its seat lease is still valid and its process is the one recorded.

  **Owner-delegated external processes** (the design's option 4.4.7, accepted with its recommendation): behind the
  node setting `delegated_processes` (off by default, and a machine's managed policy can force it off), an owner rule may
  mark a matched process tree `delegate = {actions = ["pause", "lower"]}`. Protection may then pause and lower those
  processes for a protected process, as fleet work. Only matchers a module cannot spoof count (a code-signing identity on
  macOS, a publisher and path on Windows, an exact root-owned path on Linux), modules can never declare or widen it, every
  action is journaled, and `stop` is not offered in this version.

- **D46, single-seat identity.** A workload with `identity = "per_node"` runs only under a coordinator **seat lease**
  with a **fence**. Its seat is named by the keyed fingerprints of the secrets it receives on that node, so two nodes
  given the same key compete for one seat, and at most one node runs an identity at a time (S26; TLA+
  `specs/OarbankSeat.tla`). The lease is 30 minutes, renewed in every heartbeat reply; the agent stops the workload when
  its lease lapses on its own clock, and the coordinator moves a seat only after the holder reported it stopped (with the
  fence) or after the lease and a grace period have passed.

Rejected: a `kind` on services (every service rule would grow exceptions: pools, `on_demand`, endpoints for jobs);
killing a daemon that leaves its process group on macOS instead of tracking it (the daemon is the work: a module whose
third-party daemon double-forks would never run); container workloads in this release (on macOS the container runs in
the Colima VM, so an inbound listener would need a VM-side port forward: deferred until host-process workloads have run
for a release); an agent-side egress filter for Linux (Linux nodes run only workloads whose network mode they enforce:
`none` and `egress-allowlist`; `egress-any` workloads are placed on macOS and Windows nodes only).

## The manifest (SDK)

```toml
[requires]
core = ">=2.10"
workload_protocol = [1]

[[workloads]]
name = "worker"
exec = ["python", "-I", "{bundle}/worker.py"]   # usually the SDK's supervisor shim; the agent appends `run` or `status`
seat = "node"                     # "node": one per assigned node; "fleet": the owner asks for a count, the coordinator places
identity = "per_node"             # the seat is named by this node's secrets; at most one node runs it (D46). Or "none"
secrets = ["signing_key"]         # delivered to this workload only (an owner-only file, deleted when the run ends)
listeners = []                    # inbound listeners it serves (inbound-listeners.md); needs [sandbox].net.inbound
resources = { cpu_cores = 2, mem_gb = 6 }
gpu = { use = "none" }            # or { use = "shared", apis_any = ["metal"] }
control = ["cooperative_throttle", "cooperative_pause", "freeze_ok"]
pause_tolerance_s = 20            # the longest pause its peers survive; protection stops it instead of pausing longer
stop_timeout_s = 30               # from the stop request to the kill
restart = { backoff_initial_s = 10, backoff_max_s = 600, max_failures = 5, jitter = "full" }
health = { period_s = 15, timeout_s = 5, failures = 3 }   # the `status` op; omitted: the process existing is health
reports = true                    # its `report` events reach the module's `workload.report` verb on the coordinator
platforms = []                    # only on these platforms (empty: every declared one)
```

Rules (SDK manifest rule 23; errors in `oarbank-sdk check`, at install and in the catalogue):

1. Names are unique among workloads and services (both appear as `<module>/<name>` in node reports).
2. `identity = "per_node"` needs at least one secret in `secrets`; every secret listed is a declared one, each once.
   The owner sets each per node (a value set for a group or the whole module is refused for such a workload at
   assignment: two nodes would hold one identity).
3. `gpu.use` other than `none` needs `[sandbox].devices.gpu = "compute"`; `gpu.apis_any` needs `use` shared or
   exclusive and places the workload as it places services (D38).
4. `pause_tolerance_s` defaults to 0 for a workload that declares neither `cooperative_pause` nor `freeze_ok` (such a
   workload is never paused: it is throttled where it can be, lowered, or stopped) and to 20 otherwise; it is at most
   600 (the pause ceiling).
5. `listeners` name `[sandbox].net.inbound` entries (inbound-listeners.md).
6. `reports = true` needs the coordinator capability `workload.report`, and the capability needs a workload with it.
7. Workloads need `requires.workload_protocol` and `requires.core >= 2.10`.
8. A workload whose network mode is `egress-any` is placed on macOS and Windows nodes only (Linux cannot enforce it,
   D30); the lint warns when a module's platforms include Linux.

## Assignment, seats and leases (coordinator)

Two tables (`coordinator/workloads.py`):

```sql
workload_assignments(module, workload, node_id, desired, assigned_at, assigned_by, placed_by, restart_seq,
                     unassigned_at, version)          -- one row per (module, workload, node); unassigning keeps the row
workload_seats(seat_id, module, workload, node_id, fence, lease_until, granted_at, released_at)
workload_status(module, workload, node_id, running, seat_id, fence, report_json, at)   -- each node's latest report
workload_reports(module, workload, node_id, seq, t, seat_id, fence, data_json, state, error, received_at)
```

- **Assign** (`workloads.assign`, T2, admin, preview): `{module, workload, node}` for `seat = "node"`, or `{module,
  workload, count}` for `seat = "fleet"`, which places the seats once, on the eligible nodes with the most free memory
  (module enabled there, platform declared, sandbox enforced, network mode enforceable, not yet assigned). The
  coordinator never moves a seat on its own. The preview names each node, the secrets it will receive (by fingerprint,
  never values), the listeners it opens and the protection rules that match on the node.
- **Unassign** (`workloads.unassign`, T1, operator) and **restart** (`workloads.restart`, T1, operator: bumps
  `restart_seq`, which also lifts a withdrawal).
- **Seat identity.** `identity = "none"`: no lease; the agent runs the workload while it is assigned. `identity =
  "per_node"`: the seat id is `s_` and the first 16 hex digits of SHA-256 over the module, the workload and the keyed
  fingerprints (modsecrets.py) of the workload's secrets as resolved for the node. A secret with no value, or one whose
  value comes from a group or the module scope, leaves the seat unstarted (`WORKLOAD_SECRETS_NOT_SET`,
  `WORKLOAD_IDENTITY_SHARED`).
- **Lease.** At every hello and heartbeat of node N, for each of its assignments that is runnable: if the seat is free,
  held by N, or its lease ended more than the grace (60 s) ago, it is granted (or renewed) to N: a new holder raises
  the fence by one; `lease_until = now + 1800`. Otherwise N gets no lease (`WORKLOAD_SEAT_ELSEWHERE`).
- **Release.** A report from the holder that the workload is not running **and gives the seat up** (`release: true`:
  the agent was told to stop it, its lease lapsed there, it was withdrawn or cannot run there), carrying the seat's
  current fence, frees the seat at once; a report with an older fence, or without `release`, is ignored. So a seat moves
  without waiting for the lease when the old node confirms. (Freeing on any stop report from a holder that is no longer
  assigned is unsafe: the TLA+ model's finding F1, below.)
- **Directive** (every hello and heartbeat reply): `workloads: [{key, module, workload, desired, seat_id, fence,
  lease_s, restart_seq, reason}]`, one entry per assignment of the node. `desired` is `running` only for a runnable
  assignment with its lease (or no identity); otherwise `stopped` with the reason code. `lease_s` is the lease's end
  minus the coordinator's now when it wrote the reply.
- **Secrets** reach the agent only on request, at each start: `POST /v1/agent/workloads/secrets {key, seat_id, fence}`
  answers `{secrets: {name: value}}` when the node holds the seat with that fence and its lease runs (409
  `seat_not_held` otherwise; 409 `secrets_not_set`). Never in a directive, a report or a log.

## The agent

### Running a workload

`rust/crates/oarbank-agent/src/workloads.rs`. Every protection tick (2 s) the agent compares what the directives want
with what runs, and starts or stops on worker threads (a start waits for the sandbox launcher's confinement signal; a
stop waits up to `stop_timeout_s`), so the tick never waits.

A workload starts when it is listed `running`, its lease runs (identity `per_node`), the module is in the node's release
for this platform, the sandbox and the workload's containment are available, the machine's managed policy allows
workloads, protection does not hold it and admits work, it is not withdrawn and its backoff has passed, and its secrets
arrived. Then the agent:

1. makes a fresh run directory `<module data>/workloads/<name>/run-<n>` (the per-run home and cwd, deleted when the next
   run starts) and the workload's private directory `<home>/run/workloads/<module>/<name>/` (the control document, the
   secrets file, the settings, tools and limits files, the sandbox profile; read-only to the workload);
2. writes the secrets to `secrets.json` there, owner-only from the first byte (POSIX 0600, a protected DACL on Windows),
   deleted when the run ends;
3. runs `<exec> run` through the sandbox launcher in a lasting process container (`sys::spawn_workload`), with
   `OARBANK_WORKLOAD`, `OARBANK_WORKLOAD_RUN`, `OARBANK_MODULE_DATA`, `OARBANK_CONTROL_FILE`, `OARBANK_EVENTS_FILE`,
   `OARBANK_SECRETS_FILE` (when it has secrets), `OARBANK_SETTINGS_FILE`, `OARBANK_TOOLS_FILE`, `OARBANK_LIMITS_FILE`,
   `OARBANK_NODE_ID`, `OARBANK_SEAT_ID` and `OARBANK_SEAT_FENCE`, the egress proxy for an allowlist, the control event on
   Windows, and the endpoint channel (`OARBANK_ENDPOINT_CHANNEL`) when it serves listeners; stdout and stderr go to
   `<home>/logs/workloads/<module>.<name>.log` (appended; kept under 4 MiB, the older part in `.1`);
4. registers the container's leader in the spawn registry with the workload's key (S16) and writes its record,
   `<home>/state/workloads/<module>.<name>.json`: the leader's pid and start time, the members seen, the seat and fence,
   the lease's end on the boot clock and the boot it belongs to, the run number.

The sandbox policy is the module's (read-only bundle, interpreter, runtime and approved tools; read-write the module's
data directory; the module's network grant), plus the private directory read-only. A workload never gets the broker.

**Run end.** The container's leader is the workload. When it exits the run has ended: whatever is left in the container
is killed, the secrets file is deleted, and unless the agent asked it to stop it is a failure (backoff `min(max,
initial x 2^(n-1))`, full jitter: a uniform delay between 0 and that, AWS-style; withdrawn after `max_failures`, until a
restart operation, a new module version or a reassignment).

**Health.** With `health` declared, the agent runs `<exec> status` (sandboxed, the same environment) every `period_s`
with `timeout_s`; it prints `{"healthy": bool, "detail": "..."}`. `failures` consecutive unhealthy answers (a timeout,
a non-zero exit or `healthy: false`) end the run as a failure. Without `health`, a running process is healthy.

**Control.** The runner control document (runner-protocol.md, "Control"), at `OARBANK_CONTROL_FILE`, replaced
atomically with a rising `seq`, nudged by SIGUSR1 to the leader (POSIX) or the inherited control event (Windows). A
workload also re-reads it at least every 2 s, because an adopted workload's event is gone on Windows. `stop: true` asks it
to exit; after `stop_timeout_s` the container is killed.

**Events.** The workload appends JSON lines to `OARBANK_EVENTS_FILE` (`<run>/events.ndjson`): `{"type": "progress",
"event": "...", "n": 1}`, `{"type": "error", "message": "..."}`, `{"type": "report", "data": {...}}`. The agent tails it:
progress counts appear in the heartbeat (the co-tenancy harness reads them), errors become the run's last error, and
reports (at most 4 KiB each, 60 a minute, 200 queued) go to the coordinator in heartbeats, acknowledged by sequence
number, and on to the module's `workload.report` verb, whose answer is effects (`store.write`, `files.write`): a
workload's observations reach the module's own records without a scheduled job (the design's generic gap 1).

### Containment: what each OS can and cannot do

| Concern | macOS | Linux | Windows |
|---|---|---|---|
| The container | the leader's process group, **plus every process of the agent's account that the sandbox says runs with this workload's profile** (below) | the delegated cgroup leaf `c<leader>` (setsid cannot leave a cgroup); without a delegated cgroup workloads are not offered (`WORKLOAD_NO_CONTAINMENT`) | a named Job Object, `Local\oarbank-workload-<hash>`, never kill-on-close, breakaway refused |
| A daemon that calls `setsid` and forks twice | tracked: found by its sandbox identity and treated as a member (paused, lowered, stopped with the rest) | stays in the cgroup | stays in the job |
| Pause | SIGSTOP to the group and to each tracked member | `cgroup.freeze` | suspend every member of the job (`NtSuspendProcess`, undocumented, thread by thread) |
| Throttle | the `threads` hint only (no hard cap) | `threads` and `cpu.max` | `threads` and the job's hard CPU rate cap |
| Lower | background QoS for every member | the leaf's background quota | idle priority class and EcoQoS |
| Stop | SIGKILL to the group and each tracked member | `cgroup.kill` | `TerminateJobObject` |
| Adoption after an agent restart | the leader by pid and start time; members found again by identity | the leaf survives a restart by the launcher; a stop of the agent's systemd unit kills the unit's whole cgroup, workloads included (the next agent starts them again) | the job opened again by name |
| `egress-any` | enforced | unavailable (D30): such workloads are not placed on Linux | enforced |
| Keychain, Secure Enclave, App Attest | denied by the sandbox: a daemon that needs them cannot be a workload (it can be a delegated external process) | n/a | AppContainer has no access to the user's DPAPI secrets |
| Listening | refused by the sandbox (no bind rule): a workload never listens; it serves listeners through its endpoint channel | refused (seccomp) | refused (no server capability) |

**macOS sandbox identity.** macOS has no kernel container an unprivileged agent can use, and a process can leave its
process group, but it cannot drop the Seatbelt profile it inherited. Each workload's profile is the only one that
grants reading its private directory. While a workload runs, every tick, the agent lists the processes of its own
account outside every registered container and takes one as the workload's member only when all of these hold:

1. it is sandboxed (`sandbox_check(pid, NULL)`) and was born after the run's leader;
2. its sandbox lets it read the workload's control document (`<private>/control.json`), and does **not** let it read
   `<private>.canary`, an existing file beside the private directory that no profile of a module grants;
3. its sandbox lets it write the run's events file, and does **not** let it write the control document.

The canary is a sibling, and exists, on purpose: a first version compared with a path elsewhere that did not exist,
and the end-to-end test caught system services of the account (Safari's safe-browsing service, a GPU helper of an
Electron app, a context store agent) whose profiles read every existing file of the user's temporary directory, so they
passed; protection's pause reached them for 8 s before the resume (journaled `actuation` records, all resumed, none
killed). With the sibling canary and the write checks, no process of the account but the workload's own answers so
(checked against every process of a loaded workstation, about 1,100), and the spawn registry refuses a member born
before its container's leader. A tracked member's pid and start time go into the run's record; every action on the
workload reaches it through the registry, which checks the start time before each signal.

Upfront check (the design's phase 0 spike b): `sandbox_check` answers for another account's process from an
unprivileged account. Tested on macOS 27.0.1: from a user account it answered for all 168 processes of root and the
system accounts (106 sandboxed, 62 not), and answered a `file-write-data` path query for each sandboxed one (6 allowed,
100 denied), with `errno` 0 throughout; `proc_pidinfo` for those processes failed, so the uid of another account's process
comes from `sysctl` (`kinfo_proc`), as the protection crate already reads it. The detector itself needs only the
agent's own account (module processes run as the agent's account), where every call is permitted.

Upfront check d (a firewall prompt on a daemon's first listen), as it concerns workloads: a workload cannot listen at
all. The sandbox refuses `bind` and `listen` before the Application Firewall is consulted (tested: a workload process
that tries to listen gets `EPERM` and no prompt appears), so a workload can never raise a firewall prompt. Whether the
**agent's** own listener raises one is the inbound listener's check (inbound-listeners.md).

### Seat leases on the node

The agent keeps each lease on a **boot clock** that runs during sleep (macOS `CLOCK_MONOTONIC`, Linux `CLOCK_BOOTTIME`,
Windows `GetTickCount64`), never on its wall clock and never on a monotonic clock that stops while the machine sleeps
(Rust's `Instant` does both on macOS and Linux): a machine that slept for two hours must see two hours pass. A lease
ends at `sent + lease_s`, where `sent` is when the agent sent the heartbeat that the reply answered, which is no later
than the coordinator's own end. On the end, the workload is stopped (`WORKLOAD_SEAT_LEASE_EXPIRED`) and its report says
so with the fence. A directive that no longer lists the workload, lists it `stopped`, or names another seat or a higher
fence for it stops the current run first.

### Adoption across agent restarts

A graceful stop of the agent (SIGTERM, the launcher's stop event) stops jobs but **not** workloads, as with lasting
services (architecture.md, "Stopping the agent"): their records stay and the watchdog that ends a dead agent's runners
ignores them. A new agent reads each record before its first hello and adopts the workload when (a) the leader still
has its recorded start time, (b) the record's boot is the current boot and its lease's end on the boot clock is still
ahead, and (c) the workload does not serve listeners (its endpoint channel ended with the old agent). Then it registers
the leader again, finds the members again (macOS by identity, Linux in the leaf, Windows in the job opened by name) and
reports the workload running with its fence at hello, which renews the lease. Otherwise it stops what the record names
(only processes that still have their recorded start times) and starts the workload afresh once a directive asks for it.

### Protection on workloads

A workload is fleet work: its processes join `fleet_pids` and its declared resources count against the node's capacity
(`resources.cpu_cores`, `resources.mem_gb`). The controller (`oarbank-protection`, `workloads.rs`) takes each running or
held workload as a `FleetWorkloadView` (key, pausability, `pause_tolerance_s`, cooperative throttle, GPU use,
footprint) and returns a plan per workload. The ladder, under the same constraint vector as all fleet work (S18
unchanged):

1. **Not admitted**: a workload that is not running does not start while the combined constraint admits no work, or
   pauses work of its kind (a rule's `pause_fleet` scope, GPU work not allowed for a GPU workload).
2. **Throttle**: while the controller's CPU budget binds, the workload gets its share as the `threads` hint
   (`cooperative_throttle`) and, on Linux and Windows, as a hard CPU cap on its container.
3. **Lower**: as jobs are lowered (a rule's `lower_fleet`, the controller's emergency rung).
4. **Pause**: when the controller would pause it (a pause scope, the emergency ladder) and it is pausable
   (`pause_tolerance_s` above 0): by freezing its container (`freeze_ok`) or through its control document
   (`cooperative_pause`). Paused continuously for `pause_tolerance_s`, it is stopped and held
   (`WORKLOAD_PAUSE_TOLERANCE`). A workload that cannot be paused is lowered instead, as a job that cannot be paused is.
   The pause probe never pauses a workload.
5. **Stop and hold** for as long as the cause lasts: the memory guard's victim (held until the guard is clear), a rule's
   `evict` (held while the rule is active), a pause beyond the tolerance (held while the workload would still be
   paused), GPU work not allowed for a GPU workload that cannot be paused. When the cause clears it starts again after
   `restart.backoff_initial_s` (a hold is not a failure).

Every action is journaled with the workload's key (`WORKLOAD_PAUSE`, `WORKLOAD_RESUME`, `WORKLOAD_LOWER`,
`WORKLOAD_RESTORE`, `WORKLOAD_THROTTLE`, `WORKLOAD_HOLD`, `WORKLOAD_RELEASE`, `WORKLOAD_PAUSE_TOLERANCE`), and every
signal and scheduling change goes through the spawn registry (`actuation` records carry `workload`).

### Delegated external processes

With the node setting `delegated_processes` on, an owner rule with `delegate = {actions = [...]}` names processes that
protection may treat as pausable, lowerable fleet work. Its matcher must be one a module cannot spoof, refused per OS
otherwise (protection.md): macOS a code-signing identity (`requirement`, or `team_id` with `identifier`); Linux and
Windows `path_prefix` naming one executable's exact path, trusted at every match (Linux: the file and every directory
above it owned by root and writable by no one else; Windows: under Program Files or the Windows folder; Authenticode
publishers are not read by the protection crate, so they are not offered). An unreadable fact never delegates. A
delegate rule has no other action; `actions` is a subset of `pause` and `lower` (`stop` is refused in this version).
Each matched process is acted on one at a time, never by group, through the spawn registry (`signal_delegated`,
`set_background_delegated`: its start time checked first, journaled with the rule as `delegated`). A delegated tree
paused for the pause ceiling (10 min) is resumed and lowered instead (`DELEGATE_PAUSE_LIMIT`), since it may not be
stopped. A system install's agent cannot signal the person's processes: when its own action is refused, the person's
session helper does it on the agent's request (`SessionHub::act`, on the helper's connection; the helper checks the
process still has the start time named and acts only with `pause`, `resume`, `lower` and `restore`), journaled
`via: session_helper`. With the setting off delegate rules match nothing (the setting's change is journaled). On
stopping, the agent resumes and restores everything it paused or lowered.

S16 becomes: **the agent never signals or reschedules a process outside its spawn registry (its attempts, services and
workloads, a workload's tracked members) or the owner's delegations.**

## Failure modes

| Failure | Behaviour |
|---|---|
| The daemon crash-loops | backoff with full jitter; withdrawn after `max_failures` (it gives its seat up); alert `workload_withdrawn` with the last error and log tail, cleared when it runs again; `workloads.restart` lifts it |
| The agent dies and does not come back | its watchdog (`reap-runners`, which ends a dead agent's runners) then guards the leases: each workload the dead agent's records name is ended when its lease runs out, unless a newer agent adopted it (adoption rewrites the record) |
| The daemon daemonizes itself | the leader stays (the SDK supervisor shim keeps the daemon in the foreground); a grandchild that leaves the group is tracked (macOS) or stays in the cgroup or job; if the leader exits, the run ends and everything else is killed; the conformance suite fails a workload that leaves its process group |
| Agent restart | adopted when the lease runs on the boot clock and the leader is the recorded process; listener-serving workloads restart |
| Coordinator outage | workloads keep running until their lease ends (30 min); identity `none` keeps running |
| Node sleep | the boot clock counts the sleep; on wake the agent sends hello, renews or stops |
| A secret not set for the node, or set for a group | `WORKLOAD_SECRETS_NOT_SET` / `WORKLOAD_IDENTITY_SHARED`; the seat stays unstarted |
| Two nodes given the same key | one seat: the second shows `WORKLOAD_SEAT_ELSEWHERE` |
| Pause beyond the tolerance | stop and hold; `WORKLOAD_PAUSE_TOLERANCE` |
| Linux without a delegated cgroup | not offered: `WORKLOAD_NO_CONTAINMENT` |
| Managed policy `workloads = false` | not offered, running ones stopped: `WORKLOAD_POLICY_OFF` |

## Security

| Threat | Defence |
|---|---|
| A workload reads another module's secrets or the owner's files | the module sandbox, unchanged; the secrets file lives in the workload's private directory, which only its profile can read (not the module's other stages), owner-only, deleted when the run ends |
| A workload outlives a stop | Linux cgroup and Windows Job Object; macOS sandbox identity (a process cannot drop its profile); kills verify start times |
| A compromised coordinator runs a workload on an unexpected node | assignment is a T2 owner operation with audit; a listener also needs the node's owner-signed statement (inbound-listeners.md); the module's grants are approved by digest as for any of its processes |
| Duplicate identities | seat lease with fence, seats named by key fingerprints (D46, S26, TLA+) |
| A module widens delegation | delegation lives only in the owner's protection rules, behind a node setting a managed policy can force off; matchers a module could spoof are refused |
| The helper acts on someone else's process | it acts only on its own account's processes (the kernel enforces it) and checks each start time |

## Operations and reason codes

| Operation | Tier | Role |
|---|---|---|
| `workloads.assign` | T2 (preview) | admin |
| `workloads.unassign` | T1 | operator |
| `workloads.restart` | T1 | operator |

Reason codes (category `workload`): `WORKLOAD_UNASSIGNED`, `WORKLOAD_SEAT_ELSEWHERE`, `WORKLOAD_SEAT_LEASE_EXPIRED`,
`WORKLOAD_HELD`, `WORKLOAD_WITHDRAWN`, `WORKLOAD_PAUSE_TOLERANCE`, `WORKLOAD_SECRETS_NOT_SET`,
`WORKLOAD_IDENTITY_SHARED`, `WORKLOAD_NO_CONTAINMENT`, `WORKLOAD_POLICY_OFF`, `WORKLOAD_NOT_OFFERED` (the module is not
in the node's release for its platform, or the node cannot enforce its network mode). Protection journal reasons listed
above, and `DELEGATE_PAUSE`, `DELEGATE_RESUME`, `DELEGATE_LOWER`, `DELEGATE_RESTORE`, `DELEGATE_PAUSE_LIMIT`.

## Console and CLI

- The module page has a **Workloads** tab: each workload's assignments per node, seat, fence and lease, state, last
  restart and error, the log tail, the protection actions on it in the last 24 h, and Assign / Unassign / Restart.
- The node page has a **Workloads** card: what runs here, held or paused and why, the lease left.
- `oarbank workload list [--node N] [--module M]`, `oarbank workload assign <module>/<workload> (--node N | --count C)`,
  `oarbank workload unassign <module>/<workload> --node N`, `oarbank workload restart <module>/<workload> --node N`,
  `oarbank workload logs <module>/<workload> --node N [--follow]`.

## The TLA+ model (`specs/OarbankSeat.tla`)

One seat and two nodes; a global discrete clock (lease length L, grace G); the coordinator's durable holder, fence
and lease end and the owner's assignments (assign and unassign at any time, two nodes at once included); requests and
replies in a bag with arbitrary delay and loss; an agent that sends a heartbeat while an earlier one is still in flight
(impatient), crashes and restarts with adoption, a machine that sleeps (time passes, the node takes no step) or
reboots (the workload dies), a coordinator restart (in-flight messages lost). The agent's lease ends at the request's
send time plus `lease_s`; time cannot pass a running workload's lease end on an awake node (it acts in time); a node
whose agent is down gets it back before the lease ends unless `AgentDownPastLease`.

Properties: **AtMostOneRunning** (no two nodes run the seat at once; S26), **RunningHasLease**, **FenceMonotonic**,
and, under bounded faults and a timely network, **EventuallyRuns** (a node that stays assigned runs) and
**SeatReGranted** (a seat its holder gave up reaches another assigned node). Weakened variants, each of which TLC
shows violating AtMostOneRunning: (a) freeing on any release report whatever its fence; (b) the agent applying a late
reply to a request it gave up on, after its lease lapsed; (c) re-granting before the lease and grace end without a
release; (d) the lease measured from the reply's receipt instead of the request's sending; (e) adopting a workload
without its lease; (f) a lease clock that stops while the machine sleeps. Witness configurations show that a seat
moves after an expiry, moves early on a fenced release, and that a restart adopts.

Two findings changed the design. **F1**: freeing a seat on a stop report *without* `release` from a holder that is no
longer assigned is unsafe (a stale stop report frees a seat its sender runs again after a reboot); the coordinator now
frees only on `release` with the current fence, and the agent sends `release` whenever it was told to stop (the model's
alternative, a fence per run, also passes: `OarbankSeat_fence_per_run`). **An agent down past its lease** leaves a
lasting workload running after the seat moved; the dead agent's watchdog now ends recorded workloads at their leases'
end. `./run_tlc.sh OarbankSeat` checks every configuration (`QUICK=1` skips the unbounded-fault one).

## Invariants

- **S26** at most one node runs a seat of a `per_node` identity at a time: no two nodes' latest reports (within the
  lease) say one seat is running, and every report of a running seat carries the fence of the node holding it.
- **S16** (widened) every journaled actuation targets one of the node's own attempts, services or workloads, or a process
  an owner rule delegated.

## Implementation status

Built in core 2.10 and SDK 1.6, verified by unit and property tests (the ladder, the lease on a virtual boot clock, the
backoff), the TLA+ model `specs/OarbankSeat.tla` with its weakened variants, a protection soak with workloads mixed with
jobs and services, and an end-to-end test (`tests/rust/test_agent_workloads.py`) in which a synthetic workload whose
daemon calls `setsid` and forks twice is assigned, paused and held by protection rules, survives an agent restart by
adoption and is unassigned. Cross-platform builds are checked for Linux and Windows; the Linux cgroup and Windows Job
Object paths run in CI on those systems.
