# Host protection

A node runs fleet jobs beside its owner's own work. Protection decides, every few seconds, how much fleet work the
machine may run without harming that work (PLAN D3, D3a–D3d, D20). The owner sets it per node; modules can never
declare or loosen it.

- **The contract** is `oarbank.contracts.protection` (schema 1, `schemas/protection-config-1.schema.json`), with a
  worked example in `src/oarbank/contracts/fixtures/protection-example.toml`.
- **The engine** is the agent's `oarbank-protection` crate: a pure decision core over process, meter and owner sources,
  with a native backend per OS (macOS, Linux and Windows).
- **The central copy** is the `protection` section of the node's policy, edited in the console (versioned, with restore
  and canary). **The local copy** is `protection.json` beside the agent's home on the node. The agent unions both, and
  the stricter setting wins on every dimension, so the two never conflict.

## Authority: only the fleet's own processes

The agent signals, lowers or pauses only processes in its spawn registry (a pid plus its start time, or a descendant of
one). The action vocabulary has no verb whose target is a protected process, and the schema no field that could name
one (S16). Unknown processes are never signalled; their memory always counts.

## Whose processes

The owner's processes are those of the agent's own account (the personal scope runs as the person) and, for a system
install, of the people using the machine: on macOS every account a session helper reports for (each GUI login runs
one); on Linux every person logged in (systemd-logind's user sessions) or reporting through a session helper; on
Windows each person's own processes in their session. A system install's agent runs as a service account that may not
read everything about another account's processes: on macOS their arguments, CPU time, footprint and scheduler
counters (rusage) and the app in front of their session; on Linux their executable path and open files (ptrace
access); on Windows their command line (a process handle); and on Linux and Windows their display and input. A
**session helper**, the agent's binary run as the person in their session (`oarbank-agent session-helper`: a
LaunchAgent loaded in every GUI login on macOS, a global systemd user unit on Linux, started by the elevated helper
service on Windows), reports those facts every two seconds over a local endpoint the agent serves
(`/Library/Application Support/Oarbank/run/session.sock`, `/run/oarbank/session.sock`, `\\.\pipe\oarbank-session`):
the person's processes with their paths and arguments, their resource use (macOS, read back as of one report ago and
interpolated between reports, so rates never jump with the reports' timing), their GPU use (Linux), the front app or
window (macOS, Windows) and the last input (Windows). The endpoint names the account or session that sent a report
(the Unix socket's peer credentials, the pipe client's session), the agent accepts claims only about processes of that
account or session that started when the claim says, and it forgets a helper ten seconds after its last report. A
process of a person whose helper reports is listed once the helper has described it, at most one report after it
started; until then it would match every rule whose facts only the helper can read. A helper can only describe its own
person's work. Without one, those facts are unreadable and the fail-safe rules apply; on Windows the system's own
processes in that person's session then count as the owner's too. On macOS a person without a helper (logged in only
over ssh, or before their helper's first report) is not seen; when that is the console's account, the front app reads
as unknown, which counts as in front and shows as a node condition. The macOS service reads the rest itself: every
account's processes and paths (`sysctl kern.proc`, libproc), code-signing identity, GPU time and the HID idle time.

## Modes

A node's mode selects a controller profile. It changes thresholds and triggers, never authority; owner rules bind in
every mode, and the node's pause switch (`desired_state`) stays separate.

| | `fleet_first` | `moderate` (new nodes) | `strict_yield` |
|---|---|---|---|
| Meaning | Fleet jobs are the most important work here | Use spare capacity, back off when the owner's work shows harm | Fleet work is a scavenger |
| Triggers | Owner rules and the system guards | Also the implicit owner-stall signal | Also user presence and any active protected process |
| Admission | Up to allocatable (capacity minus the OS reserve, service and rule reservations, and what is allocated) | Same, with the fleet CPU budget grown by AIMD only while every protected metric is healthy | Only after the user has been idle for 15 min with nothing protected active, ramping one slot a minute |
| Throttling | Only what a rule demands | Lower, then caps (cooperative throttle) | None: straight to pause |
| Eviction | Memory guard and a rule's `evict` | Also a job paused longer than 10 min | Same as `moderate` |

## Rules

A rule has a matcher, a tree scope, an activity condition, actions and timing.

- **Matchers:** code-signing identity (Team ID and signing identifier, or a designated requirement), bundle id, path
  prefix or substring, and an argv pattern. A signature survives updates and relocation; a path does not; argv is the
  only way to tell one interpreter's script from another's. A key whose fact the agent cannot read (another account's
  path or arguments) counts as holding, so a failed lookup never leaves a process unprotected; a rule's report counts
  the processes it matched that way (`unreadable`). The console's process picker writes the matcher from the
  processes a node reports, and its preview uses a Python matcher held equal to the agent's by shared test vectors
  (`fixtures/protection-match-vectors.json`).
- **Trees:** `self`, `descendants` (pid and parent tracking) or `same_team` (helpers signed by the same team).
- **Activity:** `present`, or thresholds on CPU cores (`cpu_cores_gt`), footprint (`footprint_gb_gt`) or GPU activity
  (`gpu_active = { min_busy = 0.05 }`), or `frontmost` (true: the app in front is one of the group's processes; false:
  the group runs but is not in front), held `for_s`; any one that holds activates the rule. A front app that cannot be
  read counts as in front either way, never looser; with nothing in front (nobody at the machine's desktop) no group is
  in front. macOS asks `lsappinfo` in the console's session (the system service through that account's session helper;
  at the login window nothing is in front); Linux takes the session logind has in front on the seat: an X11 session's
  active window (EWMH `_NET_ACTIVE_WINDOW` and its `_NET_WM_PID`, read with the session's Xauthority cookie), a text
  console's foreground process group; a Wayland compositor tells no other program which window is in front, so there it
  is unknown. Windows takes the console's session from WTS (locked: nothing in front) and its foreground window, which
  only a process in that session may ask for (a packaged app's frame is resolved to the app inside it). The session
  manager refuses WTS to the system service's virtual account, so the service asks the elevated helper, which reads
  the same session list as LocalSystem (`{"op": "sessions"}` on its pipe); without either the front and presence are
  unknown.
- **GPU activity** is the group's GPU busy seconds per second over the last sample interval, summed over its processes
  and the GPU's engines (so two busy engines can pass 1); `min_busy` defaults to 0.05. Each OS reads accumulated GPU
  time per process: macOS from the AGX driver's user clients in the IORegistry, Linux from the DRM `fdinfo` of every GPU
  file a process holds (`drm-engine-*` nanoseconds, or `drm-cycles-*` over `drm-total-cycles-*` on xe; amdgpu, i915, xe,
  msm, panfrost and the other drivers that write usage stats) and, for NVIDIA's proprietary driver, which writes none,
  from NVML (`libnvidia-ml.so.1`, opened at run time: each GPU's compute and graphics processes, and their SM
  utilization over the driver's last sample period, averaged over the samples since the previous reading and accumulated
  over the interval), Windows from the raw `GPU Engine` performance counters (running time in 100 ns per process,
  adapter and engine). Usage that cannot be read counts as busy, never looser: the first reading after start (no
  baseline yet), a missing source, a process holding a GPU that reports no per-client counters (NVIDIA's `/dev/nvidia*`
  where NVML does not load, a GPU older than Maxwell that keeps no per-process utilization, AMD's `/dev/kfd`, a kernel
  before 5.19) and another user's process whose open files the agent cannot read.
- **Actions** (fleet-side only): `reserve` (cores and memory, as expressions over measured peaks such as
  `peak(300s).footprint + 2`), `cap_fleet` (slots, cores, threads, staging bandwidth, GPU jobs), `lower_fleet` (fleet
  jobs to background scheduling: macOS background QoS, low priority on the efficiency cores; on Linux a CPU quota of a
  tenth of a core on the job's cgroup, since the agent's cgroup and the owner's are scheduled apart and no class an
  unprivileged agent can set yields to the owner; on Windows the Job Object's idle priority class with EcoQoS; where it
  cannot be done, Linux without a delegated cgroup, a pausable job is paused instead), `pause_fleet` (in scope `all`, `cpu`, `gpu` or `io`), `protect` (keep a metric of the
  protected group within a target: `cpu_stall`, `ipc_ratio`, `gpu_share`, `pageins_rate`, or `progress_rate` read from
  an owner-supplied source), and `evict`. `during` adds actions while an owner-supplied source says a phase is on.
  `ignore` only removes processes from the heuristic triggers.
- **Precedence:** every active rule, the mode profile and the guards each yield a constraint; the combined constraint
  takes the minimum of every ceiling, the OR of every pause and lower, and reservations summed over distinct processes
  (a process matched twice is reserved once, at its largest reservation).

## On each OS

Every rule field and trigger works on macOS, Linux and Windows, except what an OS cannot have: the config refuses
that there, with the reason, never leaving it silently inert. The coordinator checks the rules against the node's OS
when they are written (a promotion skips the nodes that cannot run them and says why), the agent against its own
(`support.rs`, the coordinator's `contracts.protection.refusals`, held equal by shared vectors in
`fixtures/protection-support-vectors.json`).

- Code-signing identity (`requirement`, `team_id`, `identifier`, and with it `tree = same_team`) and `bundle_id` are
  macOS's: Linux executables carry no signature, and Windows Authenticode carries no Team ID or signing identifier.
- `protect.metric = ipc_ratio` needs per-process instruction and cycle counters, which only macOS gives an
  unprivileged agent.
- `name` is the kernel's short name: 16 characters on macOS (p_comm), 15 on Linux (comm); on Windows it is the
  whole image file name.

What depends on the moment rather than the OS the agent reports, and the console and explain show it as a node
condition while the fail-safe default applies: a front app that cannot be read (`PROTECTION_FRONT_UNKNOWN`: a Wayland
desktop), presence that cannot be read (`PROTECTION_PRESENCE_UNKNOWN`: counts as someone present), processes matched
only because their path or arguments were unreadable (`PROTECTION_UNREADABLE`), an `ipc_ratio` rule whose processes
have no instruction or cycle counters (`PROTECTION_NO_IPC_COUNTERS`: a virtual machine; the metric is unknown, so the
budget does not grow on it), and a node that cannot lower its jobs (`PROTECTION_NO_LOWERING`: pausable jobs are paused
instead).

## The controller

One pure decision function over signals, configuration and its own state, on the agent's two-second loop:

- **L0, the guard**, needs no rule. Memory is budgeted before admission; the soft floor stops admitting, the hard floor
  evicts the largest-footprint job in the lowest band, one at a time, until free memory has recovered by the reclaim
  margin. Swap growth counts, because the kernel's pressure level can read normal with swap nearly full. Thermal and
  battery gates pause or stop admission.
- **L2, the fast throttle**, activates a rule after `enter_for_s` and releases it after `exit_after_s`; a protected
  metric over twice its target for two samples lowers fleet jobs at once, restored after 30 s clean.
- **L1, the resize loop**, runs AIMD on the fleet CPU budget each interval: one core up while every metric is in its
  grow zone (harm under half the target), halved on a violation, everything in scope taken back with a growth lockout
  on harm over twice the target or a guard. One actuator changes per interval, and a growth step that causes a violation
  is reverted.
- **The ladder:** stop admitting (with an exponential cooldown), cap, lower, pause, evict. Memory pressure skips to
  eviction (a paused job still holds its memory); GPU harm skips lowering (background QoS does not throttle the GPU).
- **Measured harm:** while a `protect` rule is active in `moderate`, a pause probe stops the pausable fleet jobs for a
  few seconds every ten minutes and compares the protected metric paused and running; windows with no fleet job running
  are kept as free baselines.
- **The growth gate:** the budget grows only on a validated signal: `progress_rate` for any group, or `ipc_ratio` for a
  group that is not GPU-bound. Otherwise it holds (`L1_HOLD_UNVALIDATED`). Implicit signals only veto.
- **Implicit signals count only what the fleet adds.** The frontmost-app and owner-stall signals read `cpu_stall` over
  whole groups of owner processes, measured per process (a process that starts or exits between samples adds
  nothing), and the owner's own work stalls too: a busy VM, a machine still booting. Their smoothed value counts only
  above the owner's own level, learned while no fleet job runs; while fleet work runs that level only falls, to at most
  half the target above the smoothed value. With no fleet job running they hold nothing back, so a new node starts at
  its full budget and takes work.
- **Bandwidth classes:** a module declares its runner's `bandwidth_class`. When the harm is only to GPU-bound groups,
  `low` jobs get no dynamic rung and `high` jobs are lowered as soon as the budget shrinks.
- **Failure defaults favour the owner:** a stale signal counts as a violation of every metric that uses it, a failed
  identity lookup counts as a match, presence that cannot be read counts as someone present, a missing private meter
  blocks growth but never the memory guard, and a restarted agent admits nothing until it has adopted its running jobs
  and evaluated every rule.

### Why the growth gate exists

Measured on an Apple Silicon machine without efficiency cores, with GPU training loops as the protected work: one CPU
memory-streaming thread slowed a GPU training step by 18–20 %, four by about 35 %, saturating near 40 %, because the
GPU already drew most of the chip's memory bandwidth. A compute-only fleet job did no measurable harm; a memory-heavy
CPU job cost 0–3 % at one worker and 9–12 % at five. Background QoS kept only 7–37 % of fleet throughput there, so lowering is
close to pausing on such chips. No CPU-side proxy (`cpu_stall`, `gpu_share`, system bandwidth) tracked the harm to a GPU
trainer; for a CPU-bound protected process `ipc_ratio` did (r = 0.97, full sign agreement).

## Defaults

| Default | Value |
|---|---|
| Sample period | 2 s |
| Rule enter / exit | 4 s / 60 s |
| Resume cooldown | 120 s × 2^(activations in the last hour), at most 3,840 s |
| L1 interval and step | 60 s; +1 core, ×0.5 on a violation |
| Violation lockout; revert lockout | 5 min; 30 s |
| L2 restore | after 30 s clean |
| Longest pause before eviction | 10 min |
| Pause probe | 6 s every 10 min, only while a `protect` rule is active |
| `strict_yield` admission | after 15 min idle, one slot a minute |
| Memory floors | soft 12 % free or swap +256 MB/min; hard 8 % free or swap +1 GB/min; reclaim 2 GB |
| Implicit owner stall (`moderate`, `strict_yield`) | `cpu_stall` at most 0.15 above the owner's own level |
| Implicit signal smoothing | weight 0.1 a sample (about 20 s) |
| `protect` window | 20 s |
| GPU fleet jobs | `when_no_gpu_protected` |
| Eviction grace | the runner's `stop_grace_s` |
| Flapping alert (coordinator) | more than 12 lower or pause escalations per node-hour |
| Probe-harm alert (coordinator) | a probe showing the protected process losing over 25 % |

The rule timings and the stall target are judgement values; the memory floors and the growth gate come from the
measurements above.

## Invariants

| ID | Invariant |
|---|---|
| S16 | The agent never signals or changes the scheduling of a process outside its spawn registry. |
| S17 | Admitted declared memory plus measured footprint plus reservations never exceeds the host budget, and nothing is admitted while a memory floor is active. |
| S18 | After a rule becomes active, the fleet meets its constraint within `enter_for_s` plus two samples (pause, lower, cap) or one L1 interval (reserve). |
| S19 | Worse, stale or missing signals never yield a larger fleet allowance. |

The coordinator checks S16 and S18 from the decision journals the agents ship in their heartbeats
(`protection_decisions`), shows them on the node's decision timeline, and alerts on flapping and probe harm.
