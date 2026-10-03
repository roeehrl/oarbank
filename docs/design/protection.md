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
  read counts as in front either way, never looser; with nothing in front (nobody at the machine's desktop) no group
  is in front. macOS asks `lsappinfo`; Linux takes the session logind has in front on the seat: an X11 session's
  active window (EWMH `_NET_ACTIVE_WINDOW` and its `_NET_WM_PID`, read with the session's Xauthority cookie), a text
  console's foreground process group; a Wayland compositor tells no other program which window is in front, so there
  it is unknown. Windows takes the console's session from WTS (locked: nothing in front) and its foreground window,
  which only a process in that session may ask for (a packaged app's frame is resolved to the app inside it).
- **GPU activity** is the group's GPU busy seconds per second over the last sample interval, summed over its processes
  and the GPU's engines (so two busy engines can pass 1); `min_busy` defaults to 0.05. Each OS reads accumulated GPU
  time per process: macOS from the AGX driver's user clients in the IORegistry, Linux from the DRM `fdinfo` of every
  GPU file a process holds (`drm-engine-*` nanoseconds, or `drm-cycles-*` over `drm-total-cycles-*` on xe; amdgpu,
  i915, xe, msm, panfrost and the other drivers that write usage stats), Windows from the raw `GPU Engine` performance
  counters (running time in 100 ns per process, adapter and engine). Usage that cannot be read counts as busy, never
  looser: the first reading after start (no baseline yet), a missing source, a process holding a GPU that reports no
  per-client counters (NVIDIA's proprietary `/dev/nvidia*`, AMD's `/dev/kfd`, a kernel before 5.19) and another user's
  process whose open files the agent cannot read.
- **Actions** (fleet-side only): `reserve` (cores and memory, as expressions over measured peaks such as
  `peak(300s).footprint + 2`), `cap_fleet` (slots, cores, threads, staging bandwidth, GPU jobs), `lower_fleet` (fleet
  jobs to background QoS), `pause_fleet` (in scope `all`, `cpu`, `gpu` or `io`), `protect` (keep a metric of the
  protected group within a target: `cpu_stall`, `ipc_ratio`, `gpu_share`, `pageins_rate`, or `progress_rate` read from
  an owner-supplied source), and `evict`. `during` adds actions while an owner-supplied source says a phase is on.
  `ignore` only removes processes from the heuristic triggers.
- **Precedence:** every active rule, the mode profile and the guards each yield a constraint; the combined constraint
  takes the minimum of every ceiling, the OR of every pause and lower, and reservations summed over distinct processes
  (a process matched twice is reserved once, at its largest reservation).

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
  identity lookup counts as a match, a missing private meter blocks growth but never the memory guard, and a restarted
  agent admits nothing until it has adopted its running jobs and evaluated every rule.

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
| Duty cycling | off (fans pulse) |
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
