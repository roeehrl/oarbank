# Co-tenancy: measuring harm, event-driven sources, certificates and the GPU duty

Fleet work runs beside the owner's own processes, and host protection ([protection.md](protection.md)) keeps it from
harming them. This document covers the pieces that make that measurable and fast (PLAN D50 to D54):

- **Event-driven owner sources** (D51): the owner's progress and phase sources are watched, not polled, so a phase
  such as an upload is seen within milliseconds; rules marked `immediate` pause fleet work between ticks; sources in
  a person's home are read by that person's session helper in a system install.
- **The paired on/off harness** (D52): a randomised, paired measurement of what given fleet work costs one protected
  process, with a decision at the owner's margin.
- **Co-tenancy certificates** (D52, gating D50): a run that shows no slowdown becomes a certificate for one node, rule
  and fleet configuration; `gpu_jobs = "certified"` lets cooperative GPU work run beside a protected GPU group only up
  to a certificate's duty level.
- **The duty governor** (D50): under a certificate, an AIMD budget on the protected program's own progress decides how
  much of the GPU cooperative fleet work may use, and a compliance check against each process's measured GPU time
  pauses, then stops, work that does not hold its duty.
- **The reference GPU module** (D53): `examples/llmserve` in the SDK, language-model batches on MLX or llama.cpp that
  hold their duty; and no multi-node gang scheduling (D54).

Nothing here names a particular program: protected programs are owner rules.

## Owner sources (D51)

A source belongs to a rule: `protect.source` (a progress rate for `protect.metric = "progress_rate"`) or a `during`
block's `source` (a phase). It is owner configuration, never a module's.

| Kind | Fields | Meaning |
|---|---|---|
| JSONL progress | `jsonl`, `event`, `event_key` | count lines whose `event_key` (a dotted path, default `event`) equals `event`; no `event` counts every line |
| Log progress | `log_regex`, `path` | count regex matches in new lines |
| Probe progress | `exec` | an owner-written program printing a rate (run by the agent, never by a helper) |
| Event phase | `jsonl`, `enter`, `exit`, `enter_soon`, `event_key` | on after an `enter` or `enter_soon` event, off after `exit` |
| Field phase | `jsonl`, `event`, `field`, `on`, `soon` | on while the dotted `field` of the `event` lines holds one of `on` or `soon` |
| Process trigger | `on_exec = { match, tree }` | on while a matching owner process runs |

```toml
[[rule]]
id        = "trainer"
match     = { path_prefix = "/Applications/Example Trainer.app/" }
tree      = "descendants"
immediate = true
protect   = { metric = "progress_rate", max_slowdown = 0.05,
              source = { jsonl = "~/Library/Application Support/Example/events-*.jsonl", event = "backward_complete" } }
[[rule.during]]
source      = { jsonl = "~/Library/Application Support/Example/events-*.jsonl", event = "heartbeat_response",
                field = "response.phase", on = ["weights_uploading", "merging_partitions"] }
pause_fleet = { scope = "gpu" }
cap_fleet   = { staging_mbps = 0 }
tags        = ["uplink"]
```

- **Newest file.** A path's last component may hold `*`. The reader follows the newest matching file (by
  modification time): a program that starts `events-<session>.jsonl` on every restart is picked up when the new file
  appears, and the rest of the old file is read first.
- **The tail** keeps the file's identity (device and inode; creation time on Windows) and offset. A rename or a new
  file finishes the old one through the open handle, a truncation starts again from 0, and only complete lines are
  parsed (a partial line waits for its newline; one over 1 MiB is dropped). A progress source starts at the end of the
  file; a phase source reads back up to 4 MiB to find the state already written, skipping the first fragment.
- **Watched.** macOS: kqueue `EVFILT_VNODE` on the newest file (`NOTE_WRITE`, `NOTE_EXTEND`, `NOTE_DELETE`,
  `NOTE_RENAME`, `NOTE_ATTRIB`) and on its directory, opened `O_EVTONLY`. Linux: inotify on the directory
  (`IN_MODIFY`, `IN_CLOSE_WRITE`, `IN_CREATE`, `IN_MOVED_*`, `IN_DELETE*`), `IN_Q_OVERFLOW` re-reading everything.
  Windows: a 250 ms poll of the newest file's size and write time (`ReadDirectoryChangesW` reports appends late, when
  the cache flushes, so the poll is what bounds the reaction there). Every backend re-resolves the newest file every
  250 ms, and the two-second tick reads every source anyway: a missed event costs at most a tick. A newly watched file
  is read once at once, so a change between configuration and watch is never lost.
- **Fail-safe.** An unreadable progress source counts as a violation (unchanged). An unreadable phase counts as **on**:
  never looser. Both are node conditions with their fix (`PROTECTION_SOURCE_UNREADABLE`,
  `PROTECTION_SOURCE_NEEDS_HELPER`; explain, the node page, `oarbank protection show`), never a silent hold.
- **Tags** are owner labels on a `during` block (`uplink`: the phase uses the site's internet line). The node acts on
  nothing but the block's actions; the tags travel with the phase in the heartbeat, for coordinator-side aggregation
  (below).

### Who reads a source: the session-helper relay

A system install's agent runs as a service account (`_oarbank` on macOS) that may not read a person's home, where
programs keep their logs and events. Before this release `~` expanded to the agent process's own `HOME`, the service
account's, so such a source could never be read and held fleet work back for good. Now:

| Path | Personal install (the agent runs as the person) | System install |
|---|---|---|
| `~/x`, `~name/x` | the agent reads it in its own (or `name`'s) home | the person's session helper reads it (`~`: any logged-in person whose file exists; `~name`: that person only) |
| `/Users/<name>/x`, `/home/<name>/x`, `C:\Users\<name>\x` | the agent | `name`'s session helper |
| anything else (`/Users/Shared`, `/var/log`, ...) | the agent | the agent |

The session helper (`oarbank-agent session-helper`, one per GUI login on macOS from
`/Library/LaunchAgents`, a systemd user unit on Linux, started per session by the elevated helper on Windows) already
reports to the service over a local endpoint whose peer credentials name the account. The relay adds one message the
other way: the service sends `{"v": 2, "watch": [{key, kind, account, rel, spec}]}` when the list changes and on every
connection (the spec without its path), and the helper reads those sources under its own home with the same tail
and watcher and reports, in every report and at once on a phase change, `sources: [{key, events, epoch, on, readable,
event_t}]`.

- **No new privilege, no file contents.** The helper reads only what its person can read, only paths under that
  person's home (a relative path that would leave it is refused), never runs a probe, and sends counts and phase
  states, never lines.
- **Checked.** The service accepts a source report only for a source it asked that principal for (a source for a
  named account goes only to that account's helper; on Windows, where the pipe proves the session rather than the
  account, the helper filters by its own account). A phase on at any helper wins; a count's epoch changes when the
  helper reconnects, and the next read sets a new baseline instead of a jump.
- **Nobody logged in.** No helper reports the source: it is unreadable. A progress source then counts as a violation
  and a phase as on, so fleet work under the rule is held back, and the node shows
  `PROTECTION_SOURCE_NEEDS_HELPER` ("source ... is in a person's home ...; nobody's helper reports it now"). This is
  the report's fail-safe philosophy: the agent cannot tell an idle program from one in an upload, so it assumes the
  worse. A rule whose protected process only runs while its person is logged in loses nothing: with nobody logged
  in its group is usually empty and the rule inactive. An owner who wants fleet work to run while logged out and the
  program keeps running puts its sources where the service account can read them (outside the home, readable by
  `_oarbank`).

### The event tick and `immediate` rules

A rule marked `immediate = true` has its `during` phases act between ticks:

1. The watcher thread wakes on a change (or a helper's report arrives) and re-reads only the phases the change can
   touch.
2. A phase that turned on is journaled (`phase_change`, `PROTECTION_PHASE_ON`, with `event_t`, when the change was
   seen, `via`: watch, helper, exec or poll, and the block's tags), and if its rule is **armed** (active, or its
   matched group is present: an immediate phase applies before the rule's `enter_for_s` has passed) and the block
   pauses (`pause_fleet`), the agent's fast path pauses the fleet work in scope at once: a freeze through the spawn
   registry, or `pause` in a cooperative runner's control document (S16 unchanged). The pause is journaled
   (`attempt_paused` with `event_t` and `latency_ms`).
3. The two-second tick does everything else: caps, lowering, services, the dynamic layer, and the release after the
   phase's own `exit` (hysteresis comes from the exit event, not from `exit_after_s`).

The event path only ever adds a pause. A tick that read its sources before a fast pause keeps that pause (it did not
see the phase), and the fast path records a freeze in the same set the tick resumes from, so a fast pause neither
flaps nor sticks. `specs/OarbankFastPause.tla` checks both (`FastPauseHolds`, `NoStuckPause`) and fails without
either rule.

**Process triggers** (`on_exec`) are evaluated on the tick from the process table, and for immediate rules by a
250 ms process listing on the same thread: kqueue `EVFILT_PROC` watches only known pids, the Linux proc connector
needs `CAP_NET_ADMIN`, and Windows' process events arrive on a one-second ETW flush.

**Latency.** Source write to pause request: the target is p99 under 50 ms; the agent reports its own histogram
(`event_latency`: count, p50, p99, max, buckets). On a heavily loaded development Mac the unit test measured
0.4–1.8 ms worst of five for a file the agent watches, and the relay test 44 ms through a session helper.

**S25** (new): for an immediate rule, the first pause of a phase the event path saw begin is the event path's, within
100 ms of the source event. The coordinator checks it from the decision journal (`invariants.s25_...`), beside S18.

### Per-site aggregation (the interface)

The heartbeat's `telemetry.protection.phases` lists every `during` block: `{key, rule, block, on, since, readable,
reader, tags, immediate}`. The coordinator reads it with `protection.node_phases(db, node_ids, tag)` and
`protection.any_phase_on(db, node_ids, tag)`, which is on, never looser, when any node's tagged phase is on or
unreadable or a node with such a phase has not reported for 60 s. A feature that groups nodes by shared internet line
(a site) asks `any_phase_on(site_nodes, "uplink")` and holds network-heavy fleet work at the site while it is on.

## The paired on/off harness (D52)

**What it measures.** For one rule with a `progress_rate` source on one node, `R = progress(fleet on) / progress(fleet
off)` for one fleet configuration: which work (`gpu`, `cpu`, `all`, `<module>`, or `<module>/<workload>`) and at which
`gpu_duty`.

**Design.**

- **Blocks.** A run is blocks of one ON and one OFF window in random order (a coin per block, splitmix64 from the
  run's seed). Default window 300 s, washout 60 s discarded after each switch.
- **OFF** pauses the work under test the way protection would (cooperative pause or freeze; work that can do neither
  is released), or with `off = "evicted"` releases it so its memory is free too. **ON** lets it run, exempt from the
  GPU gate (`gpu_jobs = when_no_gpu_protected` would otherwise pause GPU work beside a protected GPU group), with
  `gpu_duty` at the level under test in cooperative runners' control documents. Everything else protection does
  stays: owner rules' own pauses, the memory guard, the dynamic layer. The pause probe is suspended during a run (the
  harness replaces it).
- **Exclusions.** A block is dropped and repeated when an outside cause differed: a `during` phase of the rule was on,
  the protected process restarted (its group's pids and start times changed), the node slept (a gap of over 10 s
  between ticks), the power source changed, the memory guard acted, the rule went inactive, or the source could not
  be read. Thermal throttling is not a cause: if fleet work heats the machine, that slowdown counts. A block whose ON
  window made no progress at all while OFF did counts as harm, not an exclusion.
- **Statistic.** Per window, the mean progress rate after the washout; per block, `ln(on / off)`. The mean log ratio
  gets a 90 % interval by a bootstrap over blocks (2,000 resamples, type-7 quantiles) and by a t interval.
- **Decision (TOST).** Margin Δ (default 2 %; only slowdowns matter): **no slowdown shown** when the lower 90 % bound of
  `R` is above `1 − Δ`; **slowdown** when the whole interval is below 1 and the estimate below `1 − Δ`; otherwise
  **inconclusive**, with the further blocks the observed spread says are needed. The two intervals must agree; when
  they do not (few blocks, a skewed sample), the run is inconclusive (a refinement over the report, which made the t
  interval only a cross-check).
- **Power.** After a pilot of 3 blocks, the harness reports the slowdown the planned blocks detect with 80 % power and
  raises the block count to what the margin needs; a run that cannot reach it within its cap (default 8 hours) is
  **refused**.
- **Sequential stopping.** After each block (from 3), an always-valid mixture SPRT (normal approximation with the
  observed variance, mixing scale Δ, α = 5 % each way) may stop the run: a slowdown at once; "no slowdown shown" only
  when the fixed analysis agrees.
- **Guard.** In an ON window, harm over twice the rule's target (`max_slowdown`, else the margin) against the OFF
  baseline so far aborts the run as a slowdown.

The statistics live in the protection crate (`abstats.rs`) and, for the coordinator, in `oarbank.contracts.abstats`,
held equal by shared vectors (`src/oarbank/contracts/vectors/abstats-vectors.json`, generated by `gen_abstats.py`).
Property tests check the decision's error rates on a simulated plant: a zero effect yields "slowdown" in at most 5 %
of runs, a 5 % slowdown is detected in at least 80 %, and the sequential test stops a zero-effect run wrongly in at
most 5 %.

**Where it runs.** In the agent, as a mode of the controller (the windows are timed on the node). The coordinator
asks for a run (`ab_run` in the heartbeat reply), may abort it (`ab_abort`), stores the agent's reports (`ab_runs`),
and forgets the finished run on the node (`ab_ack`). A run lost to an agent restart is aborted at the next hello.

**Frontier search.** `protection.ab.sweep` runs the harness at rising `gpu_duty` levels (0.1, 0.2, 0.35, 0.5, 0.65,
0.8, 1.0, or the owner's list) and stops at the first that is not "no slowdown shown"; the highest passing level is
the node's certified duty for the rule.

## Certificates (D52) and `gpu_jobs = "certified"` (D50)

A run that ends "no slowdown shown" becomes a certificate: node, rule, fleet configuration (`work`, `duty`), `R` with
its interval, the margin, the run, and a validity of 14 days. It is bound to what the run was earned under: the node's
hardware (CPU model and cores), OS major version and agent version (`cert_context`), and the protected program's
identity (a fingerprint over the distinct path, Team ID and signing identifier of the rule's matched processes; a
restart keeps it, a new build at another path or signed differently changes it). The coordinator sends the
certificates in force with every heartbeat reply (`certificates`); the agent checks each itself, never looser, and a
certificate it cannot validate counts as none.

`gpu_jobs` gains `certified` (between `always` and `when_no_gpu_protected` in the strictest-wins union). Beside a
protected group that holds GPU work back through the GPU gate (a group using the GPU, more than 5 % of its GPU time,
whose rule protects `gpu_share` or `progress_rate`), cooperative GPU work (runners that declare `cooperative_throttle`)
runs at `gpu_duty = D / n`, where `D` is the duty governor's budget (below), never above the smallest certified duty
among the gating rules, and `n` the cooperative GPU jobs it trusts; work that cannot throttle stays paused, and no new
GPU work is admitted beyond what runs. Without a valid certificate for every gating rule it behaves
as `when_no_gpu_protected` and journals `GPU_NOT_CERTIFIED` (a node condition, with the sweep as the remedy). An
owner's explicit pause of GPU work, a rule's or a phase's `pause_fleet` with scope `gpu`, `all` or `io`, always binds:
it pauses the work and admits no GPU job (capacity `paused`, `paused_by`), certificate or not; a certificate lifts only
the gate. Such a rule also counts as gating, so the GPU budget shows it as not certified unless a certificate covers
it.
`certified` is opt-in per node (owner decision 14).

A rule that protects `progress_rate` gates GPU work as a `gpu_share` rule does once its group uses the GPU (2.10;
before, only `gpu_share` rules did, so a GPU trainer protected by its progress let fleet GPU work run beside it under
`when_no_gpu_protected`, against D3d). The certificate a gated node needs is therefore the one the harness earns on
that same rule.

## The duty governor (D50)

`oarbank-protection/src/gpu_duty.rs`, run by the controller every tick while `gpu_jobs = certified` and a gating group
is active; a pure function of its inputs and its state, like the dynamic controller. The ceiling is
`ProtectionController::certified_duty` (the smallest among the gating rules); each job's share reaches its control
document through `DynJob::gpu_duty` and `ThrottleDoc::gpu_duty`.

**The budget `D`.** An AIMD loop on the gating rules' `progress_rate`, the only signal validated for GPU-bound groups
(protection.md, "Why the growth gate exists"):

| When | What |
|---|---|
| The gate begins, every gating rule with a progress source has a baseline under 30 min old | `D` = the ceiling (feed-forward, as the CPU budget starts at the full allowance: the certificate measured that level harmless); a gate that went away less than 10 min ago resumes at its last `D` (no windup) |
| The gate begins and some rule has no fresh baseline | a **baseline window**: `D` = 0 for 60 s (the first 20 s discarded as washout), then the start level |
| Every 60 s (an interval) | per rule the interval's mean progress rate against its baseline: harm = `1 − rate/baseline`, pressure = harm ÷ the rule's `max_slowdown` (default 0.05). Pressure over 2: `D` = 0 and a 5-min lockout. Pressure at or over 1: `D` halves (30 s lockout). Pressure under 0.5 in every rule, every sample of the interval readable and the memory guard clear, the lockout over: `D` grows by 0.05, never above the ceiling. Otherwise it holds |
| Any tick | a progress source that cannot be read: `D` = 0 at once (fail-safe; it grows back once it reads). The memory guard: `D` = 0 and a 5-min lockout. A **collapse**, the rate over the last 30 s under half the baseline while GPU work runs: `D` = 0 and a 5-min lockout |
| The ceiling falls (a new certificate, one expired) | `D` falls to it at once |
| The baseline is 30 min old while GPU work runs | another baseline window, then back to `D` |
| `D` under 0.02 | 0: no cooperative work is exempt from the gate, so it is paused like any GPU work |

The baseline is the rule's progress rate while no fleet GPU work ran (after the 20 s washout): baseline windows and
natural ones (the budget at 0, the gate holding, no GPU work there), averaged with the previous baseline. A gating rule
without a progress source (a `gpu_share` rule) has no harm signal: `D` starts at the ceiling and stays where it is,
never growing (S19's growth gate: nothing validates growth). In a baseline window or at `D` = 0 there is nothing to
harm: such an interval is clean when its samples were readable.

**S19 for `D`:** a missing, stale, unreadable or worse signal never raises it; it rises only at an interval's end
whose every sample was clean, or at a start. **S18's GPU form:** the budget meets a falling ceiling, an emergency and
an unreadable source on the tick that sees them; a halving waits for the interval (the rule's own `pause_fleet`, if
any, still acts within `enter_for_s` + 2 samples).

**Each unit's duty and the compliance check.** Units are the GPU jobs (and, once workloads carry GPU work, workloads:
a unit is an id, a `module/name` key, whether it declares `cooperative_throttle`, whether it can be paused, and its
processes' GPU busy fraction). Every sample (2 s) the governor reads each unit's GPU busy fraction from the per-process
GPU time the meter reads (macOS AGX `accumulatedGPUTime`, Linux DRM `fdinfo` or NVML, Windows GPU Engine counters),
summed over all processes of its container.

- A unit is judged from the second sample after it was given a duty (its duty may reach it a sample late), and only on
  samples it ran through with a duty (a paused unit is not judged). Allowed: the larger of its last two duties, plus
  0.1.
- Over that for three consecutive samples: the unit is **held** for 60 s (no duty: the gate pauses it), journaled
  `GPU_DUTY_EXCEEDED` (`kind: gpu_compliance`, `action: paused`). The third hold of the same `module/name` within an
  hour **stops** it (released, `preempt_protection`; `action: evicted`), and that key gets no duty for an hour: its
  work waits beside protected GPU work like work that cannot throttle. A unit that cannot be paused is stopped at its
  first excess.
- A unit whose GPU time cannot be read for three samples (unknown on this platform, or a process the meter cannot
  see) is held the same way, `GPU_DUTY_UNVERIFIED`: a duty nobody can check is not granted. On a node whose meter reads
  no per-process GPU time, `certified` therefore runs no GPU work: the fail-safe answer.
- The remaining budget is split among the units it trusts: `D / n` each, to 1/1000, never above the ceiling.

While a harness run measures GPU work (`work` is not `cpu`), the governor stands down (state `harness`): GPU work not
under test waits beside the protected group, so the run measures only the work under test.

**What the agent reports.** `telemetry.protection.gpu_budget`: `duty` (`D`), `ceiling`, `rules`, `jobs` (units given a
duty), `per_job`, `state` (`measuring`, `running`, `held` at 0, `locked` after a take-back, `harness`, `not_certified`,
`idle`), `lockout_s`, `baseline` (per rule: `rate`, `age_s`, the last interval's `pressure`), `units` (per unit: `id`,
`duty`, `measured`, `state`: `ok`, `waiting`, `held` with `why` `exceeded` or `unverified` and `for_s`, `distrusted`,
`cannot_throttle`, `evicted`) and `distrusted` (`unit`, `for_s`). Budget steps are journaled `kind: gpu_duty`
(`GPU_DUTY_START`, `GPU_DUTY_BASELINE`, `GPU_DUTY_GROW`, `GPU_DUTY_HALVE`, `GPU_DUTY_TAKE_BACK`, `GPU_DUTY_CLAMP`, each
with `duty`, `ceiling` and `why`), compliance as above.

**S28** (new): the budget a node journals never exceeds the ceiling journaled with it, every unit the governor holds is
paused within the S18 window (or ended), and every unit it stops is gone a minute later. The coordinator checks it from
the decision journal (`invariants.s28_gpu_duty_within_ceiling_and_enforced`); the agent's property tests, a day-long
virtual-time soak and `specs/OarbankGpuDuty.tla` check the rest.

**Defaults** (judgement, to be tuned with the harness on each Mac class): interval 60 s, step 0.05, halving at the
target, take-back at twice the target or a collapse under half the baseline over 30 s, lockouts 5 min and 30 s,
baseline window 60 s with 20 s washout, every 30 min, resume memory 10 min, compliance slack 0.1, three samples, hold
60 s, three holds in an hour, distrust one hour, minimum duty 0.02.

### What the runner does

A runner holds its duty with the SDK's governor, `oarbank_sdk.duty.Duty` (SDK `spec/runner-protocol.md`, "Holding a
GPU duty"): it times each unit of GPU work to the end of the GPU's work and idles `b·(1−d)/d` after it, applies a
newer control document while it idles, holds at duty 0, says how much shorter units should be (`scale()`), and reports
what it held as `gpu_duty` metric events. The conformance kit's duty specs give a `cooperative_throttle` runner a duty
mid-run and measure it holding it (its GPU time on macOS, its CPU time for a CPU stand-in backend).

### Why not throttle from outside

On Apple Silicon no public interface lets a third party prefer one process's GPU work or cut another's: Metal has no
queue priority, the GPU's firmware schedules, and a submitted command buffer runs to its end. Freeze cycling (SIGSTOP
on and off) is not used: in-flight command buffers finish anyway, the cycle the agent can hold is about 100 ms at best,
and its effect would need its own certificate. On NVIDIA, MPS thread percentages are fixed when a client starts. So the
duty is cooperative and verified, and work that cannot cooperate only ever pauses or stops.

### An owner-run experiment: `PRIO_DARWIN_GPU`

xnu has a private `setpriority(PRIO_DARWIN_GPU, pid, PRIO_DARWIN_GPU_DENY | _ALLOW)` that switches a process's GPU
access off and on, nothing in between. Oarbank does not use it (D3c allows private signals only to restrict, and this
one may make the target's command buffers fail, which most programs treat as fatal). Whether it is worth anything is a
measurement for the owner, in a window they free for it, against fleet work they choose and never against a protected
program:

```sh
python3 bench/prio_darwin_gpu.py --seconds 20 --i-understand -- <command that runs GPU work, e.g. an llmserve job>
```

The script starts the command itself (it signals nothing it did not start), lets it run, denies it the GPU, allows it
again, and reports for each phase the child's GPU time growth (from the driver's counters, as the agent reads them),
whether `setpriority` was permitted, and whether the child survived. Unverified until an owner runs it: whether an
unprivileged process may set it on its own child, whether denied work fails or waits, and whether access comes back.
Its result decides whether a later release offers it as an opt-in last resort for work that cannot cooperate.

## The reference GPU module (D53)

[`examples/llmserve`](../../vendor/oarbank-sdk/examples/llmserve) in the SDK (an SDK example rather than a module in a
repository of its own, so the SDK's CI conforms it on every platform): a `batch` stage that runs prompts through MLX
(macOS on Apple Silicon) or llama.cpp (Metal, CUDA, Vulkan or the CPU) in its runner, with each generation step one
unit under `oarbank_sdk.duty`, MLX's memory limit set and nothing wired; and a deterministic `selftest` stage (a pure
Python stand-in model, integer arithmetic only) whose golden certifies the module on every node and whose CPU units
let the conformance kit's duty spec run on a machine without a GPU or a model. It bundles no model and depends on
neither backend: an owner installs one and puts a model under the module's data directory (SDK `docs/gpu-duty.md`).
It is the harness's first real GPU test subject: a sweep of its work against a protected program on each Mac class
gives the first GPU co-tenancy certificates.

## No gang scheduling (D54)

Multi-node jobs (all-or-nothing placement of cooperating processes, a rendezvous, a shared failure domain) are not
built: distributed inference across Macs pays only when a model does not fit on one machine, and a gang ties every
member's protection to the slowest owner. Independent per-node work earns more per unit of engineering on this fleet.
Revisit only for a ranked workload that needs more than one node's memory, starting with a module-level design (a
workload with `seat = "fleet"` and a module-run rendezvous) before any coordinator change.

## Operations, console and CLI

| Operation | Tier | What |
|---|---|---|
| `protection.ab.start` | T2 | a run on a node; the preview names the rule and source, the work, the planned and capped hours |
| `protection.ab.abort` | T0 | abort a run |
| `protection.ab.sweep` | T2 | a duty sweep |

- **Protection page, Co-tenancy card:** every phase and progress source with its state and who reads it (the agent,
  the person's session helper, a process trigger), the event path's latency, the GPU budget, the certificates with
  `R`, interval, margin, expiry and state (valid, expired, stale with why), the latest run, and forms to start a run
  or a sweep.
- **Harness page** (`/protection/ab/<run>`): the blocks as a paired dot plot, `R` and its interval against the margin,
  the decision in words ("No slowdown shown: the protected process ran at 99.4 % of its speed without fleet work (90 %
  interval 98.6–100.3 %), within the 2 % margin"), excluded blocks and why.
- **CLI:** `oarbank protection ab start <node> --rule <id> [--work gpu|cpu|all|<module>|<module>/<workload>] [--duty
  0.3] [--blocks 12] [--window 300] [--washout 60] [--margin 0.02] [--off paused|evicted] [--max-hours 8]`,
  `oarbank protection ab status [<node>]`, `oarbank protection ab show|abort <run>`, `oarbank protection ab sweep <node>
  --rule <id> [--levels 0.1,0.2,0.35]`, `oarbank protection certificates [<node>]`, `oarbank protection duty [<node>]`
  (the governor: budget against the ceiling, state, baselines, each unit's asked and measured duty and state, the
  units it does not trust, the last day's steps and compliance actions; `GET /api/v1/protection/duty[?node=]`).
- **GPU duty card** on the protection page (with `gpu_jobs = certified` and a gating group): the same, with the node
  conditions `GPU_DUTY_EXCEEDED` (a module not trusted for an hour) and `GPU_DUTY_UNVERIFIED` (units whose GPU time
  cannot be read).

## Running the first measurement against a real protected program

Only in a window the owner frees for it, started by hand:

1. Give the protected program a rule with a `progress_rate` source (its own event file, counted by event type). On a
   system install with the file in the person's home, stay logged in: the session helper reads it.
2. Check the source reads: the Co-tenancy card shows a rate, `read by` names the agent or the session helper.
3. CPU co-tenancy first (it already runs): `oarbank protection ab start <node> --rule <id> --work cpu`, about two hours
   at the defaults.
4. GPU co-tenancy, only with fleet GPU work whose runner declares `cooperative_throttle`: `oarbank protection ab sweep
   <node> --rule <id>`. Each level is a run; a slowdown stops the sweep at once and the guard aborts a collapse.
5. To use a certificate, set the node's `gpu_jobs = "certified"`. The governor measures a baseline for a minute, then
   runs cooperative GPU work at the certified duty and moves it with the program's progress; `oarbank protection duty
   <node>` shows it.

## Failure modes

| Failure | Behaviour |
|---|---|
| Progress source unreadable or stale | a violation (fail-safe, unchanged); in a harness run the block is excluded |
| Phase source unreadable (a person's home with nobody logged in) | the phase counts as on; `PROTECTION_SOURCE_NEEDS_HELPER` |
| Watcher misses an event | the 250 ms re-scan and the tick catch it |
| The helper disconnects | its sources read as unreadable at once (the event path is told) |
| Harness confounded by an outside event | the block is excluded and repeated; too many exclusions abort the run |
| The agent restarts mid-run | the run is aborted at the next hello |
| Certificate stale (OS update, new hardware, agent or program build) | `certified` behaves as `when_no_gpu_protected` until a new run passes |
| Thermal throttling during ON windows | counted as harm, by design |
| A runner ignores its `gpu_duty` | held after three samples over duty + 0.1, stopped on the third hold in an hour, its module distrusted for an hour |
| The node cannot read a unit's GPU time | the unit is held (`GPU_DUTY_UNVERIFIED`): no unverifiable duty |
| The protected program makes no progress at all (no baseline) | the baseline window gives up after four windows: `D` stays at 0, grows back a step at a time and measures again once GPU work runs |
| The gate flaps (the program's GPU use dips) | the budget resumes at its last level within 10 min, never at the ceiling |

## Security

Runs and sweeps are owner operations (T2: they deliberately run fleet work beside a protected process); modules
cannot start runs, read certificates or name sources. Sources remain owner configuration read by the agent or the
person's own session helper, which gains no privilege and sends no file contents. A coordinator that could forge a
certificate can already set `gpu_jobs = "always"`; the node's local protection file still wins on every dimension.

## Verification

| Layer | Tests |
|---|---|
| Statistics | shared vectors (Rust and Python), error-rate and power properties, the sequential test's validity (`tests/abstats.rs`) |
| Harness | a simulated protected process: harmless and harmful co-tenants, the guard, every exclusion, sleep detection, power refusal (`tests/cotenancy.rs`) |
| Controller | harness arms and `gpu_duty`, certified work against valid and invalid certificates, immediate phases and process triggers (`tests/cotenancy.rs`) |
| Sources | newest-file following, field phases, rotation, truncation, partial lines, the lookback fragment, locations, the event path's latency (`tests/sources.rs`) |
| Relay | helper readings and filtering, the hub's checks and wake-ups (`tests/relay.rs`); a real helper over the session socket in one account with a scratch home (`tests/relay_live.rs`) |
| Agent | the fast pause freezing a real process between ticks and the tick keeping it (`prot.rs`, macOS) |
| Coordinator | runs, reports, certificates and their validity, sweeps, aborts, conditions, S25, per-site aggregation (`tests/test_cotenancy.py`) |
| End to end | a real agent and oarbankd with a synthetic protected process: phases with tags, a harness run to its decision (`tests/rust/test_agent_cotenancy.py`) |
| TLA+ | `OarbankFastPause.tla`: the agent's rules hold; each weakened variant fails. `OarbankGpuDuty.tla`: the budget stays within the ceiling and grows only after a clean interval, excess is held, a unit that never holds its duty is stopped; each weakened variant (no clamp, growth on an unclean interval, no hold, strikes reset) fails |
| Duty governor | AIMD steps, baselines, take-backs, the ceiling, resume memory, S19 for `D` over random signals, compliance holds and stops, unverified units (`tests/gpu_duty.rs`); a 24-hour virtual-time soak with a contention plant, certificates, guards, unreadable sources and honest, lying and unmeasurable jobs (`tests/gpu_duty_soak.rs`) |
| Duty, coordinator | the duty view and the card's units, the conditions, S28, the API and `oarbank protection duty` (`tests/test_gpu_duty.py`) |
| Duty, SDK | the governor's share of time, new duties while idle, duty 0, stops while idle, `scale()`, reports (`tests/test_duty.py`); llmserve conforms with its duty spec, and a runner that does not hold its duty is caught (`tests/test_conformance.py`) |
