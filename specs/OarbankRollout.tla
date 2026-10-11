---------------------------- MODULE OarbankRollout ----------------------------
(***************************************************************************)
(* Fleet rollouts (docs/design/fleet-updates.md, D57-D61, invariants       *)
(* S29-S31): the coordinator takes the fleet from version 1 to version 2,  *)
(* updating itself first (ring 0), then the node rings in order (canary,   *)
(* then broad). Two machines run per node:                                 *)
(*                                                                         *)
(*  - the coordinator's view of the node (rollout_nodes.state): pending -> *)
(*    staged -> go -> draining -> installing -> confirming -> done, or     *)
(*    failed / rolled_back; the agent moves it along on its heartbeats     *)
(*    while the node is online;                                            *)
(*  - the node's root update runner (oarbank-launcher update-run): take    *)
(*    the request, install (may fail), probation (the new agent confirms,  *)
(*    or never does), commit or reinstall the kept previous package. Its   *)
(*    step is journaled, so a runner that crashes resumes where it was.    *)
(*                                                                         *)
(* The tick grants "go" to a staged, online node of the current ring while *)
(* fewer than the ring's max_unavailable are busy (go to confirming);      *)
(* counts failed and rolled-back nodes against the ring's budget, and      *)
(* above it halts and, with auto_rollback, starts rolling the moved nodes  *)
(* back to version 1 through the same machinery and slot rule; finishes a  *)
(* ring when every member is done, failed or waiting offline; and starts   *)
(* the next ring after the bake (abstracted: a step that needs the ring    *)
(* still finished with no failure since). A node that was offline when its *)
(* ring finished joins the current ring when it returns, or catches up     *)
(* after the rollout is done (D61). The operator may Start, Pause, Resume, *)
(* Halt and Roll back. Faults (bounded by MaxFaults): an install fails,    *)
(* a new agent never confirms, a runner crashes, a node goes offline, the  *)
(* coordinator's own update rolls back (which halts the rollout).          *)
(*                                                                         *)
(* Abstracted away: time (bake time, heartbeat counts, the 600 s           *)
(* probation are single steps), staging failures, drain timeouts           *)
(* (deferred), windows, holds, pins and stops (eligibility is "online"),   *)
(* the fleet-unhealthy start gate, empty rings and the early ring (two     *)
(* rings carry every rule), a newer rollout superseding this one.          *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Canary, Broad,              \* the nodes of each ring (update_ring)
    CanaryCap, BroadCap,        \* max_unavailable per ring
    CanaryBudget, BroadBudget,  \* failure budget per ring (0 and 1 by default)
    MaxFaults,                  \* faults: install failure, no confirmation, runner crash, offline, coordinator rollback
    MaxOps,                     \* operator actions that can repeat (Pause, Halt, Resume after a halt, Roll back)
    AutoRollback,               \* auto_rollback (default on)
    \* Weakened variants (all FALSE in the protocol as designed):
    NoCap,                      \* (a) Grant ignores max_unavailable
    NoBake,                     \* (b) the next ring starts when a ring finishes, without its bake
    CoordLast,                  \* (c) the nodes update before the coordinator, which updates whenever
    NoHalt,                     \* (d) failures above the budget do not halt
    NoJournal,                  \* (e) the runner keeps its step only in memory: a crash forgets it
    NoEvidence                  \* (f) a ring bakes and widens the rollout with none of its nodes updated

Nodes == Canary \cup Broad
ASSUME Canary \cap Broad = {} /\ Canary # {} /\ Broad # {}
ASSUME CanaryCap >= 1 /\ BroadCap >= 1

Rings == 1..2
RingOf(n) == IF n \in Canary THEN 1 ELSE 2
Cap(r) == IF r = 1 THEN CanaryCap ELSE BroadCap
Budget(r) == IF r = 1 THEN CanaryBudget ELSE BroadBudget

VARIABLES
    \* the rollout (coordinator, durable)
    rs,         \* "planned" | "running" | "paused" | "halted" | "rolling_back" | "rolled_back" | "done"
    kind,       \* "update" (to 2) | "rollback" (the moved nodes back to 1)
    ring,       \* the current ring: 0 = the coordinator, 1 = canary, 2 = broad
    fin,        \* the current ring finished and is baking
    baked,      \* the rings that finished and baked
    coordUpd,   \* the coordinator's own update: "none" | "done" | "rolled_back"
    fails,      \* failures counted per ring (by the slot the node was granted in)
    ns,         \* rollout_nodes.state per node
    slot,       \* the ring whose max_unavailable the node's go was counted in
    want,       \* the version the node's go installs (2, or 1 when rolling back)
    online,     \* the node is up and heartbeating (offline: the machine is down, its runner too)
    \* the node (agent spool and runner)
    req,        \* request.json is in the spool
    rstep,      \* the runner's step: "idle" | "installing" | "probation" | "reverting"
    rup,        \* the runner process is alive
    pkg,        \* the package installed (0: half-installed by a failed install)
    committed,  \* journal.committed: the version the runner last committed
    conf,       \* the new agent wrote "confirmed"
    res,        \* result.json: "none" | "done" | "failed" | "rolled_back"
    \* bookkeeping
    faults, ops,
    moved,      \* ghost: the rollout committed version 2 here at some point
    missed,     \* ghost: the node was waiting offline when its ring baked
    resumed     \* ghost: a runner restarted mid-step

vars == <<rs, kind, ring, fin, baked, coordUpd, fails, ns, slot, want, online,
          req, rstep, rup, pkg, committed, conf, res, faults, ops, moved, missed, resumed>>

Busy == {"go", "draining", "installing", "confirming"}
NodeStates == {"pending", "staged", "done", "failed", "rolled_back", "skip"} \cup Busy
Final == {"done", "halted", "rolled_back"}

TypeOK ==
    /\ rs \in {"planned", "running", "paused", "halted", "rolling_back", "rolled_back", "done"}
    /\ kind \in {"update", "rollback"}
    /\ ring \in 0..2 /\ fin \in BOOLEAN /\ baked \subseteq Rings
    /\ coordUpd \in {"none", "done", "rolled_back"}
    /\ fails \in [Rings -> 0..Cardinality(Nodes)]
    /\ ns \in [Nodes -> NodeStates] /\ slot \in [Nodes -> 0..2] /\ want \in [Nodes -> 1..2]
    /\ online \in [Nodes -> BOOLEAN]
    /\ req \in [Nodes -> BOOLEAN] /\ rstep \in [Nodes -> {"idle", "installing", "probation", "reverting"}]
    /\ rup \in [Nodes -> BOOLEAN] /\ pkg \in [Nodes -> 0..2] /\ committed \in [Nodes -> 1..2]
    /\ conf \in [Nodes -> BOOLEAN] /\ res \in [Nodes -> {"none", "done", "failed", "rolled_back"}]
    /\ faults \in Nat /\ ops \in Nat
    /\ moved \in [Nodes -> BOOLEAN] /\ missed \in [Nodes -> BOOLEAN] /\ resumed \in [Nodes -> BOOLEAN]

Init ==
    /\ rs = "planned" /\ kind = "update" /\ ring = 0 /\ fin = FALSE /\ baked = {}
    /\ coordUpd = "none" /\ fails = [r \in Rings |-> 0]
    /\ ns = [n \in Nodes |-> "pending"] /\ slot = [n \in Nodes |-> 0] /\ want = [n \in Nodes |-> 2]
    /\ online = [n \in Nodes |-> TRUE]
    /\ req = [n \in Nodes |-> FALSE] /\ rstep = [n \in Nodes |-> "idle"] /\ rup = [n \in Nodes |-> TRUE]
    /\ pkg = [n \in Nodes |-> 1] /\ committed = [n \in Nodes |-> 1]
    /\ conf = [n \in Nodes |-> FALSE] /\ res = [n \in Nodes |-> "none"]
    /\ faults = 0 /\ ops = 0
    /\ moved = [n \in Nodes |-> FALSE] /\ missed = [n \in Nodes |-> FALSE] /\ resumed = [n \in Nodes |-> FALSE]

-----------------------------------------------------------------------------
(* Helpers                                                                  *)
-----------------------------------------------------------------------------
CoordVer == IF coordUpd = "done" THEN 2 ELSE 1

CanFault == faults < MaxFaults
SpendFault == faults' = faults + 1
CanOp == ops < MaxOps
SpendOp == ops' = ops + 1

Max(a, b) == IF a >= b THEN a ELSE b

\* The ring whose slots a go is counted in: the current one (a node of an earlier ring catching
\* up joins it); a rollback counts each node in its own ring.
SlotFor(n) == IF kind = "rollback" THEN RingOf(n) ELSE Max(RingOf(n), ring)
BusyIn(r) == {m \in Nodes : ns[m] \in Busy /\ slot[m] = r}

\* The node is assigned the rollout's target (fleetupdates.assigned): its ring started, and the
\* coordinator already runs version 2 (S30).
Assigned(n) ==
    IF kind = "rollback" THEN rs = "rolling_back"
    ELSE /\ rs \in {"running", "paused", "done"}
         /\ ring >= 1
         /\ RingOf(n) <= ring
         /\ CoordVer = 2 \/ CoordLast

\* A member that no longer holds its ring up: done, failed, or waiting offline.
Settled(n) == ns[n] \in {"done", "failed", "rolled_back"} \/ (~online[n] /\ ns[n] \in {"pending", "staged"})
RingSettled(r) == \A n \in Nodes : RingOf(n) <= r => Settled(n)

\* Halting or pausing withdraws a go the node has not acted on.
Withdraw(f) == [m \in Nodes |-> IF f[m] = "go" THEN "staged" ELSE f[m]]

\* A rollback rollout: the nodes this rollout moved (done) go back to version 1; nodes mid-install
\* finish first; the others have nothing to undo (an agent draining for the old target stops).
RollbackNs(f) == [m \in Nodes |-> CASE f[m] = "done" -> "pending"
                                    [] f[m] \in {"installing", "confirming"} -> f[m]
                                    [] OTHER -> "skip"]

NodeVars == <<ns, slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>
RolloutVars == <<rs, kind, ring, fin, baked, coordUpd, fails>>

-----------------------------------------------------------------------------
(* Operator                                                                 *)
-----------------------------------------------------------------------------
Start ==
    /\ rs = "planned"
    /\ rs' = "running"
    /\ ring' = IF CoordLast THEN 1 ELSE 0
    /\ UNCHANGED <<kind, fin, baked, coordUpd, fails, faults, ops>> /\ UNCHANGED NodeVars

Pause ==
    /\ rs = "running" /\ CanOp /\ SpendOp
    /\ rs' = "paused" /\ ns' = Withdraw(ns)
    /\ UNCHANGED <<kind, ring, fin, baked, coordUpd, fails, faults>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* the owner eventually resumes a paused rollout (fair)
ResumePaused ==
    /\ rs = "paused"
    /\ rs' = "running"
    /\ UNCHANGED <<kind, ring, fin, baked, coordUpd, fails, faults, ops>> /\ UNCHANGED NodeVars

Halt ==
    /\ rs \in {"running", "paused"} /\ CanOp /\ SpendOp
    /\ rs' = "halted" /\ ns' = Withdraw(ns)
    /\ UNCHANGED <<kind, ring, fin, baked, coordUpd, fails, faults>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* resuming a halted rollout: not while a ring is over its budget or the coordinator's update rolled back
ResumeHalted ==
    /\ rs = "halted" /\ CanOp /\ SpendOp
    /\ \A r \in Rings : fails[r] <= Budget(r)
    /\ coordUpd # "rolled_back"
    /\ rs' = "running"
    /\ UNCHANGED <<kind, ring, fin, baked, coordUpd, fails, faults>> /\ UNCHANGED NodeVars

Rollback ==
    /\ rs \in {"running", "paused", "halted"} /\ kind = "update" /\ CanOp /\ SpendOp
    /\ rs' = "rolling_back" /\ kind' = "rollback" /\ ns' = RollbackNs(ns)
    /\ UNCHANGED <<ring, fin, baked, coordUpd, fails, faults>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

-----------------------------------------------------------------------------
(* Coordinator                                                              *)
-----------------------------------------------------------------------------
\* Ring 0: the coordinator's own update (D58), which passes its probation ...
CoordUpdate ==
    /\ rs = "running" /\ kind = "update" /\ coordUpd = "none"
    /\ ring = 0 \/ CoordLast
    /\ coordUpd' = "done"
    /\ ring' = IF CoordLast THEN ring ELSE 1
    /\ UNCHANGED <<rs, kind, fin, baked, fails, faults, ops>> /\ UNCHANGED NodeVars

\* ... or fails it: the runner restores the old version and the rollout halts
CoordUpdateFails ==
    /\ rs = "running" /\ kind = "update" /\ coordUpd = "none"
    /\ ring = 0 \/ CoordLast
    /\ CanFault /\ SpendFault
    /\ coordUpd' = "rolled_back" /\ rs' = "halted" /\ ns' = Withdraw(ns)
    /\ UNCHANGED <<kind, ring, fin, baked, fails, ops>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* the slot rule (tick step 3): go to a staged, eligible node while its ring has a free slot
Grant(n) ==
    /\ ns[n] = "staged" /\ online[n] /\ Assigned(n)
    /\ rs \in {"running", "done", "rolling_back"}
    /\ NoCap \/ Cardinality(BusyIn(SlotFor(n))) < Cap(SlotFor(n))
    /\ ns' = [ns EXCEPT ![n] = "go"]
    /\ slot' = [slot EXCEPT ![n] = SlotFor(n)]
    /\ want' = [want EXCEPT ![n] = IF kind = "update" THEN 2 ELSE 1]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* the node's outcome reaches the coordinator (heartbeat), and the tick counts a failure against the
\* ring's budget in the same transaction: above it, halt (and with auto_rollback, roll back)
Report(n) ==
    /\ online[n] /\ rstep[n] = "idle" /\ res[n] # "none"
    /\ ns[n] \in {"installing", "confirming"}
    /\ LET ok    == res[n] = "done"
           count == kind = "update" /\ ~ok /\ rs # "done"
           f2    == IF count THEN [fails EXCEPT ![slot[n]] = @ + 1] ELSE fails
           over  == count /\ f2[slot[n]] > Budget(slot[n]) /\ ~NoHalt /\ rs \in {"running", "paused", "halted"}
           back  == over /\ AutoRollback
           n2    == [ns EXCEPT ![n] =
                        IF kind = "update" THEN res[n]
                        ELSE IF want[n] = 2 THEN (IF ok THEN "pending" ELSE "skip")  \* an update in flight when the rollback began
                        ELSE (IF ok THEN "done" ELSE "pending")]                     \* a rollback install is retried
       IN /\ fails' = f2
          /\ fin' = IF count THEN FALSE ELSE fin
          /\ rs' = IF back THEN "rolling_back" ELSE IF over THEN "halted" ELSE rs
          /\ kind' = IF back THEN "rollback" ELSE kind
          /\ ns' = IF back THEN RollbackNs(n2) ELSE IF over THEN Withdraw(n2) ELSE n2
    /\ res' = [res EXCEPT ![n] = "none"] /\ conf' = [conf EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<ring, baked, coordUpd, faults, ops>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, moved, missed, resumed>>

\* tick step 5: the ring finished (with NoBake the next ring starts at once)
Finish ==
    /\ rs = "running" /\ kind = "update" /\ ring >= 1 /\ ~fin
    /\ RingSettled(ring)
    /\ IF NoBake /\ ring < 2
       THEN ring' = ring + 1 /\ UNCHANGED <<rs, fin>>
       ELSE fin' = TRUE /\ UNCHANGED <<rs, ring>>
    /\ UNCHANGED <<kind, baked, coordUpd, fails, faults, ops>> /\ UNCHANGED NodeVars

\* the bake passed with no failure since the ring finished (a failure clears fin): the next ring starts
Bake ==
    /\ rs = "running" /\ kind = "update" /\ fin
    /\ RingSettled(ring)
    /\ ring = 2 => coordUpd = "done"
    \* widen only on evidence (D59): the canary ring hands over to broad once one of its nodes updated; a canary ring
    \* whose nodes were all offline waits for one to return (inconclusive is a pause)
    /\ (ring = 1 /\ ~NoEvidence) => \E c \in Canary : ns[c] = "done"
    /\ baked' = baked \cup {ring}
    /\ fin' = FALSE
    /\ IF ring = 2 THEN rs' = "done" /\ ring' = ring ELSE ring' = ring + 1 /\ rs' = rs
    /\ missed' = [n \in Nodes |-> missed[n] \/ (RingOf(n) <= ring /\ ~online[n] /\ ns[n] \in {"pending", "staged"})]
    /\ UNCHANGED <<kind, coordUpd, fails, faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, resumed>>

RollbackDone ==
    /\ rs = "rolling_back"
    /\ \A n \in Nodes : ns[n] \in {"done", "skip"}
    /\ rs' = "rolled_back"
    /\ UNCHANGED <<kind, ring, fin, baked, coordUpd, fails, faults, ops>> /\ UNCHANGED NodeVars

-----------------------------------------------------------------------------
(* Agent                                                                    *)
-----------------------------------------------------------------------------
\* the directive arrives; the agent downloads and verifies the package
Stage(n) ==
    /\ ns[n] = "pending" /\ online[n] /\ Assigned(n)
    /\ ns' = [ns EXCEPT ![n] = "staged"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

Drain(n) ==
    /\ ns[n] = "go" /\ online[n]
    /\ ns' = [ns EXCEPT ![n] = "draining"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* drained: the package and request.json go into the spool; the runner owns the outcome from here
Request(n) ==
    /\ ns[n] = "draining" /\ online[n]
    /\ ns' = [ns EXCEPT ![n] = "installing"]
    /\ req' = [req EXCEPT ![n] = TRUE]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<slot, want, online, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

\* the new agent's first hello and heartbeat: it writes "confirmed" and reports confirming
Confirm(n) ==
    /\ online[n] /\ rstep[n] = "probation" /\ pkg[n] = want[n] /\ ~conf[n]
    /\ conf' = [conf EXCEPT ![n] = TRUE]
    /\ ns' = [ns EXCEPT ![n] = IF @ = "installing" THEN "confirming" ELSE @]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<slot, want, online, req, rstep, rup, pkg, committed, res, moved, missed, resumed>>

GoOffline(n) ==
    /\ online[n] /\ CanFault /\ SpendFault
    /\ online' = [online EXCEPT ![n] = FALSE]
    /\ UNCHANGED RolloutVars /\ UNCHANGED ops
    /\ UNCHANGED <<ns, slot, want, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

Return(n) ==
    /\ ~online[n]
    /\ online' = [online EXCEPT ![n] = TRUE]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, req, rstep, rup, pkg, committed, conf, res, moved, missed, resumed>>

-----------------------------------------------------------------------------
(* The node's update runner (root); every step needs the machine up and the *)
(* runner alive, and is journaled before it is taken                       *)
-----------------------------------------------------------------------------
RunnerUp(n) == online[n] /\ rup[n]

\* take the request (journal first, then remove request.json)
Take(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "idle" /\ req[n]
    /\ rstep' = [rstep EXCEPT ![n] = "installing"]
    /\ req' = [req EXCEPT ![n] = FALSE]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, rup, pkg, committed, conf, res, moved, missed, resumed>>

Install(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "installing"
    /\ pkg' = [pkg EXCEPT ![n] = want[n]]
    /\ rstep' = [rstep EXCEPT ![n] = "probation"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, req, rup, committed, conf, res, moved, missed, resumed>>

\* the OS tool fails part way; the runner reinstalls the kept package
InstallFails(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "installing" /\ CanFault /\ SpendFault
    /\ pkg' = [pkg EXCEPT ![n] = 0]
    /\ rstep' = [rstep EXCEPT ![n] = "reverting"]
    /\ res' = [res EXCEPT ![n] = "failed"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED ops
    /\ UNCHANGED <<ns, slot, want, online, req, rup, committed, conf, moved, missed, resumed>>

Commit(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "probation" /\ conf[n]
    /\ committed' = [committed EXCEPT ![n] = want[n]]
    /\ rstep' = [rstep EXCEPT ![n] = "idle"]
    /\ res' = [res EXCEPT ![n] = "done"]
    /\ moved' = [moved EXCEPT ![n] = @ \/ want[n] = 2]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, req, rup, pkg, conf, missed, resumed>>

\* probation ran out without a confirmation (the new agent or launcher never came up)
ProbationExpires(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "probation" /\ ~conf[n] /\ CanFault /\ SpendFault
    /\ rstep' = [rstep EXCEPT ![n] = "reverting"]
    /\ res' = [res EXCEPT ![n] = "rolled_back"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED ops
    /\ UNCHANGED <<ns, slot, want, online, req, rup, pkg, committed, conf, moved, missed, resumed>>

Revert(n) ==
    /\ RunnerUp(n) /\ rstep[n] = "reverting"
    /\ pkg' = [pkg EXCEPT ![n] = committed[n]]
    /\ rstep' = [rstep EXCEPT ![n] = "idle"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, req, rup, committed, conf, res, moved, missed, resumed>>

\* the runner dies mid-step (a crash or a reboot); its journal keeps the step unless NoJournal
RunnerCrash(n) ==
    /\ rup[n] /\ rstep[n] # "idle" /\ CanFault /\ SpendFault
    /\ rup' = [rup EXCEPT ![n] = FALSE]
    /\ rstep' = IF NoJournal THEN [rstep EXCEPT ![n] = "idle"] ELSE rstep
    /\ UNCHANGED RolloutVars /\ UNCHANGED ops
    /\ UNCHANGED <<ns, slot, want, online, req, pkg, committed, conf, res, moved, missed, resumed>>

\* the trigger starts it again (RunAtLoad, the path unit, the helper) and it resumes from its journal
RunnerRestart(n) ==
    /\ ~rup[n] /\ online[n]
    /\ rup' = [rup EXCEPT ![n] = TRUE]
    /\ resumed' = [resumed EXCEPT ![n] = @ \/ rstep[n] # "idle"]
    /\ UNCHANGED RolloutVars /\ UNCHANGED <<faults, ops>>
    /\ UNCHANGED <<ns, slot, want, online, req, rstep, pkg, committed, conf, res, moved, missed>>

-----------------------------------------------------------------------------
Next ==
    \/ Start \/ Pause \/ ResumePaused \/ Halt \/ ResumeHalted \/ Rollback
    \/ CoordUpdate \/ CoordUpdateFails \/ Finish \/ Bake \/ RollbackDone
    \/ \E n \in Nodes :
          \/ Grant(n) \/ Report(n) \/ Stage(n) \/ Drain(n) \/ Request(n) \/ Confirm(n)
          \/ GoOffline(n) \/ Return(n)
          \/ Take(n) \/ Install(n) \/ InstallFails(n) \/ Commit(n) \/ ProbationExpires(n) \/ Revert(n)
          \/ RunnerCrash(n) \/ RunnerRestart(n)

\* Weak fairness on the coordinator's tick, the agents, the runners, machines coming back and the
\* owner resuming a pause. Faults and the other operator actions are unfair (and bounded).
Fairness ==
    /\ WF_vars(CoordUpdate) /\ WF_vars(Finish) /\ WF_vars(Bake) /\ WF_vars(RollbackDone)
    /\ WF_vars(ResumePaused)
    /\ \A n \in Nodes :
          /\ WF_vars(Grant(n)) /\ WF_vars(Report(n)) /\ WF_vars(Stage(n)) /\ WF_vars(Drain(n))
          /\ WF_vars(Request(n)) /\ WF_vars(Confirm(n)) /\ WF_vars(Return(n))
          /\ WF_vars(Take(n)) /\ WF_vars(Install(n)) /\ WF_vars(Commit(n)) /\ WF_vars(Revert(n))
          /\ WF_vars(RunnerRestart(n))

Spec == Init /\ [][Next]_vars /\ Fairness

BroadSymmetry == Permutations(Broad)

-----------------------------------------------------------------------------
(* Properties                                                               *)
-----------------------------------------------------------------------------
\* S29: no ring has more busy nodes (go to confirming) than its max_unavailable.
CapRespected == \A r \in Rings : Cardinality(BusyIn(r)) <= Cap(r)

\* S30 (second half): no node of a later ring is busy or updated by this rollout before every
\* earlier ring finished and baked.
RingOrder ==
    kind = "update" =>
        \A n \in Nodes : (ns[n] \in Busy \/ committed[n] = 2) =>
            \A r \in Rings : r < RingOf(n) => r \in baked

\* S30: no node is assigned, or runs, a version newer than the coordinator's.
NoNodeAheadOfCoordinator ==
    \A n \in Nodes :
        /\ pkg[n] <= CoordVer
        /\ (kind = "update" /\ ns[n] \in {"staged"} \cup Busy) => CoordVer = 2

\* After a halt (or a pause, or once rolled back) no node holds a go it has not acted on, so none
\* starts draining.
HaltedStartsNothing == rs \in {"planned", "paused", "halted", "rolled_back"} => \A n \in Nodes : ns[n] # "go"

\* Failures above a ring's budget imply the rollout halted or is rolling back.
BudgetHalts == (\E r \in Rings : fails[r] > Budget(r)) => rs \in {"halted", "rolling_back", "rolled_back"}

\* A rolled-back rollout leaves every node on the old version.
RolledBackIsOld == rs = "rolled_back" => \A n \in Nodes : pkg[n] = 1 /\ committed[n] = 1

\* When a node's runner has nothing in hand, the node runs what the runner committed: the new
\* version confirmed, or the previous one.
RunnerSafe == \A n \in Nodes : rstep[n] = "idle" => pkg[n] = committed[n]

\* Liveness: once started, the rollout ends done, halted or rolled back, and stays there.
\* The broad ring starts only after a canary node updated in this rollout (the evidence rule; S30's companion)
WidenOnlyOnEvidence == (kind = "update" /\ ring = 2) => \E c \in Canary : moved[c]

Ends == (rs # "planned") ~> [](rs \in Final)

-----------------------------------------------------------------------------
(* Reachability witnesses (vacuity checks), each EXPECTED to be violated.   *)
-----------------------------------------------------------------------------
\* every node runs version 2 and the rollout is done
W_FleetUpdated == ~(rs = "done" /\ \A n \in Nodes : pkg[n] = 2 /\ committed[n] = 2)

\* the canary failed (budget 0): halted and rolled back
W_RolledBackAfterCanaryFailure == ~(rs = "rolled_back" /\ fails[1] > 0)

\* the broad ring went over its budget after the canary moved: auto_rollback took the canary back to 1
W_MovedNodeRolledBack == ~(rs = "rolled_back" /\ fails[2] > BroadBudget /\ \E n \in Nodes : moved[n])

\* a node offline while its ring ran and baked returned and was updated later
W_OfflineNodeCaughtUp == ~(\E n \in Nodes : missed[n] /\ committed[n] = 2)

\* a runner crashed mid-update, resumed from its journal, and committed
W_CommittedAfterRunnerCrash == ~(\E n \in Nodes : resumed[n] /\ committed[n] = 2 /\ rstep[n] = "idle")

\* a broad node updated although no canary node ever did (the canary was offline while its ring ran:
\* it finished waiting(offline) and baked with no evidence; see the README)

\* the coordinator's own update rolled back and the rollout halted before any node
W_CoordinatorRolledBack == ~(coordUpd = "rolled_back" /\ rs = "halted")

=============================================================================
