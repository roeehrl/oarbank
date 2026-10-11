---------------------------- MODULE OarbankSeat ----------------------------
(***************************************************************************)
(* Seat leases for single-seat workloads (docs/design/workloads.md, D46,   *)
(* invariant S26): one seat (one identity) and a few nodes.                *)
(*                                                                         *)
(* The coordinator keeps, durably, the seat's holder, its fence and the    *)
(* lease's end, plus the owner's assignments. At every heartbeat of node N *)
(* it (1) frees the seat when N is the holder and reports the workload not *)
(* running under the current fence and asks for release (it gave the seat  *)
(* up: its lease lapsed, it was unassigned, the workload was withdrawn or  *)
(* cannot run there); a report with an older fence is ignored. Then (2) it *)
(* grants or renews the seat to N when N is assigned                       *)
(* and the seat is free, held by N, or its lease ended more than the grace *)
(* G ago; a new holder raises the fence. The reply says "run" with the     *)
(* fence and lease_s = lease_until - now, or "stop" (seat elsewhere) or    *)
(* "unassigned".                                                           *)
(*                                                                         *)
(* The agent applies only the reply to its outstanding request (an HTTP    *)
(* reply on the request's own connection). The lease ends at sent +        *)
(* lease_s on the node's boot clock, where sent is when the request was    *)
(* sent; the agent starts the workload when the reply says "run" and that  *)
(* end is still ahead, stops it when the lease lapses, when the reply says *)
(* "stop"/"unassigned" or names another fence, and reports the stop with   *)
(* the fence it ran under in its next request. The workload survives an    *)
(* agent crash; the next agent adopts it only while its lease runs. A      *)
(* reboot kills it.                                                        *)
(*                                                                         *)
(* Time. Every clock is kept relative to the global "now": the coordinator *)
(* keeps lrem = lease_until - now, each agent drem = deadline - its clock, *)
(* each message its age on the sender's clock (now - sent). Tick advances  *)
(* time by one unit and shifts every timer, clamped at the point past      *)
(* which only "expired" matters. So time is unbounded while the state      *)
(* space is finite, which the liveness check needs.                        *)
(*                                                                         *)
(* "Acts in time": Tick is disabled while an awake node's workload is      *)
(* running at its lease's end (the agent stops it before time moves on).   *)
(* A sleeping node takes no steps while time advances; it wakes with its   *)
(* lapse check done first (Wake). A node whose agent is down is assumed to *)
(* get it back before the workload's lease ends (launchd / systemd / the   *)
(* service manager restart it in seconds); AgentDownPastLease = TRUE drops *)
(* that assumption.                                                        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Nodes,              \* nodes that may be assigned the workload
    None,               \* model value: no holder
    L,                  \* lease length (1800 s in the code)
    G,                  \* grace after the lease's end before another node may take the seat (60 s)
    MaxFence,           \* state constraint on the fence (holder changes)
    MaxMsgs,            \* at most this many messages of one node in flight
    MaxFaults,          \* budget for loss, sleep, agent crash, reboot, give-up, coordinator restart
                        \* (Unbounded: no budget)
    PatientHeartbeat,   \* TRUE: an agent sends a new heartbeat only when the previous one is answered or
                        \*       lost; FALSE: also while it is merely delayed (it timed out), which leaves
                        \*       the old request in flight to be processed later
    TimelyNetwork,      \* liveness assumption: a round trip of an awake node takes under L - 1 ticks
    AgentDownPastLease, \* environment: an agent may stay down past its workload's lease (see above)
    \* Release rule (see "Release" in the README):
    ReleaseIfUnassigned,    \* the coordinator also frees the seat on a stop report without release from a
                            \* holder that is no longer assigned (finding F1: unsafe unless FencePerRun)
    FencePerRun,            \* a grant to a node that reports its workload not running raises the fence,
                            \* so every run has a fence of its own
    \* Weakened variants (all FALSE in the protocol as designed):
    NoFenceOnRelease,       \* (a) any "not running" report from the holder frees the seat, whatever its fence
    RenewAfterExpiry,       \* (b) the agent also applies a late reply to a request it gave up on
    NoGraceOrExpiry,        \* (c) the coordinator hands the seat to any assigned node that asks
    DeadlineFromReceive,    \* (d) the agent's lease ends at receive time + lease_s
    AdoptWithoutLeaseCheck, \* (e) a new agent adopts a live workload without looking at its lease
    ClockStopsInSleep       \* (f) the agent's lease clock stops while the machine sleeps

ASSUME L \in Nat /\ L >= 2 /\ G \in Nat /\ MaxMsgs >= 1

VARIABLES
    \* coordinator (durable)
    holder,     \* Nodes \cup {None}
    fence,      \* the seat's fence
    lrem,       \* lease_until - now, clamped at Floor
    assigned,   \* [Nodes -> BOOLEAN], the owner's assignments
    \* agents
    running,    \* the workload runs on the node
    frun,       \* the fence it runs (or last ran) under; kept after a stop so the stop is reported with it
    drem,       \* the lease's end minus the node's boot clock; 0 = ended; NoDeadline = no lease known
    up,         \* the agent process is alive
    asleep,     \* the machine sleeps
    gaveup,     \* the node gave the seat up (its lease lapsed locally, or the workload was withdrawn
                \* or cannot run there); its stop report then asks for release
    \* network
    msgs,       \* requests and replies in flight
    \* bookkeeping
    faults,     \* faults spent
    prev,       \* the seat's last holder (ghost: for the witnesses)
    ev          \* the last notable event (ghost: for the witnesses)

vars == <<holder, fence, lrem, assigned, running, frun, drem, up, asleep, gaveup, msgs, faults, prev, ev>>

Unbounded == -1         \* cfg: MaxFaults <- Unbounded
Floor == -(G + 1)       \* lrem < -G <=> now > lease_until + G; nothing below matters
NoDeadline == -1

Msg == [k : {"req", "rep"}, n : Nodes, cur : BOOLEAN, age : 0..L, run : BOOLEAN, rls : BOOLEAN,
        f : Nat, d : {"none", "run", "stop", "unassigned"}, ls : 0..L]

TypeOK ==
    /\ holder \in Nodes \cup {None}
    /\ fence \in Nat
    /\ lrem \in Floor..L
    /\ assigned \in [Nodes -> BOOLEAN]
    /\ running \in [Nodes -> BOOLEAN]
    /\ frun \in [Nodes -> Nat]
    /\ drem \in [Nodes -> {NoDeadline} \cup 0..L]
    /\ up \in [Nodes -> BOOLEAN]
    /\ asleep \in [Nodes -> BOOLEAN]
    /\ gaveup \in [Nodes -> BOOLEAN]
    /\ msgs \subseteq Msg
    /\ faults \in Nat
    /\ prev \in Nodes \cup {None}
    /\ ev \in {"none", "expiry", "release", "adopt"}

Init ==
    /\ holder = None
    /\ fence = 0
    /\ lrem = Floor
    /\ assigned = [n \in Nodes |-> FALSE]
    /\ running = [n \in Nodes |-> FALSE]
    /\ frun = [n \in Nodes |-> 0]
    /\ drem = [n \in Nodes |-> 0]
    /\ up = [n \in Nodes |-> TRUE]
    /\ asleep = [n \in Nodes |-> FALSE]
    /\ gaveup = [n \in Nodes |-> FALSE]
    /\ msgs = {}
    /\ faults = 0
    /\ prev = None
    /\ ev = "none"

-----------------------------------------------------------------------------
(* Helpers                                                                  *)
-----------------------------------------------------------------------------
Max(a, b) == IF a >= b THEN a ELSE b

CanFault == MaxFaults < 0 \/ faults < MaxFaults
SpendFault == faults' = IF MaxFaults < 0 THEN faults ELSE faults + 1

\* The node's lease clock advances with global time (the boot clock counts sleep).
ClockRuns(n) == ~(ClockStopsInSleep /\ asleep[n])

\* The agent gives up on its outstanding request (it sends a new one, crashes, or the machine
\* reboots): the request may still reach the coordinator, but its reply will not be applied. In
\* the protocol as designed such a reply is as good as lost, so it is dropped (fewer states).
Abandon(n) ==
    IF RenewAfterExpiry
    THEN {IF m.n = n THEN [m EXCEPT !.cur = FALSE] ELSE m : m \in msgs}
    ELSE {IF m.n = n THEN [m EXCEPT !.cur = FALSE, !.age = 0] ELSE m :
              m \in {x \in msgs : ~(x.n = n /\ x.k = "rep")}}

Stop(n) ==
    /\ running' = [running EXCEPT ![n] = FALSE]
    /\ drem' = [drem EXCEPT ![n] = 0]

\* An awake node's workload has reached its lease's end: the agent must act before time moves.
MustAct(n) ==
    /\ running[n]
    /\ drem[n] = 0
    /\ IF up[n] THEN ~asleep[n] ELSE ~AgentDownPastLease

-----------------------------------------------------------------------------
(* Time                                                                     *)
-----------------------------------------------------------------------------
Tick ==
    /\ \A n \in Nodes : ~MustAct(n)
    /\ TimelyNetwork => \A m \in msgs : (m.cur /\ up[m.n] /\ ~asleep[m.n]) => m.age < L - 1
    /\ lrem' = Max(lrem - 1, Floor)
    /\ drem' = [n \in Nodes |-> IF ClockRuns(n) /\ drem[n] > 0 THEN drem[n] - 1 ELSE drem[n]]
    /\ msgs' = {IF ClockRuns(m.n) /\ (m.cur \/ RenewAfterExpiry) /\ m.age < L
                THEN [m EXCEPT !.age = m.age + 1] ELSE m : m \in msgs}
    /\ UNCHANGED <<holder, fence, assigned, running, frun, up, asleep, faults, prev, ev, gaveup>>

-----------------------------------------------------------------------------
(* Owner                                                                    *)
-----------------------------------------------------------------------------
Assign(n) ==
    /\ ~assigned[n]
    /\ assigned' = [assigned EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<holder, fence, lrem, running, frun, drem, up, asleep, msgs, faults, prev, ev, gaveup>>

Unassign(n) ==
    /\ assigned[n]
    /\ assigned' = [assigned EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<holder, fence, lrem, running, frun, drem, up, asleep, msgs, faults, prev, ev, gaveup>>

-----------------------------------------------------------------------------
(* Coordinator: one heartbeat request (one transaction)                     *)
-----------------------------------------------------------------------------
HandleReq(m) ==
    /\ m \in msgs
    /\ m.k = "req"
    /\ LET n     == m.n
           rel   == /\ ~m.run
                    /\ holder = n
                    /\ NoFenceOnRelease \/ m.f = fence
                    /\ m.rls \/ (ReleaseIfUnassigned /\ ~assigned[n])   \* the node gave the seat up
           h1    == IF rel THEN None ELSE holder
           grant == /\ assigned[n]
                    /\ \/ h1 = None
                       \/ h1 = n
                       \/ lrem < -G
                       \/ NoGraceOrExpiry
           f1    == IF grant /\ (h1 # n \/ (FencePerRun /\ ~m.run)) THEN fence + 1 ELSE fence
           rep   == IF grant
                    THEN [k |-> "rep", n |-> n, cur |-> m.cur, age |-> m.age, run |-> FALSE, rls |-> FALSE,
                          f |-> f1, d |-> "run", ls |-> L]
                    ELSE [k |-> "rep", n |-> n, cur |-> m.cur, age |-> m.age, run |-> FALSE, rls |-> FALSE,
                          f |-> 0, d |-> IF assigned[n] THEN "stop" ELSE "unassigned", ls |-> 0]
       IN /\ holder' = IF grant THEN n ELSE h1
          /\ fence' = f1
          /\ lrem' = IF grant THEN L ELSE lrem
          /\ msgs' = (msgs \ {m}) \cup (IF m.cur \/ RenewAfterExpiry THEN {rep} ELSE {})
          /\ prev' = IF grant THEN n ELSE prev
          /\ ev' = IF grant /\ prev \notin {None, n}
                   THEN IF h1 # None THEN "expiry"             \* taken over after lease + grace
                        ELSE IF lrem >= 0 THEN "release"        \* freed by a fenced report, lease still running
                        ELSE ev
                   ELSE ev
    /\ UNCHANGED <<assigned, running, frun, drem, up, asleep, gaveup, faults>>

\* The coordinator restarts: its state is durable, requests and replies in flight are lost.
CoordRestart ==
    /\ CanFault
    /\ msgs # {}
    /\ msgs' = {}
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, running, frun, drem, up, asleep, prev, ev, gaveup>>

-----------------------------------------------------------------------------
(* Network                                                                  *)
-----------------------------------------------------------------------------
Lose(m) ==
    /\ m \in msgs
    /\ CanFault
    /\ msgs' = msgs \ {m}
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, running, frun, drem, up, asleep, prev, ev, gaveup>>

-----------------------------------------------------------------------------
(* Agent                                                                    *)
-----------------------------------------------------------------------------
SendHeartbeat(n) ==
    /\ up[n] /\ ~asleep[n]
    /\ PatientHeartbeat => ~\E m \in msgs : m.n = n /\ m.cur
    /\ Cardinality({m \in Abandon(n) : m.n = n}) < MaxMsgs
    /\ msgs' = Abandon(n) \cup {[k |-> "req", n |-> n, cur |-> TRUE, age |-> 0, run |-> running[n],
                                 rls |-> gaveup[n] /\ ~running[n], f |-> frun[n], d |-> "none", ls |-> 0]}
    /\ UNCHANGED <<holder, fence, lrem, assigned, running, frun, drem, up, asleep, faults, prev, ev, gaveup>>

\* The agent applies the reply to its outstanding request.
Receive(m) ==
    /\ m \in msgs
    /\ m.k = "rep"
    /\ up[m.n] /\ ~asleep[m.n]
    /\ m.cur \/ RenewAfterExpiry
    /\ msgs' = msgs \ {m}
    /\ LET n  == m.n
           nd == IF DeadlineFromReceive THEN m.ls ELSE m.ls - m.age   \* the lease's end, relative
       IN IF m.d = "run"
          THEN IF running[n] /\ m.f # frun[n]
               THEN /\ Stop(n)                               \* another fence: stop the current run first
                    /\ UNCHANGED <<frun, gaveup>>
               ELSE IF running[n]
               THEN /\ drem' = [drem EXCEPT ![n] = Max(nd, 0)]   \* renewed
                    /\ UNCHANGED <<running, frun, gaveup>>
               ELSE IF nd > 0
               THEN /\ running' = [running EXCEPT ![n] = TRUE]   \* start
                    /\ frun' = [frun EXCEPT ![n] = m.f]
                    /\ drem' = [drem EXCEPT ![n] = nd]
                    /\ gaveup' = [gaveup EXCEPT ![n] = FALSE]
               ELSE UNCHANGED <<running, frun, drem, gaveup>>    \* the lease already ended
          ELSE /\ IF running[n]
                  THEN /\ Stop(n)
                       /\ UNCHANGED frun
                  ELSE UNCHANGED <<running, frun, drem>>
               \* "unassigned": the node gives the seat up, and its next report asks for release
               /\ gaveup' = IF m.d = "unassigned" THEN [gaveup EXCEPT ![n] = TRUE] ELSE gaveup
    /\ UNCHANGED <<holder, fence, lrem, assigned, up, asleep, faults, prev, ev>>

\* The lease ended on the node's clock (WORKLOAD_SEAT_LEASE_EXPIRED).
Lapse(n) ==
    /\ up[n] /\ ~asleep[n]
    /\ running[n] /\ drem[n] = 0
    /\ Stop(n)
    /\ gaveup' = [gaveup EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<holder, fence, lrem, assigned, frun, up, asleep, msgs, faults, prev, ev>>

\* The agent process dies; the workload (a lasting process) keeps running, and the agent's record
\* keeps its fence and lease end.
AgentCrash(n) ==
    /\ up[n] /\ ~asleep[n]
    /\ CanFault
    /\ up' = [up EXCEPT ![n] = FALSE]
    /\ msgs' = Abandon(n)
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, running, frun, drem, asleep, prev, ev, gaveup>>

\* A new agent reads the record: it adopts the workload only while the lease runs.
AgentRestart(n) ==
    /\ ~up[n] /\ ~asleep[n]
    /\ up' = [up EXCEPT ![n] = TRUE]
    /\ IF running[n]
       THEN IF AdoptWithoutLeaseCheck
            THEN /\ drem' = [drem EXCEPT ![n] = NoDeadline]   \* adopted; lease from the next directive
                 /\ ev' = "adopt"
                 /\ UNCHANGED running
            ELSE IF drem[n] > 0
            THEN /\ ev' = "adopt"
                 /\ UNCHANGED <<running, drem>>
            ELSE /\ Stop(n)                                  \* the lease lapsed: stop, give up
                 /\ UNCHANGED ev
       ELSE UNCHANGED <<running, drem, ev>>
    /\ gaveup' = IF running[n] /\ ~AdoptWithoutLeaseCheck /\ drem[n] = 0
                 THEN [gaveup EXCEPT ![n] = TRUE] ELSE gaveup
    /\ UNCHANGED <<holder, fence, lrem, assigned, frun, asleep, msgs, faults, prev>>

\* The machine reboots: the workload dies, the record's lease is void (another boot); the fence it
\* ran under is still on disk and the next report carries it.
Reboot(n) ==
    /\ ~asleep[n]
    /\ CanFault
    /\ running' = [running EXCEPT ![n] = FALSE]
    /\ drem' = [drem EXCEPT ![n] = 0]
    /\ up' = [up EXCEPT ![n] = TRUE]
    /\ msgs' = Abandon(n)
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, frun, asleep, prev, ev, gaveup>>

\* The node gives the seat up: the workload was withdrawn (max_failures), held past its pause
\* tolerance, or can no longer run there. The agent stops it if it runs.
GiveUp(n) ==
    /\ up[n] /\ ~asleep[n]
    /\ ~gaveup[n]
    /\ CanFault
    /\ gaveup' = [gaveup EXCEPT ![n] = TRUE]
    /\ Stop(n)
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, frun, up, asleep, msgs, prev, ev>>

\* The machine sleeps without warning: no steps of its own until it wakes.
Sleep(n) ==
    /\ ~asleep[n]
    /\ CanFault
    /\ asleep' = [asleep EXCEPT ![n] = TRUE]
    /\ SpendFault
    /\ UNCHANGED <<holder, fence, lrem, assigned, running, frun, drem, up, msgs, prev, ev, gaveup>>

\* On wake, a live agent's lapse check runs before the workload does anything.
Wake(n) ==
    /\ asleep[n]
    /\ asleep' = [asleep EXCEPT ![n] = FALSE]
    /\ IF running[n] /\ up[n] /\ drem[n] = 0
       THEN /\ Stop(n)
            /\ gaveup' = [gaveup EXCEPT ![n] = TRUE]
       ELSE UNCHANGED <<running, drem, gaveup>>
    /\ UNCHANGED <<holder, fence, lrem, assigned, frun, up, msgs, faults, prev, ev>>

-----------------------------------------------------------------------------
Next ==
    \/ Tick
    \/ CoordRestart
    \/ \E n \in Nodes :
          \/ Assign(n) \/ Unassign(n)
          \/ SendHeartbeat(n) \/ Lapse(n)
          \/ AgentCrash(n) \/ AgentRestart(n) \/ Reboot(n) \/ GiveUp(n)
          \/ Sleep(n) \/ Wake(n)
    \/ \E m \in msgs : HandleReq(m) \/ Receive(m) \/ Lose(m)

\* Weak fairness on time, the coordinator, delivery and the agents. Faults and the owner are
\* unfair; faults are bounded by MaxFaults in the liveness configuration, so delivery is
\* eventually reliable.
Fairness ==
    /\ WF_vars(Tick)
    /\ \A n \in Nodes :
          /\ WF_vars(SendHeartbeat(n))
          /\ WF_vars(\E m \in msgs : m.n = n /\ HandleReq(m))
          /\ WF_vars(\E m \in msgs : m.n = n /\ Receive(m))
          /\ WF_vars(Lapse(n))
          /\ WF_vars(AgentRestart(n))
          /\ WF_vars(Wake(n))

Spec == Init /\ [][Next]_vars /\ Fairness

SeatConstraint == fence <= MaxFence

NodeSymmetry == Permutations(Nodes)

-----------------------------------------------------------------------------
(* Properties                                                               *)
-----------------------------------------------------------------------------
\* The workload makes progress on the node (a sleeping machine's processes are frozen).
Active(n) == running[n] /\ ~asleep[n]

\* S26: at most one node runs the seat at a time.
AtMostOneRunning ==
    \A n, o \in Nodes : n # o => ~(Active(n) /\ Active(o))

\* A running workload runs under the seat's current fence, on the holder, and its lease ends on
\* the node no later than the coordinator's lease.
RunningHasLease ==
    \A n \in Nodes : Active(n) =>
        /\ holder = n
        /\ frun[n] = fence
        /\ 0 <= drem[n]
        /\ drem[n] <= lrem

FenceMonotonic == [][fence' >= fence]_fence

\* Liveness: a node that is the only one assigned eventually runs the workload (unless the
\* assignment changes first) ...
OnlyAssigned(n) == \A x \in Nodes : assigned[x] = (x = n)
EventuallyRuns ==
    \A n \in Nodes : [](OnlyAssigned(n) ~> (running[n] \/ ~OnlyAssigned(n)))

\* ... and a seat that is free, or held by an unassigned node, is eventually granted to an
\* assigned node (unless no node is assigned any more).
SomeAssigned == \E x \in Nodes : assigned[x]
HeldByAssigned == holder # None /\ assigned[holder]
SeatReGranted ==
    [](SomeAssigned /\ ~HeldByAssigned ~> (HeldByAssigned \/ ~SomeAssigned))

\* The owner is unfair: one who keeps moving the assignment faster than a heartbeat round trip
\* can keep any node from ever being granted the seat. The liveness properties are checked for
\* behaviours in which the assignments eventually stop changing.
OwnerSettles == <>[][FALSE]_assigned        \* from some point on, assigned never changes
EventuallyRunsOnceSettled == OwnerSettles => EventuallyRuns
SeatReGrantedOnceSettled == OwnerSettles => SeatReGranted

-----------------------------------------------------------------------------
(* Reachability witnesses (vacuity checks), each EXPECTED to be violated.   *)
-----------------------------------------------------------------------------
\* The seat moved to another node after the old holder's lease (and grace) ran out, and the new
\* holder runs it.
W_SeatMovedAfterExpiry == ~(ev = "expiry" /\ holder # None /\ Active(holder))

\* The seat moved to another node before the old lease ended, on the old holder's fenced report
\* that it stopped, and the new holder runs it.
W_SeatMovedOnRelease == ~(ev = "release" /\ holder # None /\ Active(holder))

\* A new agent adopted a running workload across an agent restart.
W_AdoptedAcrossRestart == ~(ev = "adopt" /\ \E n \in Nodes : Active(n))

=============================================================================
