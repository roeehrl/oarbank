---------------------------- MODULE OarbankLease ----------------------------
(***************************************************************************)
(* oarbank lease / fencing / acceptance protocol, as implemented by       *)
(* src/oarbank/coordinator/core.py at commit bb04f9d (fixes for F1-F6).       *)
(*                                                                         *)
(* One coordinator (oarbankd: a durable SQLite DB plus volatile handler      *)
(* state) and a set of agents (Macs). Agents claim jobs, run attempts and  *)
(* report completions, releases and failures through a durable outbox over *)
(* a network that delays, reorders, duplicates and drops their messages.   *)
(* The coordinator fences completions (attempt state, node quarantine, job *)
(* generation, certification generation, settled job, dispute party),    *)
(* makes at most one result canonical per job, compares late completions  *)
(* with the canonical result, convicts a node that gives two different     *)
(* results, opens a quorum dispute (new generation) when two nodes differ, *)
(* lets an uninvolved node break the tie, quarantines the outvoted node    *)
(* and invalidates its canonical results, and re-runs sampled jobs as      *)
(* replica jobs when another node can run them.                            *)
(*                                                                         *)
(* Time is abstract. A lease that nobody renews (the agent does not run    *)
(* the attempt, or is asleep) expires by the fair action ReapOrphan; any   *)
(* other live lease may also expire spuriously (Expire, a counted fault:   *)
(* lost heartbeats, a coordinator restart, a long stall).                  *)
(*                                                                         *)
(* Each state-changing core.py function is one atomic step, because it is  *)
(* one `with db.tx()` (BEGIN IMMEDIATE ... COMMIT) under the process lock, *)
(* and its `post` callbacks run before the commit. The claim handler is    *)
(* two steps when ClaimReadsNodeInTx = FALSE (the pre-5ed1465 code): the   *)
(* node row claim() trusted was read by the auth dependency before the     *)
(* transaction.                                                            *)
(*                                                                         *)
(* Faults (bounded by MaxFaults, so delivery is eventually reliable):      *)
(*   message drop, lost response, lost grant, spurious lease expiry, agent *)
(*   sleep, agent release (preempt / sleep / user active), agent execution *)
(*   failure, coordinator crash, module revocation (golden mismatch),      *)
(*   operator quarantine.                                                  *)
(* User operations (bounded by MaxUserOps): retry_job and cancel_job.      *)
(* Not modelled: golden jobs, studies/trials, resources and caps, hard     *)
(* deadlines, heartbeat progress accounting, enrollment, releases.         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Nodes,              \* agents (Macs)
    EvalJobs,           \* eval jobs (kind 'eval'), pending at the start
    ReplicaJobs,        \* replica jobs (kind 'replica'), created by _maybe_replicate
    ReplicaTarget,      \* the eval job every replica job re-runs (a sampled job_key); NoJob if none
    FaultyNodes,        \* nodes whose output may differ from the correct one ("A")
    FaultyAlwaysWrong,  \* TRUE: a faulty node always returns "B"; FALSE: "A" or "B" at random
    NoJob, NoNode,      \* model values used in unallocated attempt slots
    MaxAtt,             \* attempt ids 1..MaxAtt (AUTOINCREMENT attempt_id)
    MaxFaults,          \* fault budget
    MaxUserOps,         \* budget for retry_job + cancel_job
    MaxExecFailures,    \* config.MAX_EXEC_FAILURES
    Variant,            \* weakened variant: "none" | "nofence" | "noreturn" | "nodemote" | "nonatomic"
    \* TRUE/FALSE switches. The value core.py@5ed1465 has is given after "="; the opposite value
    \* is the older behaviour (commit named), kept as a weakened variant.
    ClaimReadsNodeInTx,       \* = TRUE   claim() re-reads the node row in its transaction (F1; 5ed1465)
    DisputeFencesParties,     \* = TRUE   complete() rejects a dispute party's completion (F2b; 5ed1465)
    DisputeBumpsGen,          \* = TRUE   opening a dispute bumps the job generation (F2a; 5ed1465)
    SettledJobFence,          \* = TRUE   complete() rejects results for cancelled/quarantined jobs (5ed1465)
    SelfInconsistencyConvicts,\* = TRUE   two different results from one node for a done job convict it (F2c)
    ReplicaNeedsEligible,     \* = TRUE   _maybe_replicate only if another eligible node exists (F3; 5ed1465)
    ReapCancelsReplica,       \* = TRUE   reap() cancels a pending replica no eligible node can run (F3)
    CompleteFencesQuarantine, \* = TRUE   complete() rejects results from quarantined nodes (8e5abc6)
    BreakerFencesAttempts,    \* = TRUE   fail()'s breaker revokes like revoke_module (27aa459)
    StrictFailedHere,         \* = FALSE  failed_here is a preference, not an exclusion (8e5abc6)
    CertifyingIsEligible,     \* = TRUE   _can_serve counts a 'certifying' node ...
    CertifyingGrace,          \* = TRUE   ... only until CERTIFYING_GRACE_S has passed (F5; bb04f9d)
    GoldenFailLimit,          \* = TRUE   MAX_EXEC_FAILURES golden failures per (node, module) -> golden_failed,
                              \*          goldens cancelled, no breaker; queue_goldens cancels stale sets (F6)
    \* Environment (not code):
    CertifyMayStall,          \* TRUE: a node's golden jobs may neither pass nor fail (leases keep expiring),
                              \*       so passing them (Recertify) is not fair
    GoldenFailNodes,          \* nodes whose golden jobs always fail (they never recertify)
    \* the module host: module code runs out of process and completion needs the module's verdict.
    ModuleFaults,             \* environment: the module host may be down (bounded by MaxFaults)
    AwaitHoldsLease           \* = TRUE   a completion answered 503 because its module is down marks the attempt
                              \*          awaiting_module: its lease is held and it never expires or is killed
                              \*          (FALSE: the lease is left to lapse, the weakened variant)

ASSUME Variant \in {"none", "nofence", "noreturn", "nodemote", "nonatomic"}
ASSUME FaultyNodes \subseteq Nodes
ASSUME EvalJobs \cap ReplicaJobs = {}
ASSUME ReplicaJobs # {} => ReplicaTarget \in EvalJobs
ASSUME MaxAtt \in Nat /\ MaxFaults \in Nat /\ MaxUserOps \in Nat
ASSUME {FaultyAlwaysWrong, ClaimReadsNodeInTx, DisputeFencesParties, DisputeBumpsGen, SettledJobFence,
        SelfInconsistencyConvicts, ReplicaNeedsEligible, ReapCancelsReplica, CompleteFencesQuarantine,
        BreakerFencesAttempts, StrictFailedHere, CertifyingIsEligible, CertifyingGrace,
        GoldenFailLimit, CertifyMayStall, ModuleFaults, AwaitHoldsLease} \subseteq BOOLEAN
ASSUME GoldenFailNodes \subseteq Nodes

Jobs      == EvalJobs \cup ReplicaJobs
ReplicaOf == [j \in Jobs |-> IF j \in ReplicaJobs THEN ReplicaTarget ELSE NoJob]
AttIds    == 1..MaxAtt
Values    == {"A", "B"}              \* "A" is the correct output
Vals(n)   == IF n \notin FaultyNodes THEN {"A"} ELSE IF FaultyAlwaysWrong THEN {"B"} ELSE Values
Slots     == {1, 2}                  \* handler threads; used only by Variant "nonatomic"
IsEval(j) == ReplicaOf[j] = NoJob
Terminal  == {"done", "cancelled", "quarantined"}

\* Agent -> coordinator reports (outbox entries and network messages).
\*   C = POST /complete (idempotency_key att-<a>-complete), R = POST /release, F = POST /fail
Reports == [k : {"C"}, a : AttIds, v : Values] \cup [k : {"R", "F"}, a : AttIds, v : {"-"}]

\* One attempts row joined with its results row (results.attempt_id is UNIQUE).
\*   g = attempts.generation, cg = attempts.cert_generation, st = attempts.state,
\*   rv = result value ("none" = no results row), racc = results.accepted, rcan = results.canonical
NoAttempt == [j |-> NoJob, n |-> NoNode, g |-> 0, cg |-> 0, st |-> "none",
              rv |-> "none", racc |-> FALSE, rcan |-> FALSE, aw |-> FALSE]
\*   aw = attempts.phase = 'awaiting_module'

VARIABLES
    job,       \* DB jobs: [st, g, canon (canonical_result_id as attempt id, 0 = NULL), fails,
               \*           disp (dispute_json.nodes), dres (dispute_json.results as attempt ids)]
    att,       \* DB attempts + results, AttIds -> record
    nextAtt,   \* next attempt id
    cert,      \* DB modules_json[m].generation per node; negative = revoked (core.py writes -1)
    brk,       \* DB modules_json[m].state='revoked' with the generation kept (pre-27aa459 breaker)
    cfy,       \* DB modules_json[m].state='certifying' (golden jobs queued after a revocation)
    gold,      \* per node: [gfd: state='golden_failed', gfail: golden_failures, sets: pending golden
               \*  sets, graceOver: CERTIFYING_GRACE_S passed since certifying_since,
               \*  gcons: history, golden failures since the last certification or golden_failed]
    quar,      \* DB nodes.lifecycle = 'quarantined'
    ghost,     \* history variables for the properties
    up,        \* coordinator process is running
    snap,      \* volatile: cert generation read by auth_node for an in-progress claim (0 = none)
    inflight,  \* volatile: completions past the idempotency check, not yet applied (nonatomic only)
    running,   \* agent: attempts whose process is running (volatile on the agent)
    asleep,    \* agent: the machine asleep (silent)
    outbox,    \* agents: durable outboxes (the attempt determines the node)
    net,       \* in-flight messages (a set: reordering; a resend while unacked = duplicate)
    faults,
    userOps,
    modUp      \* the module host can evaluate completions

vars == <<job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight,
          running, asleep, outbox, net, faults, userOps, modUp>>

-----------------------------------------------------------------------------
TypeOK ==
    /\ \A j \in Jobs : /\ job[j].st \in {"absent", "pending", "leased", "done", "cancelled", "quarantined"}
                       /\ job[j].g \in Nat /\ job[j].canon \in 0..MaxAtt
                       /\ job[j].disp \subseteq Nodes /\ job[j].dres \subseteq AttIds
    /\ \A a \in AttIds : att[a].st \in {"none", "live", "completed", "released",
                                          "expired", "failed", "revoked"}
    /\ nextAtt \in 1..(MaxAtt + 1)
    /\ cert \in [Nodes -> Int]
    /\ brk \in [Nodes -> BOOLEAN]
    /\ cfy \in [Nodes -> BOOLEAN]
    /\ gold \in [Nodes -> [gfd : BOOLEAN, gfail : 0..MaxExecFailures, sets : 0..2,
                           graceOver : BOOLEAN, gcons : 0..(MaxExecFailures + 1)]]
    /\ quar \in [Nodes -> BOOLEAN]
    /\ up \in BOOLEAN
    /\ snap \in [Nodes -> Int]
    /\ inflight \subseteq (Reports \X Slots)
    /\ running \in [Nodes -> SUBSET AttIds]
    /\ asleep \in [Nodes -> BOOLEAN]
    /\ outbox \subseteq Reports
    /\ net \subseteq Reports
    /\ faults \in 0..MaxFaults
    /\ userOps \in 0..MaxUserOps
    /\ modUp \in BOOLEAN

Init ==
    /\ job = [j \in Jobs |-> [st |-> IF IsEval(j) THEN "pending" ELSE "absent",
                              g |-> 1, canon |-> 0, fails |-> 0, disp |-> {}, dres |-> {}]]
    /\ att = [a \in AttIds |-> NoAttempt]
    /\ nextAtt = 1
    /\ cert = [n \in Nodes |-> 1]
    /\ brk = [n \in Nodes |-> FALSE]
    /\ cfy = [n \in Nodes |-> FALSE]
    /\ gold = [n \in Nodes |-> [gfd |-> FALSE, gfail |-> 0, sets |-> 0, graceOver |-> FALSE, gcons |-> 0]]
    /\ quar = [n \in Nodes |-> FALSE]
    /\ ghost = [staleCanon |-> FALSE, grantToQuar |-> FALSE, canonFromQuar |-> FALSE,
                canonFromUncert |-> FALSE, honestConvicted |-> FALSE, convicted |-> {},
                revived |-> FALSE, moduleCharged |-> FALSE]
    /\ up = TRUE
    /\ snap = [n \in Nodes |-> 0]
    /\ inflight = {}
    /\ running = [n \in Nodes |-> {}]
    /\ asleep = [n \in Nodes |-> FALSE]
    /\ outbox = {}
    /\ net = {}
    /\ faults = 0
    /\ userOps = 0
    /\ modUp = TRUE

-----------------------------------------------------------------------------
(* DB-level helpers. A "DB record" d = [att, job, quar, ghost] lets the     *)
(* statements of one transaction compose functionally.                      *)

CurDB == [att |-> att, job |-> job, quar |-> quar, ghost |-> ghost]
SetDB(d) == /\ att' = d.att /\ job' = d.job /\ quar' = d.quar /\ ghost' = d.ghost

LiveIn(A, j) == {a \in AttIds : A[a].st = "live" /\ A[a].j = j}
Certified(n) == cert[n] > 0 /\ ~brk[n]
\* _eligible_nodes() and _stranded_disputes(): ready, and certified or (code) certifying
EligibleIn(Q, m) ==
    ~Q[m] /\ (Certified(m) \/ (CertifyingIsEligible /\ cfy[m] /\ ~(CertifyingGrace /\ gold[m].graceOver)))
GenAfterDispute(g) == IF DisputeBumpsGen THEN g + 1 ELSE g

\* _end_attempt(a, newst, count_failure=False) for every a in S (all live).
\* ret = FALSE is weakened variant (b): the reaper does not return the job to pending.
EndNF(d, S, newst, ret) ==
    LET A2 == [a \in AttIds |-> IF a \in S THEN [d.att[a] EXCEPT !.st = newst] ELSE d.att[a]]
        J2 == [j \in Jobs |->
                 IF /\ ret
                    /\ d.job[j].st = "leased"
                    /\ \E a \in S : d.att[a].j = j
                    /\ LiveIn(A2, j) = {}
                 THEN [d.job[j] EXCEPT !.st = "pending"]
                 ELSE d.job[j]]
    IN [d EXCEPT !.att = A2, !.job = J2]

EndIfLive(d, a) == IF d.att[a].st = "live" THEN EndNF(d, {a}, "completed", TRUE) ELSE d

FailedNodes(A, j) == {A[b].n : b \in {b \in AttIds : A[b].st = "failed" /\ A[b].j = j}}

\* _end_attempt(a, "failed", count_failure=True)
EndFail(d, a) ==
    LET A2    == [d.att EXCEPT ![a].st = "failed"]
        j     == d.att[a].j
        fails == d.job[j].fails + 1
    IN IF d.job[j].st = "leased" /\ LiveIn(A2, j) = {}
       THEN [d EXCEPT !.att = A2,
                      !.job = [d.job EXCEPT
                                ![j].st = IF fails >= MaxExecFailures /\ Cardinality(FailedNodes(A2, j)) >= 2
                                          THEN "quarantined" ELSE "pending",
                                ![j].fails = fails]]
       ELSE [d EXCEPT !.att = A2]

\* quarantine(m, reason) for every m in S; nondet = the reason contains "nondeterminism",
\* which also runs invalidate_node_results(m): every done eval job whose canonical result
\* came from m goes back to pending in a new generation, its results demoted.
QuarantineSet(d, S, nondet) ==
    LET d1  == EndNF(d, {a \in AttIds : d.att[a].st = "live" /\ d.att[a].n \in S}, "revoked", TRUE)
        Inv == IF nondet
               THEN {x \in Jobs : /\ d1.job[x].st = "done" /\ IsEval(x) /\ d1.job[x].canon # 0
                                  /\ d1.att[d1.job[x].canon].n \in S}
               ELSE {}
        J2  == [x \in Jobs |-> IF x \in Inv
                               THEN [d1.job[x] EXCEPT !.st = "pending", !.g = @ + 1, !.canon = 0, !.fails = 0]
                               ELSE d1.job[x]]
        A2  == [b \in AttIds |-> IF d1.att[b].st # "none" /\ d1.att[b].j \in Inv
                                 THEN [d1.att[b] EXCEPT !.rcan = FALSE] ELSE d1.att[b]]
    IN [d1 EXCEPT !.quar = [m \in Nodes |-> d1.quar[m] \/ m \in S],
                  !.job = J2, !.att = A2,
                  !.ghost = [d1.ghost EXCEPT
                               !.honestConvicted = @ \/ (nondet /\ S \ FaultyNodes # {}),
                               !.convicted = IF nondet THEN @ \cup S ELSE @]]

\* After a canonical result for job j: _maybe_replicate (eval job, sampled, once per job_key;
\* the replica excludes the node n that produced the result; with ReplicaNeedsEligible only if
\* another eligible node exists) or _check_replica (replica job: a disagreement demotes the
\* original's canonical result and opens a dispute on the original, in a new generation).
AfterCanonical(d, j, a, n, v) ==
    IF IsEval(j) THEN
        LET R == IF ReplicaNeedsEligible /\ ~\E m \in Nodes \ {n} : EligibleIn(d.quar, m)
                 THEN {}
                 ELSE {r \in Jobs : ReplicaOf[r] = j /\ d.job[r].st = "absent"}
        IN [d EXCEPT !.job = [x \in Jobs |-> IF x \in R
                                            THEN [d.job[x] EXCEPT !.st = "pending", !.disp = {n}]
                                            ELSE d.job[x]]]
    ELSE
        LET oj == ReplicaOf[j]
            c  == d.job[oj].canon
        IN IF d.job[oj].st = "done" /\ c # 0 /\ d.att[c].rv # v
           THEN [d EXCEPT !.att = [d.att EXCEPT ![c].rcan = FALSE, ![c].racc = FALSE],
                          !.job = [d.job EXCEPT ![oj].st = "pending", ![oj].canon = 0,
                                                ![oj].g = GenAfterDispute(@),
                                                ![oj].disp = {d.att[c].n, n}, ![oj].dres = {c, a}]]
           ELSE d

\* The `if canonical:` block of complete(): result canonical, job done, attempt completed,
\* the job's other live attempts revoked (lost_race); then replication.
MakeCanonical(d, a, v) ==
    LET at == d.att[a]
        j  == at.j
        n  == at.n
        A1 == [b \in AttIds |->
                 IF b = a THEN [d.att[b] EXCEPT !.st = "completed", !.rv = v, !.racc = TRUE, !.rcan = TRUE]
                 ELSE IF d.att[b].st = "live" /\ d.att[b].j = j THEN [d.att[b] EXCEPT !.st = "revoked"]
                 ELSE d.att[b]]
        d1 == [d EXCEPT !.att = A1,
                        !.job = [d.job EXCEPT ![j].st = "done", ![j].canon = a],
                        !.ghost = [d.ghost EXCEPT !.staleCanon = @ \/ at.g # d.job[j].g,
                                                  !.canonFromQuar = @ \/ d.quar[n],
                                                  !.canonFromUncert = @ \/ ~Certified(n)]]
    IN AfterCanonical(d1, j, a, n, v)

\* complete(): the transaction after the idempotency / one-result-per-attempt lookups missed.
DoComplete(d, a, v) ==
    LET at       == d.att[a]
        j        == at.j
        n        == at.n
        jb       == d.job[j]
        closed   == at.st \notin {"live", "expired"}                    \* attempt_closed
        settled  == SettledJobFence /\ jb.st \in {"cancelled", "quarantined"}   \* job_<state>
        party    == DisputeFencesParties /\ jb.dres # {} /\ n \in jb.disp   \* dispute_party
        nq       == CompleteFencesQuarantine /\ d.quar[n]               \* node_quarantined
        rejStale == at.g # jb.g /\ Variant # "nofence"                  \* stale_generation; (a) drops it
        certBad  == at.cg # cert[n]                                     \* release_invalid
        accept0  == ~closed /\ ~settled /\ ~party /\ ~nq /\ ~rejStale /\ ~certBad
        d0g      == [d EXCEPT !.ghost = [d.ghost EXCEPT
                                !.revived = @ \/ (accept0 /\ jb.st \in {"cancelled", "quarantined"})]]
        d0       == [d0g EXCEPT !.att = [d.att EXCEPT ![a].rv = v, ![a].racc = FALSE, ![a].rcan = FALSE]]
        c        == jb.canon
        agree    == {r \in jb.dres : d.att[r].rv = v}
        losers   == {d.att[r].n : r \in jb.dres \ agree}
        nodes2   == jb.disp \cup {n}
        ready    == Cardinality({m \in Nodes : ~d.quar[m]})
        others   == LiveIn(d.att, j) \ {a}
    IN
    IF ~accept0 THEN EndIfLive(d0, a)
    ELSE IF jb.st = "done" THEN
        \* job_done: compared with the canonical result. Same node, different result: that node
        \* convicts itself (self_inconsistent); different nodes: a dispute opens.
        IF c # 0 /\ d.att[c].rv # v /\ SelfInconsistencyConvicts /\ d.att[c].n = n
        THEN QuarantineSet(EndIfLive(d0, a), {n}, TRUE)
        ELSE IF c # 0 /\ d.att[c].rv # v
        THEN EndIfLive([d0 EXCEPT !.att = [d0.att EXCEPT ![c].rcan = FALSE, ![c].racc = FALSE],
                                  !.job = [d0.job EXCEPT ![j].st = "pending", ![j].canon = 0,
                                                         ![j].g = GenAfterDispute(@),
                                                         ![j].disp = {d.att[c].n, n}, ![j].dres = {c, a}]], a)
        ELSE EndIfLive(d0, a)
    ELSE IF jb.dres = {} THEN MakeCanonical(d0, a, v)
    ELSE IF agree # {} THEN
        \* tie-break found a majority: canonical, dispute cleared, the outvoted node(s) convicted
        QuarantineSet(MakeCanonical([d0 EXCEPT !.job = [d0.job EXCEPT ![j].disp = {}, ![j].dres = {}]], a, v),
                      losers, TRUE)
    ELSE IF Cardinality(nodes2) >= ready THEN
        \* three-way disagreement and no node left: job quarantined, its other live attempts revoked
        LET d1 == EndIfLive([d0 EXCEPT !.job = [d0.job EXCEPT ![j].st = "quarantined",
                                                              ![j].disp = nodes2, ![j].dres = jb.dres \cup {a}]], a)
        IN [d1 EXCEPT !.att = [b \in AttIds |-> IF b \in others THEN [d1.att[b] EXCEPT !.st = "revoked"]
                                                ELSE d1.att[b]]]
    ELSE
        \* widen the dispute; leased while another attempt is live, else pending
        LET d1 == EndIfLive([d0 EXCEPT !.job = [d0.job EXCEPT ![j].disp = nodes2, ![j].dres = jb.dres \cup {a}]], a)
        IN [d1 EXCEPT !.job = [d1.job EXCEPT ![j].st = IF others # {} THEN "leased" ELSE "pending"]]

\* Handling of one report inside one transaction (atomic path).
Handle(d, m) ==
    CASE m.k = "C" -> IF d.att[m.a].rv # "none" THEN d          \* idempotent replay / duplicate
                      ELSE DoComplete(d, m.a, m.v)
      [] m.k = "R" -> IF d.att[m.a].st = "live" THEN EndNF(d, {m.a}, "released", TRUE) ELSE d
      [] m.k = "F" -> IF d.att[m.a].st \in {"live", "expired"} THEN EndFail(d, m.a) ELSE d

Ack(ok) == /\ ok \/ faults < MaxFaults
           /\ faults' = IF ok THEN faults ELSE faults + 1

-----------------------------------------------------------------------------
(* Coordinator: message handlers                                            *)

\* complete() / release() / fail() without a breaker trip: one transaction; the response may be lost.
Deliver(m, ok) ==
    /\ up /\ m \in net
    /\ ~(Variant = "nonatomic" /\ m.k = "C")
    /\ (m.k # "C" \/ modUp \/ att[m.a].rv # "none")      \* a first completion needs the module's verdict
    /\ Ack(ok)
    /\ SetDB(Handle(CurDB, m))
    /\ net' = net \ {m}
    /\ outbox' = IF ok THEN outbox \ {m} ELSE outbox
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, up, snap, inflight, running, asleep, userOps>>

\* fail() when the breaker trips (BREAKER_K consecutive failures, or a HOST_FAILURES reason).
DeliverFailTrip(m, ok) ==
    /\ up /\ m \in net /\ m.k = "F"
    /\ att[m.a].st \in {"live", "expired"}
    /\ Ack(ok)
    /\ LET n  == att[m.a].n
           d1 == EndFail(CurDB, m.a)
       IN IF BreakerFencesAttempts
          THEN \* _revoke_quiet: generation -1, the node's live attempts revoked
               /\ SetDB(EndNF(d1, {a \in AttIds : d1.att[a].st = "live" /\ d1.att[a].n = n},
                              "revoked", TRUE))
               /\ cert' = [cert EXCEPT ![n] = IF @ > 0 THEN -@ ELSE @]
               /\ cfy' = [cfy EXCEPT ![n] = FALSE]
               /\ UNCHANGED brk
          ELSE \* pre-27aa459: state='revoked', generation kept, live attempts left running
               /\ SetDB(d1)
               /\ brk' = [brk EXCEPT ![n] = TRUE]
               /\ UNCHANGED <<modUp, cert, cfy>>
    /\ net' = net \ {m}
    /\ outbox' = IF ok THEN outbox \ {m} ELSE outbox
    /\ UNCHANGED <<modUp, nextAtt, gold, up, snap, inflight, running, asleep, userOps>>

\* Variant (d): the idempotency lookup runs outside the transaction.
CompleteHit(m, ok) ==
    /\ Variant = "nonatomic" /\ up /\ m \in net /\ m.k = "C"
    /\ att[m.a].rv # "none"
    /\ Ack(ok)
    /\ net' = net \ {m}
    /\ outbox' = IF ok THEN outbox \ {m} ELSE outbox
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep, userOps>>

CompleteCheck(m, h) ==
    /\ Variant = "nonatomic" /\ up /\ m \in net /\ m.k = "C"
    /\ att[m.a].rv = "none"
    /\ ~\E x \in inflight : x[2] = h
    /\ inflight' = inflight \cup {<<m, h>>}
    /\ net' = net \ {m}
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, running, asleep, outbox, faults, userOps>>

CompleteTx(m, h, ok) ==
    /\ up /\ <<m, h>> \in inflight /\ modUp
    /\ Ack(ok)
    /\ SetDB(DoComplete(CurDB, m.a, m.v))
    /\ inflight' = inflight \ {<<m, h>>}
    /\ outbox' = IF ok THEN outbox \ {m} ELSE outbox
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, up, snap, running, asleep, net, userOps>>

(* Coordinator: claim()                                                     *)

NodeOK(n) == ~quar[n] /\ Certified(n)          \* lifecycle='ready' and module certified

\* _other_node_can_take(j, n): another ready, certified node that neither failed j nor is in its dispute
OtherCanTake(j, n) ==
    \E m \in Nodes \ {n} : ~quar[m] /\ Certified(m) /\ m \notin FailedNodes(att, j) /\ m \notin job[j].disp

Excluded(n, j) ==
    \/ n \in job[j].disp
    \/ n \in FailedNodes(att, j) /\ (StrictFailedHere \/ OtherCanTake(j, n))

CanGrant(n, j) == job[j].st = "pending" /\ nextAtt <= MaxAtt /\ ~Excluded(n, j)

\* INSERT attempts(...,'live'); UPDATE jobs SET state='leased'. ok = FALSE: the grant response is lost.
Grant(n, j, cg, ok) ==
    /\ ok \/ faults < MaxFaults
    /\ att' = [att EXCEPT ![nextAtt] = [NoAttempt EXCEPT !.j = j, !.n = n, !.g = job[j].g,
                                                        !.cg = cg, !.st = "live"]]
    /\ job' = [job EXCEPT ![j].st = "leased"]
    /\ nextAtt' = nextAtt + 1
    /\ running' = IF ok THEN [running EXCEPT ![n] = @ \cup {nextAtt}] ELSE running
    /\ faults' = IF ok THEN faults ELSE faults + 1
    /\ ghost' = [ghost EXCEPT !.grantToQuar = @ \/ quar[n]]

\* Proposed fix for finding F1: the node row is (re-)read inside the claim transaction.
ClaimAtomic(n, j, ok) ==
    /\ ClaimReadsNodeInTx /\ up /\ ~asleep[n]
    /\ NodeOK(n) /\ CanGrant(n, j)
    /\ Grant(n, j, cert[n], ok)
    /\ UNCHANGED <<modUp, cert, brk, cfy, gold, quar, up, snap, inflight, asleep, outbox, net, userOps>>

\* core.py: auth_node() reads the node row (app.py node_dep); claim() checks lifecycle and module
\* certification on that snapshot and takes the attempt's cert_generation from it; only jobs,
\* attempts and other nodes are read inside its transaction.
ClaimAuth(n) ==
    /\ ~ClaimReadsNodeInTx /\ up /\ ~asleep[n] /\ snap[n] = 0
    /\ NodeOK(n)
    /\ snap' = [snap EXCEPT ![n] = cert[n]]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, inflight, running, asleep,
                   outbox, net, faults, userOps>>

ClaimGrant(n, j, ok) ==
    /\ ~ClaimReadsNodeInTx /\ up /\ snap[n] # 0
    /\ CanGrant(n, j)
    /\ Grant(n, j, snap[n], ok)
    /\ snap' = [snap EXCEPT ![n] = 0]
    /\ UNCHANGED <<modUp, cert, brk, cfy, gold, quar, up, inflight, asleep, outbox, net, userOps>>

ClaimEmpty(n) ==
    /\ ~ClaimReadsNodeInTx /\ up /\ snap[n] # 0
    /\ ~\E j \in Jobs : CanGrant(n, j)
    /\ snap' = [snap EXCEPT ![n] = 0]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, inflight, running, asleep,
                   outbox, net, faults, userOps>>

(* Coordinator: reap(), module revocation, quarantine, crash                *)

Pending(a) == (\E m \in outbox \cup net : m.a = a) \/ (\E x \in inflight : x[1].a = a)

\* Nobody renews this lease: the agent is asleep, or neither runs nor will report it.
Orphaned(a) == LET n == att[a].n IN
    \/ asleep[n] \/ (a \notin running[n] /\ ~Pending(a))
    \/ (~AwaitHoldsLease /\ att[a].aw)      \* weakened: nobody renews a finished attempt waiting on its module

\* awaiting_module attempts never expire while AwaitHoldsLease (core.py _await_module, reap)
Held(a) == AwaitHoldsLease /\ att[a].aw

\* the expiry of an attempt that waited on its module is a charge caused by a module fault (S15)
Charge(d, a) == [d EXCEPT !.ghost = [@ EXCEPT !.moduleCharged = @ \/ att[a].aw]]

\* reap(): expiry of an unrenewed lease (fair, not a fault).
ReapOrphan(a) ==
    /\ up /\ att[a].st = "live" /\ Orphaned(a) /\ ~Held(a)
    /\ SetDB(Charge(EndNF(CurDB, {a}, "expired", Variant # "noreturn"), a))
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, up, snap, inflight, running, asleep, outbox, net, faults, userOps>>

\* reap(): expiry of any live lease (heartbeats lost, stall): a fault.
Expire(a) ==
    /\ faults < MaxFaults /\ up /\ att[a].st = "live" /\ ~Held(a)
    /\ SetDB(Charge(EndNF(CurDB, {a}, "expired", Variant # "noreturn"), a))
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, up, snap, inflight, running, asleep, outbox, net, userOps>>

\* reap() -> _stranded_disputes(): a pending disputed job that no ready node outside the dispute
\* (certified or certifying for the module) can tie-break is quarantined.
ReapStranded(j) ==
    /\ up /\ job[j].st = "pending" /\ job[j].dres # {}
    /\ ~\E m \in Nodes : m \notin job[j].disp /\ EligibleIn(quar, m)
    /\ job' = [job EXCEPT ![j].st = "quarantined"]
    /\ UNCHANGED <<modUp, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* reap(): a pending replica job that no eligible node outside its exclusion list can run is
\* cancelled (new generation).
ReapReplica(r) ==
    /\ ReapCancelsReplica /\ up /\ ~IsEval(r) /\ job[r].st = "pending"
    /\ ~\E m \in Nodes : m \notin job[r].disp /\ EligibleIn(quar, m)
    /\ job' = [job EXCEPT ![r].st = "cancelled", ![r].g = @ + 1]
    /\ UNCHANGED <<modUp, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* revoke_module() after a golden mismatch: generation -1, the node's live attempts revoked.
RevokeModule(n) ==
    /\ faults < MaxFaults /\ up /\ cert[n] > 0
    /\ cert' = [cert EXCEPT ![n] = -cert[n]]
    /\ SetDB(EndNF(CurDB, {a \in AttIds : att[a].st = "live" /\ att[a].n = n}, "revoked", TRUE))
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, nextAtt, brk, cfy, gold, up, snap, inflight, running, asleep, outbox, net, userOps>>

\* queue_goldens(): a new golden set, the module is 'certifying' (certifying_since = now).
\* bb04f9d cancels any stale set first; before, sets piled up.
QueueGoldens(g) == [g EXCEPT !.sets = IF GoldenFailLimit THEN 1 ELSE IF @ < 2 THEN @ + 1 ELSE 2,
                             !.graceOver = FALSE]

\* doctor ok after a revocation -> queue_goldens().
BeginCertify(n) ==
    /\ up /\ cert[n] < 0 /\ ~cfy[n] /\ ~gold[n].gfd /\ ~quar[n]
    /\ cfy' = [cfy EXCEPT ![n] = TRUE]
    /\ gold' = [gold EXCEPT ![n] = QueueGoldens(@)]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* _lifecycle_step: a golden_failed module is retried after RECERT_EVERY (counter reset).
RetryGoldenFailed(n) ==
    /\ up /\ gold[n].gfd /\ ~quar[n]
    /\ cfy' = [cfy EXCEPT ![n] = TRUE]
    /\ gold' = [gold EXCEPT ![n] = QueueGoldens([@ EXCEPT !.gfd = FALSE, !.gfail = 0])]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* CERTIFYING_GRACE_S passes while the node is certifying (abstract time).
GraceExpires(n) ==
    /\ cfy[n] /\ ~gold[n].graceOver
    /\ gold' = [gold EXCEPT ![n].graceOver = TRUE]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* A golden job of certifying node n fails (fail() -> _end_attempt(count_failure=True)). For a node
\* in GoldenFailNodes this is its normal behaviour; for others a counted fault. trip = the node
\* breaker trips on this failure (BREAKER_K consecutive failures of any job, or a host failure).
\*   bb04f9d: the MAX_EXEC_FAILURES-th golden failure -> _golden_failed (goldens cancelled, state
\*            golden_failed, generation -1, alert) and no breaker; otherwise a trip revokes the
\*            module and the next doctor pass re-queues goldens.
\*   before:  no golden limit; a trip revokes and re-queues (stale set kept).
GoldenFail(n, trip) ==
    /\ up /\ cfy[n] /\ ~quar[n]
    /\ n \in GoldenFailNodes \/ faults < MaxFaults
    /\ faults' = IF n \in GoldenFailNodes THEN faults ELSE faults + 1
    /\ LET g     == gold[n]
           gc    == IF g.gcons < MaxExecFailures + 1 THEN g.gcons + 1 ELSE g.gcons
           limit == GoldenFailLimit /\ g.gfail + 1 >= MaxExecFailures
       IN IF limit
          THEN /\ gold' = [gold EXCEPT ![n] = [g EXCEPT !.gfd = TRUE, !.gfail = g.gfail + 1, !.sets = 0,
                                                      !.gcons = 0]]
               /\ cfy' = [cfy EXCEPT ![n] = FALSE]
          ELSE /\ gold' = [gold EXCEPT ![n] = [g EXCEPT !.gfail = IF GoldenFailLimit THEN g.gfail + 1 ELSE 0,
                                                      !.gcons = gc]]
               /\ cfy' = [cfy EXCEPT ![n] = ~trip]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, userOps>>

\* golden jobs pass -> _golden_done() -> _certify(): a new, larger cert generation, counter reset.
\* (brk: the pre-27aa459 breaker left the generation positive; it recertifies directly.)
Recertify(n) ==
    /\ up /\ (cfy[n] \/ brk[n]) /\ ~quar[n] /\ n \notin GoldenFailNodes
    /\ cert' = [cert EXCEPT ![n] = IF cert[n] < 0 THEN -cert[n] + 1 ELSE cert[n] + 1]
    /\ brk' = [brk EXCEPT ![n] = FALSE]
    /\ cfy' = [cfy EXCEPT ![n] = FALSE]
    /\ gold' = [gold EXCEPT ![n] = [@ EXCEPT !.gfail = 0, !.sets = 0, !.gcons = 0]]
    /\ UNCHANGED <<modUp, job, att, nextAtt, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* quarantine() called by an operator (reason without "nondeterminism": nothing invalidated).
AdminQuarantine(n) ==
    /\ faults < MaxFaults /\ up /\ ~quar[n]
    /\ SetDB(QuarantineSet(CurDB, {n}, FALSE))
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, up, snap, inflight, running, asleep, outbox, net, userOps>>

\* oarbankd dies: volatile state (handler threads, claim snapshots) is lost; the DB survives.
\* On restart __main__ extends live leases by the outage (a no-op with abstract time).
Crash ==
    /\ faults < MaxFaults /\ up
    /\ up' = FALSE
    /\ snap' = [n \in Nodes |-> 0]
    /\ inflight' = {}
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, running, asleep, outbox, net, userOps>>

Restart ==
    /\ ~up /\ up' = TRUE
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

(* User operations                                                          *)

\* retry_job(): new generation, old canonical result demoted ((c) skips the demotion).
Retry(j) ==
    /\ userOps < MaxUserOps /\ up
    /\ job[j].st \in {"done", "cancelled", "quarantined"}
    /\ job' = [job EXCEPT ![j].st = "pending", ![j].g = @ + 1, ![j].canon = 0, ![j].fails = 0]
    /\ att' = IF Variant = "nodemote" THEN att
              ELSE [a \in AttIds |-> IF att[a].j = j THEN [att[a] EXCEPT !.rcan = FALSE] ELSE att[a]]
    /\ userOps' = userOps + 1
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep, outbox, net, faults>>

\* cancel_job(): new generation, live attempts revoked (pushed as cancel).
Cancel(j) ==
    /\ userOps < MaxUserOps /\ up
    /\ job[j].st \in {"pending", "leased"}
    /\ job' = [job EXCEPT ![j].st = "cancelled", ![j].g = @ + 1]
    /\ att' = [a \in AttIds |-> IF att[a].st = "live" /\ att[a].j = j
                                THEN [att[a] EXCEPT !.st = "revoked"] ELSE att[a]]
    /\ userOps' = userOps + 1
    /\ UNCHANGED <<modUp, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep, outbox, net, faults>>

-----------------------------------------------------------------------------
(* Agents and network                                                       *)

\* The runner exits 0 with result.json; the agent queues the completion in its outbox.
Finish(n, a, v) ==
    /\ ~asleep[n] /\ a \in running[n] /\ v \in Vals(n)
    /\ running' = [running EXCEPT ![n] = @ \ {a}]
    /\ outbox' = outbox \cup {[k |-> "C", a |-> a, v |-> v]}
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, asleep, net, faults, userOps>>

\* The agent kills the attempt and queues release(reason) (sleep, preempt_tah, user_active, ...).
AgentRelease(n, a) ==
    /\ faults < MaxFaults /\ ~asleep[n] /\ a \in running[n]
    /\ running' = [running EXCEPT ![n] = @ \ {a}]
    /\ outbox' = outbox \cup {[k |-> "R", a |-> a, v |-> "-"]}
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, asleep, net, userOps>>

\* The runner exits non-zero; the agent queues fail(reason).
AgentFail(n, a) ==
    /\ faults < MaxFaults /\ ~asleep[n] /\ a \in running[n]
    /\ running' = [running EXCEPT ![n] = @ \ {a}]
    /\ outbox' = outbox \cup {[k |-> "F", a |-> a, v |-> "-"]}
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, asleep, net, userOps>>

\* Outbox loop: (re)send an unacknowledged report.
Send(m) ==
    /\ m \in outbox /\ ~asleep[att[m.a].n] /\ m \notin net
    /\ net' = net \cup {m}
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, faults, userOps>>

Drop(m) ==
    /\ faults < MaxFaults /\ m \in net
    /\ net' = net \ {m}
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, userOps>>

\* heartbeat() response carries revoke/cancel: the agent kills the attempt silently.
HeartbeatKill(n, a) ==
    /\ up /\ ~asleep[n] /\ a \in running[n] /\ att[a].st = "revoked"
    /\ running' = [running EXCEPT ![n] = @ \ {a}]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, asleep, outbox,
                   net, faults, userOps>>

Sleep(n) ==
    /\ faults < MaxFaults /\ ~asleep[n]
    /\ asleep' = [asleep EXCEPT ![n] = TRUE]
    /\ faults' = faults + 1
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, outbox, net, userOps>>

Wake(n) ==
    /\ asleep[n]
    /\ asleep' = [asleep EXCEPT ![n] = FALSE]
    /\ UNCHANGED <<modUp, job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, outbox,
                   net, faults, userOps>>

-----------------------------------------------------------------------------
(* the module host                                                       *)

\* The module host goes down (crash, bad release, stuck process): a fault.
ModuleDown ==
    /\ ModuleFaults /\ modUp /\ faults < MaxFaults
    /\ modUp' = FALSE /\ faults' = faults + 1
    /\ UNCHANGED <<job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, userOps>>

\* It comes back (respawn after backoff, or an operator restart).
ModuleUp ==
    /\ ~modUp /\ modUp' = TRUE
    /\ UNCHANGED <<job, att, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, net, faults, userOps>>

\* complete() while the module cannot evaluate: 503 + Retry-After. The report stays in the agent's
\* outbox for redelivery; the attempt is marked awaiting_module; nothing is charged.
DeliverModuleDown(m) ==
    /\ up /\ ~modUp /\ m \in net /\ m.k = "C" /\ att[m.a].rv = "none"
    /\ att' = [att EXCEPT ![m.a].aw = att[m.a].st \in {"live", "expired"} \/ @]
    /\ net' = net \ {m}
    /\ UNCHANGED <<modUp, job, nextAtt, cert, brk, cfy, gold, quar, ghost, up, snap, inflight, running, asleep,
                   outbox, faults, userOps>>

Next ==
    \/ ModuleDown \/ ModuleUp \/ \E m \in net : DeliverModuleDown(m)
    \/ \E m \in net, ok \in BOOLEAN : Deliver(m, ok) \/ DeliverFailTrip(m, ok) \/ CompleteHit(m, ok)
    \/ \E m \in net, h \in Slots : CompleteCheck(m, h)
    \/ \E x \in inflight, ok \in BOOLEAN : CompleteTx(x[1], x[2], ok)
    \/ \E n \in Nodes, j \in Jobs, ok \in BOOLEAN : ClaimAtomic(n, j, ok) \/ ClaimGrant(n, j, ok)
    \/ \E n \in Nodes : ClaimAuth(n) \/ ClaimEmpty(n)
    \/ \E a \in AttIds : ReapOrphan(a) \/ Expire(a)
    \/ \E j \in Jobs : ReapStranded(j) \/ ReapReplica(j)
    \/ \E n \in Nodes : RevokeModule(n) \/ BeginCertify(n) \/ Recertify(n) \/ AdminQuarantine(n)
    \/ \E n \in Nodes : RetryGoldenFailed(n) \/ GraceExpires(n) \/ \E t \in BOOLEAN : GoldenFail(n, t)
    \/ Crash \/ Restart
    \/ \E j \in Jobs : Retry(j) \/ Cancel(j)
    \/ \E n \in Nodes, a \in AttIds, v \in Values : Finish(n, a, v)
    \/ \E n \in Nodes, a \in AttIds : AgentRelease(n, a) \/ AgentFail(n, a) \/ HeartbeatKill(n, a)
    \/ \E m \in outbox : Send(m)
    \/ \E m \in net : Drop(m)
    \/ \E n \in Nodes : Sleep(n) \/ Wake(n)

\* Weak fairness on the coordinator and agent progress actions (claims per agent: every agent
\* keeps polling). Faults and user operations are unfair and bounded, so delivery is
\* eventually reliable.
Fairness ==
    /\ WF_vars(ModuleUp)
    /\ WF_vars(\E m \in net : Deliver(m, TRUE) \/ CompleteHit(m, TRUE))
    /\ WF_vars(\E m \in net, h \in Slots : CompleteCheck(m, h))
    /\ WF_vars(\E x \in inflight : CompleteTx(x[1], x[2], TRUE))
    /\ \A n \in Nodes : WF_vars(\E j \in Jobs : ClaimAtomic(n, j, TRUE) \/ ClaimGrant(n, j, TRUE))
    /\ \A n \in Nodes : WF_vars(ClaimAuth(n) \/ ClaimEmpty(n))
    /\ WF_vars(\E a \in AttIds : ReapOrphan(a))
    \* the reaper runs every REAPER_EVERY seconds: strong fairness, because a retried golden_failed
    \* node can make its conditions true only intermittently
    /\ SF_vars(\E j \in Jobs : ReapStranded(j) \/ ReapReplica(j))
    /\ WF_vars(\E n \in Nodes : BeginCertify(n))
    /\ WF_vars(\E n \in Nodes : GraceExpires(n))
    /\ WF_vars(\E n \in Nodes : RetryGoldenFailed(n))
    /\ \A n \in GoldenFailNodes : IF CertifyMayStall THEN TRUE ELSE WF_vars(\E t \in BOOLEAN : GoldenFail(n, t))
    /\ IF CertifyMayStall THEN TRUE ELSE WF_vars(\E n \in Nodes : Recertify(n))
    /\ WF_vars(Restart)
    /\ WF_vars(\E n \in Nodes, a \in AttIds, v \in Values : Finish(n, a, v))
    /\ WF_vars(\E m \in outbox : Send(m))
    /\ WF_vars(\E n \in Nodes : Wake(n))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties                                                               *)

CanonOf(j) == {a \in AttIds : att[a].st # "none" /\ att[a].j = j /\ att[a].rcan}

\* 1. At most one canonical result per job at any time.
OneCanonical == \A j \in Jobs : Cardinality(CanonOf(j)) <= 1

\* 2. A canonical result's attempt generation equals the job's generation.
CanonicalGenCurrent == \A j \in Jobs : \A a \in CanonOf(j) : att[a].g = job[j].g

\* 3. A completion from a stale generation is never made canonical (checked at acceptance).
StaleNeverCanonical == ~ghost.staleCanon

\* 4. No lost job: a leased job has a live attempt (equivalently: a job whose attempts all
\*    ended is pending or settled), and every live attempt belongs to a leased job of its
\*    generation (settled and pending jobs have no live attempts).
NoLostJob ==
    /\ \A j \in Jobs : job[j].st = "leased" => LiveIn(att, j) # {}
    /\ \A a \in AttIds : att[a].st = "live" =>
           job[att[a].j].st = "leased" /\ att[a].g = job[att[a].j].g

\* 5. A quarantined node never gets a grant.
QuarantinedNoGrant == ~ghost.grantToQuar

\* Extra (S2): a done job points at exactly its canonical result.
DoneHasCanonical ==
    \A j \in Jobs : job[j].st = "done" =>
        /\ job[j].canon # 0
        /\ att[job[j].canon].j = j
        /\ att[job[j].canon].rcan

\* Extra (S7, S8): live attempts run only on ready nodes, under the current certification.
LiveOnReadyCertified ==
    \A a \in AttIds : att[a].st = "live" =>
        /\ ~quar[att[a].n]
        /\ Certified(att[a].n) /\ att[a].cg = cert[att[a].n]

\* Extra: no result from a node quarantined at acceptance time becomes canonical.
NoCanonicalFromQuarantined == ~ghost.canonFromQuar

\* Extra: no result becomes canonical while its node's module certification is revoked.
NoCanonicalFromUncertified == ~ghost.canonFromUncert

\* Extra (I1): a correct node (not in FaultyNodes) is never convicted of nondeterminism.
\* Meaningful when at most one node is faulty: a quorum of distinct nodes then never outvotes
\* a correct one.
NoHonestConviction == ~ghost.honestConvicted

\* F6: a module never collects more than one pending golden set (stale sets are cancelled).
GoldenSetsBounded == \A n \in Nodes : gold[n].sets <= 1

\* F6: at most MAX_EXEC_FAILURES golden failures on a node before it is certified or taken out of
\* service as golden_failed (with an alert); no silent retry loop.
GoldenFailuresBounded == \A n \in Nodes : gold[n].gcons <= MaxExecFailures

\* Extra: a cancelled or quarantined job is never revived by a late completion (only retry_job
\* or the reaper moves it).
SettledNotRevived == ~ghost.revived

\* S15 : a module fault is never charged: no attempt that waited on its module expires.
ModuleFaultsNotCharged == ~ghost.moduleCharged

\* Extra (I2): once a node is convicted, no canonical result of an eval job it produced survives.
ConvictedResultsInvalidated ==
    \A a \in AttIds : att[a].rcan /\ IsEval(att[a].j) => att[a].n \notin ghost.convicted

\* Liveness: every job eventually settles in done, cancelled or quarantined (a job quarantined
\* by the failure policy or by an unbreakable dispute), provided some node is never quarantined
\* (clear_quarantine is an operator action outside the model) and ends up certified. A replica job that is never
\* created (absent) counts as settled.
SomeNodeStaysHealthy == \E n \in Nodes : [](~quar[n]) /\ <>[](Certified(n))
Settled(j) == job[j].st \in Terminal \cup {"absent"}
AllJobsSettle == \A j \in Jobs : <>[](Settled(j))
Liveness == SomeNodeStaysHealthy => AllJobsSettle

-----------------------------------------------------------------------------
(* Reachability witnesses (vacuity checks). Each is written as an invariant *)
(* that TLC is EXPECTED to violate, proving the scenario is reachable.      *)

\* An expired attempt's late completion became canonical; the re-leased attempt lost the race.
W_LateCompletionWins ==
    ~\E a, b \in AttIds : /\ a < b /\ att[a].rcan /\ att[b].j = att[a].j
                          /\ att[b].g = att[a].g /\ att[b].st = "revoked"

\* A late result differed from the canonical one and opened a dispute.
W_DisputeOpened == ~\E j \in Jobs : job[j].dres # {}

\* A tie-break completion found a majority: a node was convicted and a job is done again.
W_TieBreakConvicts == ~(ghost.convicted # {} /\ \E j \in Jobs : job[j].st = "done")

\* A dispute that nobody can break was quarantined by the reaper.
W_StrandedDisputeQuarantined == ~\E j \in Jobs : job[j].st = "quarantined" /\ job[j].dres # {}

\* A replica job ran and disagreed with the original's canonical result.
W_ReplicaDisagrees ==
    ~\E r \in Jobs : ~IsEval(r) /\ job[r].st = "done" /\ job[ReplicaOf[r]].dres # {}

\* A completion of an old generation arrived after retry/cancel and was rejected.
W_StaleCompletionRejected ==
    ~\E a \in AttIds : /\ att[a].rv # "none" /\ ~att[a].racc
                       /\ att[a].g < job[att[a].j].g /\ att[a].st \in {"expired", "completed"}
                       /\ att[a].cg = cert[att[a].n]

\* A job was retried after done and finished again in generation 2.
W_RetriedJobDoneAgain == ~\E j \in Jobs : job[j].g = 2 /\ job[j].st = "done"

\* A completion was rejected because the module was revoked (release_invalid).
W_RevokedCertRejected ==
    ~\E a \in AttIds : /\ att[a].rv # "none" /\ ~att[a].racc /\ att[a].g = job[att[a].j].g
                       /\ att[a].cg # cert[att[a].n]

\* A node gave two different results for one job and convicted itself; the job is recomputed.
W_SelfInconsistentConvicted ==
    ~\E a, b \in AttIds : /\ a # b /\ att[a].n = att[b].n /\ att[a].j = att[b].j
                          /\ att[a].rv # "none" /\ att[b].rv # "none" /\ att[a].rv # att[b].rv
                          /\ att[a].n \in ghost.convicted

\* The reaper cancelled a replica job that nobody could run.
W_ReplicaCancelledByReaper == ~\E r \in Jobs : ~IsEval(r) /\ job[r].st = "cancelled"

\* A dispute party's older attempt delivered its result after the dispute opened and was fenced.
W_PartyLateVoteFenced ==
    ~\E a \in AttIds : /\ att[a].rv # "none" /\ ~att[a].racc /\ att[a].st = "expired"
                       /\ job[att[a].j].dres # {} /\ att[a].n \in job[att[a].j].disp
                       /\ a \notin job[att[a].j].dres

\* A node's goldens failed MAX_EXEC_FAILURES times and it went golden_failed.
W_GoldenFailed == ~\E n \in Nodes : gold[n].gfd

\* A certifying node's grace expired and the reaper cancelled a replica only it could have run.
W_GraceExpiredReplicaCancelled ==
    ~\E n \in Nodes, r \in Jobs : cfy[n] /\ gold[n].graceOver /\ ~IsEval(r) /\ job[r].st = "cancelled"

JobSymmetry == Permutations(EvalJobs)    \* only sound when ReplicaJobs = {}
=============================================================================
