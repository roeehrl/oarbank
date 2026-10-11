------------------------------ MODULE OarbankFastPause ------------------------------
(***************************************************************************)
(* The event path of host protection (D51, docs/design/gpu-cotenancy.md)   *)
(* against the agent's regular two-second tick, for one fleet job and one  *)
(* immediate `during` phase.                                               *)
(*                                                                         *)
(* The watcher thread sees the phase turn on and pauses the job at once    *)
(* (FastAct). The tick reads the owner sources (TickRead) and acts on what *)
(* it read some time later (TickAct); between the two the phase may turn   *)
(* on and the fast path may pause. The agent's rules (prot.rs `actuate`):  *)
(*  - a fast pause newer than the tick's read stands until the next tick   *)
(*    (FreshnessCheck);                                                    *)
(*  - the fast path records a freeze in the same frozen set the tick       *)
(*    resumes from (SharedFrozen).                                         *)
(*                                                                         *)
(* Properties:                                                             *)
(*  FastPauseHolds: once the event path paused the job for a phase that is *)
(*    still on, nothing resumes it (no pause, resume, pause flapping).     *)
(*  NoStuckPause: a phase that has ended (and stays ended) never leaves    *)
(*    the job paused for good.                                             *)
(* Weakened variants: FreshnessCheck = FALSE breaks FastPauseHolds (a tick *)
(* that read before the phase began resumes the job); SharedFrozen = FALSE *)
(* breaks NoStuckPause (the tick never learns of the fast freeze).         *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS FreshnessCheck, SharedFrozen

VARIABLES
    phase,        \* the owner source: "on" | "off"
    pending,      \* the watcher has an unprocessed change
    paused,       \* the job is frozen
    frozenKnown,  \* the tick's frozen set holds the job (it may resume it)
    fastFresh,    \* a fast pause happened after the current tick's read
    tick,         \* "idle" | "read": a tick between reading and acting
    snapshot,     \* what the tick read
    episode       \* the fast path paused the job during the current on-phase

vars == <<phase, pending, paused, frozenKnown, fastFresh, tick, snapshot, episode>>

Init ==
    /\ phase = "off" /\ pending = FALSE /\ paused = FALSE /\ frozenKnown = FALSE
    /\ fastFresh = FALSE /\ tick = "idle" /\ snapshot = "off" /\ episode = FALSE

PhaseOn ==
    /\ phase = "off"
    /\ phase' = "on" /\ pending' = TRUE
    /\ UNCHANGED <<paused, frozenKnown, fastFresh, tick, snapshot, episode>>

PhaseOff ==
    /\ phase = "on"
    /\ phase' = "off" /\ episode' = FALSE
    /\ UNCHANGED <<pending, paused, frozenKnown, fastFresh, tick, snapshot>>

\* the watcher re-reads the source: the phase is on, pause now
FastAct ==
    /\ pending /\ phase = "on"
    /\ pending' = FALSE
    /\ paused' = TRUE /\ episode' = TRUE /\ fastFresh' = TRUE
    /\ frozenKnown' = (SharedFrozen \/ frozenKnown)
    /\ UNCHANGED <<phase, tick, snapshot>>

\* the change is already over when the watcher reads it
FastDrop ==
    /\ pending /\ phase = "off"
    /\ pending' = FALSE
    /\ UNCHANGED <<phase, paused, frozenKnown, fastFresh, tick, snapshot, episode>>

TickRead ==
    /\ tick = "idle"
    /\ tick' = "read" /\ snapshot' = phase /\ fastFresh' = FALSE
    /\ UNCHANGED <<phase, pending, paused, frozenKnown, episode>>

TickAct ==
    /\ tick = "read"
    /\ tick' = "idle"
    /\ IF snapshot = "on"
         THEN /\ paused' = TRUE /\ frozenKnown' = TRUE
         ELSE IF FreshnessCheck /\ fastFresh
                THEN UNCHANGED <<paused, frozenKnown>>                 \* this tick did not see the phase
                ELSE IF frozenKnown
                       THEN /\ paused' = FALSE /\ frozenKnown' = FALSE  \* resume what it froze
                       ELSE UNCHANGED <<paused, frozenKnown>>           \* a freeze it does not know of stays
    /\ UNCHANGED <<phase, pending, fastFresh, snapshot, episode>>

Next == PhaseOn \/ PhaseOff \/ FastAct \/ FastDrop \/ TickRead \/ TickAct

Spec == Init /\ [][Next]_vars /\ WF_vars(FastAct) /\ WF_vars(FastDrop) /\ WF_vars(TickRead) /\ WF_vars(TickAct)

TypeOK ==
    /\ phase \in {"on", "off"} /\ snapshot \in {"on", "off"} /\ tick \in {"idle", "read"}
    /\ pending \in BOOLEAN /\ paused \in BOOLEAN /\ frozenKnown \in BOOLEAN /\ fastFresh \in BOOLEAN
    /\ episode \in BOOLEAN

FastPauseHolds == (phase = "on" /\ episode) => paused

\* a phase that ends and stays ended leaves the job running eventually
NoStuckPause == [](phase = "off" => <>(~paused \/ phase = "on"))

\* the event path does act: an on-phase the watcher saw gets the job paused
EventuallyPaused == [](pending /\ phase = "on" => <>(paused \/ phase = "off"))
==============================================================================
