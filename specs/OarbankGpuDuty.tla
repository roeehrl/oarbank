------------------------------ MODULE OarbankGpuDuty ------------------------------
(***************************************************************************)
(* The GPU duty governor of host protection (D50, docs/design/            *)
(* gpu-cotenancy.md, "The duty governor"; rust gpu_duty.rs) for one       *)
(* gating rule and one cooperative unit of fleet GPU work, at the grain    *)
(* of its samples (2 s) and intervals (60 s). Duties are in steps of 0.05  *)
(* (0..MaxD); the environment picks every sample's signal (readable, the   *)
(* memory guard, the harm the fleet's GPU use caused, whether the harm     *)
(* could be computed) and whether the unit holds its duty, and changes the *)
(* certified ceiling at any time.                                          *)
(*                                                                         *)
(* The governor's rules:                                                   *)
(*  - an unreadable source or the memory guard takes the budget to 0 at    *)
(*    once and spoils the interval;                                        *)
(*  - at an interval's end: harm over twice the target takes it to 0,      *)
(*    harm at the target halves it, and a clean interval (every sample     *)
(*    readable, guard clear, harm known and under half the target) grows   *)
(*    it by one step, never past the ceiling (GrowNeedsClean);             *)
(*  - a falling ceiling binds at once (ClampOnCeiling);                    *)
(*  - a unit over its duty (plus the slack) for Samples consecutive        *)
(*    samples is held (HoldPauses), and the Strikes-th hold within the     *)
(*    window stops it for good (StrikesPersist: holds count across holds). *)
(*                                                                         *)
(* Properties:                                                             *)
(*  DutyWithinCeiling: the budget never exceeds the certified ceiling.     *)
(*  NoGrowthOnUnclean: the budget never grows at the end of an interval    *)
(*    that had an unreadable, guarded, unknown or harmful sample (S19).    *)
(*  ExcessBounded: a unit never runs over its duty for more than Samples   *)
(*    + 1 consecutive samples (the first sample after it starts to run is  *)
(*    not judged: its duty may not have reached it yet).                   *)
(*  LiarStops (with Liar = TRUE, a unit that never holds its duty, kept    *)
(*    running: Calm = TRUE, no bad samples, harm or ceiling changes, and   *)
(*    no hour without running to clear its strikes): eventually it never   *)
(*    runs again.                                                          *)
(* Weakened variants: ClampOnCeiling = FALSE breaks DutyWithinCeiling;     *)
(* GrowNeedsClean = FALSE breaks NoGrowthOnUnclean; HoldPauses = FALSE     *)
(* breaks ExcessBounded; StrikesPersist = FALSE breaks LiarStops.          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxD, Samples, Strikes, Liar, Forgets, Calm,
          ClampOnCeiling, GrowNeedsClean, HoldPauses, StrikesPersist

Harms == {"none", "target", "double"}
Worse(a, b) == IF a = "double" \/ b = "double" THEN "double"
               ELSE IF a = "target" \/ b = "target" THEN "target" ELSE "none"
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    ceiling,      \* the smallest valid certificate's duty, in steps
    d,            \* the budget, in steps
    ivClean,      \* every sample of the interval so far was clean
    ivHarm,       \* the worst harm measured in the interval so far
    grewUnclean,  \* history: the budget grew at the end of an unclean interval
    running,      \* the unit runs with a duty (d > 0, not held, not stopped)
    prevRunning,  \* it ran at the start of the previous sample (only then is a sample judged)
    over,         \* the unit's consecutive samples over its duty (the governor's count)
    excess,       \* history: consecutive samples it actually ran over its duty
    held,         \* the unit is held (for a while) after exceeding its duty
    strikes,      \* holds within the window
    stopped       \* the unit was stopped (and is not trusted with a duty)

vars == <<ceiling, d, ivClean, ivHarm, grewUnclean, running, prevRunning, over, excess, held, strikes, stopped>>

Runs(dd, h, s) == dd > 0 /\ ~h /\ ~s

Init ==
    /\ ceiling \in 0..MaxD /\ d = ceiling
    /\ ivClean = TRUE /\ ivHarm = "none" /\ grewUnclean = FALSE
    /\ running = Runs(d, FALSE, FALSE) /\ prevRunning = FALSE /\ over = 0 /\ excess = 0 /\ held = FALSE /\ strikes = 0 /\ stopped = FALSE

\* One sample. The environment chooses the signal and whether the unit held its duty.
Sample ==
    \E readable, guard, known \in BOOLEAN, harm \in Harms, lies \in BOOLEAN :
        LET lied   == running /\ (lies \/ Liar)
            hurt   == IF running THEN harm ELSE "none"
            bad    == ~readable \/ ~guard
            d1     == IF bad THEN 0 ELSE d
            over1  == IF running /\ prevRunning THEN (IF lied THEN over + 1 ELSE 0) ELSE 0
            hold   == over1 >= Samples
            str1   == IF hold THEN (IF StrikesPersist THEN strikes + 1 ELSE 1) ELSE strikes
            stop1  == stopped \/ (hold /\ str1 >= Strikes)
            held1  == held \/ (hold /\ HoldPauses)
        IN
        /\ Calm => (readable /\ guard /\ known /\ harm = "none")
        /\ d' = d1
        /\ ivClean' = (ivClean /\ ~bad /\ (known \/ ~running) /\ hurt = "none")
        /\ ivHarm' = Worse(ivHarm, IF known THEN hurt ELSE "none")
        /\ over' = IF hold THEN 0 ELSE over1
        /\ excess' = IF lied THEN excess + 1 ELSE 0
        /\ strikes' = IF stop1 THEN Strikes ELSE str1
        /\ stopped' = stop1
        /\ held' = held1
        /\ running' = Runs(d1, held1, stop1)
        /\ prevRunning' = running
        /\ UNCHANGED <<ceiling, grewUnclean>>

IntervalEnd ==
    LET grow == ivHarm = "none" /\ d < ceiling /\ (GrowNeedsClean => ivClean)
        d1   == IF ivHarm = "double" THEN 0
                ELSE IF ivHarm = "target" THEN d \div 2
                ELSE IF grow THEN d + 1 ELSE d
    IN
    /\ d' = d1
    /\ grewUnclean' = (grewUnclean \/ (grow /\ ~ivClean))
    /\ ivClean' = TRUE /\ ivHarm' = "none"
    /\ running' = Runs(d1, held, stopped)
    /\ UNCHANGED <<ceiling, prevRunning, over, excess, held, strikes, stopped>>

CeilingChange ==
    /\ ~Calm
    /\ \E c \in 0..MaxD :
        /\ c /= ceiling
        /\ ceiling' = c
        /\ d' = IF ClampOnCeiling THEN Min(d, c) ELSE d
        /\ running' = Runs(d', held, stopped)
        /\ UNCHANGED <<ivClean, ivHarm, grewUnclean, prevRunning, over, excess, held, strikes, stopped>>

\* the hold ends (60 s later: the unit did not run in between, so any run over its duty is broken)
Release ==
    /\ held
    /\ held' = FALSE /\ excess' = 0 /\ prevRunning' = FALSE
    /\ running' = Runs(d, FALSE, stopped)
    /\ UNCHANGED <<ceiling, d, ivClean, ivHarm, grewUnclean, over, strikes, stopped>>

\* the strike window forgets old holds after an hour without one, which a unit that lies whenever it runs reaches only
\* by not running for that hour (Forgets = FALSE: the liveness configs, where the liar keeps getting to run)
Forget ==
    /\ Forgets /\ strikes > 0 /\ ~stopped /\ (Liar => ~running)
    /\ strikes' = 0
    /\ UNCHANGED <<ceiling, d, ivClean, ivHarm, grewUnclean, running, prevRunning, over, excess, held, stopped>>

Next == Sample \/ IntervalEnd \/ CeilingChange \/ Release \/ Forget

\* Liveness assumptions: samples, intervals and hold ends keep coming; the strike window is never what saves a liar
\* (Forget is not fair: an hour without a hold never comes to a unit that always lies).
Spec == Init /\ [][Next]_vars /\ WF_vars(Sample) /\ WF_vars(IntervalEnd) /\ WF_vars(Release)

TypeOK ==
    /\ ceiling \in 0..MaxD /\ d \in 0..MaxD /\ ivClean \in BOOLEAN /\ ivHarm \in Harms
    /\ grewUnclean \in BOOLEAN /\ running \in BOOLEAN /\ prevRunning \in BOOLEAN /\ over \in 0..Samples /\ excess \in Nat
    /\ held \in BOOLEAN /\ strikes \in 0..Strikes /\ stopped \in BOOLEAN

DutyWithinCeiling == d <= ceiling

NoGrowthOnUnclean == ~grewUnclean

ExcessBounded == excess <= Samples + 1

LiarStops == <>[](~running)

\* keep the state space finite: excess beyond Samples + 2 is already a violation
StateBound == excess <= Samples + 2
==============================================================================
