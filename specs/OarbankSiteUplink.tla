------------------------------ MODULE OarbankSiteUplink ------------------------------
(***************************************************************************)
(* Transfer leases at a site (D55, docs/design/sites.md): agents at one    *)
(* site ask the coordinator for a lease before a bulk transfer, renew it   *)
(* while they transfer, and stop when they cannot; the coordinator grants  *)
(* at most MaxTransfers live leases, lets an unrenewed one expire after    *)
(* TTL, and while the site holds (a protected process there is in an      *)
(* uplink phase) grants none and revokes the live ones (Revoke). A revoked *)
(* lease keeps its slot until its holder, having stopped, gives it back    *)
(* (a release, which may be lost) or it expires (SlotUntilReleased): an    *)
(* answer granting or renewing it may still be on its way.                 *)
(*                                                                         *)
(* Time is discrete. Requests and answers take up to D ticks and may be    *)
(* lost. An agent checks its lease only between chunks (every Chunk ticks  *)
(* at most) and renews at least every Poll ticks while it transfers. Its   *)
(* lease is fresh while less than TTL - Margin ticks have passed since it  *)
(* SENT the request that last granted or renewed it (the coordinator       *)
(* processed that request later, so its own age of the lease is never     *)
(* larger).                                                                *)
(*                                                                         *)
(* Properties:                                                             *)
(*  Budget: at most MaxTransfers agents transfer at once.                  *)
(*  HoldBound: once the site holds, every transfer stops within            *)
(*    TTL - Margin + Chunk ticks, however many messages are lost (with     *)
(*    renewals answered, within Poll + 2D + Chunk).                        *)
(* Weakened variants: Margin = 0 breaks Budget (an agent mid-chunk still   *)
(* transfers after the coordinator gave its expired slot to another);      *)
(* Revoke = FALSE breaks HoldBound (renewals go on during the hold);       *)
(* SlotUntilReleased = FALSE breaks Budget (TLC's finding on this model:   *)
(* a grant or renewal answered just before a hold reaches its agent after  *)
(* the revoked slot went to another; fixed in sites.py and uplink.rs).     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Agents, MaxTransfers, TTL, Margin, Chunk, Poll, D, Revoke, SlotUntilReleased

\* every counter saturates where nothing that reads it changes any more (a lease TTL old is expired however old)
Cap == TTL
Bound == TTL - Margin + Chunk
Upto(x, m) == IF x < m THEN x + 1 ELSE m
Inc(x) == Upto(x, Cap)
Perms == Permutations(Agents)

VARIABLES
    hold, holdAge,          \* the site holds; ticks since it began
    xfer,                   \* "idle" | "moving"
    aLease, aAge,           \* the agent believes it holds a lease; ticks since it sent the request that last confirmed it
    aOwes,                  \* the agent was granted a lease it has not given back (it may give back only what it knows)
    sinceCheck, sinceRenew, \* ticks since the agent last checked its lease (a chunk boundary) and last sent a renewal
    cLease, cAge,           \* the coordinator's lease: "none" | "live" | "revoked"; ticks since it last granted or renewed it
    req, reqAge,            \* the agent's request in flight: "none" | "lease" | "renew"; ticks since sent
    resp, respAge, respLat  \* the answer in flight: "none" | "ok" | "no"; ticks since its request was sent; since answered

vars == <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, req, reqAge, resp, respAge, respLat>>

TypeOK ==
    /\ hold \in BOOLEAN /\ holdAge \in 0..Bound
    /\ xfer \in [Agents -> {"idle", "moving"}]
    /\ aLease \in [Agents -> BOOLEAN] /\ aAge \in [Agents -> 0..Cap] /\ aOwes \in [Agents -> BOOLEAN]
    /\ sinceCheck \in [Agents -> 0..Cap] /\ sinceRenew \in [Agents -> 0..Cap]
    /\ cLease \in [Agents -> {"none", "live", "revoked"}] /\ cAge \in [Agents -> 0..Cap]
    /\ req \in [Agents -> {"none", "lease", "renew"}] /\ reqAge \in [Agents -> 0..Cap]
    /\ resp \in [Agents -> {"none", "ok", "no"}] /\ respAge \in [Agents -> 0..Cap] /\ respLat \in [Agents -> 0..Cap]

Live(a) == cLease[a] = "live" /\ cAge[a] < TTL
\* the slots a grant must leave room for: live leases, and revoked ones whose holder may not know yet
Holds(a) == cAge[a] < TTL /\ (cLease[a] = "live" \/ (SlotUntilReleased /\ cLease[a] = "revoked"))
LiveCount == Cardinality({b \in Agents : Holds(b)})
Fresh(a) == aLease[a] /\ aAge[a] < TTL - Margin

Init ==
    /\ hold = FALSE /\ holdAge = 0
    /\ xfer = [a \in Agents |-> "idle"]
    /\ aLease = [a \in Agents |-> FALSE] /\ aAge = [a \in Agents |-> 0] /\ aOwes = [a \in Agents |-> FALSE]
    /\ sinceCheck = [a \in Agents |-> 0] /\ sinceRenew = [a \in Agents |-> 0]
    /\ cLease = [a \in Agents |-> "none"] /\ cAge = [a \in Agents |-> 0]
    /\ req = [a \in Agents |-> "none"] /\ reqAge = [a \in Agents |-> 0]
    /\ resp = [a \in Agents |-> "none"] /\ respAge = [a \in Agents |-> 0] /\ respLat = [a \in Agents |-> 0]

\* a protected process at the site enters an uplink phase: every lease is revoked (Revoke)
HoldOn ==
    /\ ~hold
    /\ hold' = TRUE /\ holdAge' = 0
    /\ cLease' = IF Revoke THEN [a \in Agents |-> IF cLease[a] = "live" THEN "revoked" ELSE cLease[a]] ELSE cLease
    /\ UNCHANGED <<xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cAge, req, reqAge, resp, respAge, respLat>>

HoldOff ==
    /\ hold
    /\ hold' = FALSE /\ holdAge' = 0
    /\ UNCHANGED <<xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, req, reqAge, resp, respAge, respLat>>

AskLease(a) ==
    /\ xfer[a] = "idle" /\ ~aLease[a] /\ req[a] = "none" /\ resp[a] = "none"
    /\ req' = [req EXCEPT ![a] = "lease"] /\ reqAge' = [reqAge EXCEPT ![a] = 0]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, resp, respAge, respLat>>

SendRenew(a) ==
    /\ aLease[a] /\ req[a] = "none" /\ resp[a] = "none"
    /\ req' = [req EXCEPT ![a] = "renew"] /\ reqAge' = [reqAge EXCEPT ![a] = 0]
    /\ sinceRenew' = [sinceRenew EXCEPT ![a] = 0]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, cLease, cAge, resp, respAge, respLat>>

\* the coordinator processes a request (sites.lease, sites.renew)
Deliver(a) ==
    /\ req[a] # "none"
    /\ LET grant == ~hold /\ LiveCount < MaxTransfers
           renew == Live(a) /\ (~hold \/ ~Revoke)
           ok == IF req[a] = "lease" THEN grant ELSE renew
       IN /\ cLease' = [cLease EXCEPT ![a] = IF ok THEN "live"
                                              ELSE IF cLease[a] = "live" \/ (SlotUntilReleased /\ cLease[a] = "revoked")
                                                   THEN "revoked" ELSE "none"]
          /\ cAge' = IF ok THEN [cAge EXCEPT ![a] = 0] ELSE cAge
          /\ resp' = [resp EXCEPT ![a] = IF ok THEN "ok" ELSE "no"]
    /\ respAge' = [respAge EXCEPT ![a] = reqAge[a]] /\ respLat' = [respLat EXCEPT ![a] = 0]
    /\ req' = [req EXCEPT ![a] = "none"]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, reqAge>>

LoseRequest(a) ==
    /\ req[a] # "none"
    /\ req' = [req EXCEPT ![a] = "none"]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, reqAge, resp, respAge, respLat>>

LoseAnswer(a) ==
    /\ resp[a] # "none"
    /\ resp' = [resp EXCEPT ![a] = "none"]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, req, reqAge, respAge, respLat>>

\* the answer reaches the agent: its lease is confirmed as of when it sent the request, or gone
Receive(a) ==
    /\ resp[a] # "none"
    /\ aLease' = [aLease EXCEPT ![a] = (resp[a] = "ok")]
    /\ aAge' = IF resp[a] = "ok" THEN [aAge EXCEPT ![a] = respAge[a]] ELSE aAge
    /\ aOwes' = IF resp[a] = "ok" THEN [aOwes EXCEPT ![a] = TRUE] ELSE aOwes
    /\ resp' = [resp EXCEPT ![a] = "none"]
    /\ UNCHANGED <<hold, holdAge, xfer, sinceCheck, sinceRenew, cLease, cAge, req, reqAge, respAge, respLat>>

Start(a) ==
    /\ xfer[a] = "idle" /\ Fresh(a)
    /\ xfer' = [xfer EXCEPT ![a] = "moving"] /\ sinceCheck' = [sinceCheck EXCEPT ![a] = 0]
    /\ sinceRenew' = [sinceRenew EXCEPT ![a] = 0]
    /\ UNCHANGED <<hold, holdAge, aLease, aAge, aOwes, cLease, cAge, req, reqAge, resp, respAge, respLat>>

\* a chunk boundary (uplink.rs Transfer::pace): go on only with a fresh lease
Check(a) ==
    /\ xfer[a] = "moving"
    /\ sinceCheck' = [sinceCheck EXCEPT ![a] = 0]
    /\ IF Fresh(a) THEN UNCHANGED <<xfer, aLease>>
       ELSE /\ xfer' = [xfer EXCEPT ![a] = "idle"] /\ aLease' = [aLease EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<hold, holdAge, aAge, aOwes, sinceRenew, cLease, cAge, req, reqAge, resp, respAge, respLat>>

\* the agent, stopped and without the lease, gives a revoked one back (sites.release); the message may never arrive
GiveBack(a) ==
    /\ xfer[a] = "idle" /\ ~aLease[a] /\ aOwes[a] /\ req[a] = "none" /\ resp[a] = "none"
    /\ aOwes' = [aOwes EXCEPT ![a] = FALSE]
    /\ cLease' = IF cLease[a] = "revoked" THEN [cLease EXCEPT ![a] = "none"] ELSE cLease
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, sinceCheck, sinceRenew, cAge, req, reqAge, resp, respAge, respLat>>

\* the coordinator forgets an expired lease (the reaper)
Expire(a) ==
    /\ cLease[a] # "none" /\ cAge[a] >= TTL
    /\ cLease' = [cLease EXCEPT ![a] = "none"]
    /\ UNCHANGED <<hold, holdAge, xfer, aLease, aAge, aOwes, sinceCheck, sinceRenew, cAge, req, reqAge, resp, respAge, respLat>>

Finish(a) ==
    /\ xfer[a] = "moving"
    /\ xfer' = [xfer EXCEPT ![a] = "idle"] /\ aLease' = [aLease EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<hold, holdAge, aAge, aOwes, sinceCheck, sinceRenew, cLease, cAge, req, reqAge, resp, respAge, respLat>>

\* time passes only while every transferring agent is within its chunk and renewal periods, and every message within D
Tick ==
    /\ \A a \in Agents : xfer[a] = "moving" => sinceCheck[a] < Chunk /\ sinceRenew[a] < Poll
    /\ \A a \in Agents : req[a] # "none" => reqAge[a] < D
    /\ \A a \in Agents : resp[a] # "none" => respLat[a] < D
    /\ holdAge' = IF hold THEN Upto(holdAge, Bound) ELSE 0
    /\ aAge' = [a \in Agents |-> Inc(aAge[a])] /\ cAge' = [a \in Agents |-> Inc(cAge[a])]
    /\ sinceCheck' = [a \in Agents |-> Upto(sinceCheck[a], Chunk)] /\ sinceRenew' = [a \in Agents |-> Upto(sinceRenew[a], Poll)]
    /\ reqAge' = [a \in Agents |-> Upto(reqAge[a], D)] /\ respAge' = [a \in Agents |-> Inc(respAge[a])]
    /\ respLat' = [a \in Agents |-> Upto(respLat[a], D)]
    /\ UNCHANGED <<hold, xfer, aLease, aOwes, cLease, req, resp>>

Next ==
    \/ HoldOn \/ HoldOff \/ Tick
    \/ \E a \in Agents : AskLease(a) \/ SendRenew(a) \/ Deliver(a) \/ LoseRequest(a) \/ LoseAnswer(a)
                         \/ Receive(a) \/ Start(a) \/ Check(a) \/ Finish(a) \/ GiveBack(a) \/ Expire(a)

Spec == Init /\ [][Next]_vars

Budget == Cardinality({a \in Agents : xfer[a] = "moving"}) <= MaxTransfers

HoldBound == hold => \A a \in Agents : xfer[a] = "moving" => holdAge < Bound

=============================================================================
