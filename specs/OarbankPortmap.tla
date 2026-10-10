---------------------------- MODULE OarbankPortmap ----------------------------
(***************************************************************************)
(* The agent's port-mapping manager (docs/design/inbound-listeners.md,     *)
(* "Port mapping"): one agent (node) maps router ports for its listeners   *)
(* on one router (gateway), next to a foreign device that maps ports of    *)
(* its own.                                                                *)
(*                                                                         *)
(* The router holds a set of mappings [ext, client, desc, ttl] keyed by    *)
(* external port. An add for a port held by another internal client is a   *)
(* conflict (UPnP 718); an add by the same client replaces the mapping (a  *)
(* renewal). A reboot drops every mapping and bumps the router's epoch. A  *)
(* lease mapping that nobody renews runs out (Tick); a permanent-only      *)
(* router (PermanentOnly) makes every mapping of the agent permanent.      *)
(*                                                                         *)
(* The agent writes each intended mapping to its write-ahead journal       *)
(* (persistent) BEFORE the request goes out. Requests are not atomic: the  *)
(* request is sent, the router applies it (or the request is lost), and    *)
(* the response may be lost or arrive after the agent crashed. A crash     *)
(* loses the agent's volatile state (announcements, timers, the response   *)
(* it waited for); a restart reads the journal, releases what is no longer *)
(* wanted or points at an old address, and on a router that lists mappings *)
(* deletes every mapping with its own description and its own current      *)
(* address that the journal does not account for. Every delete reads the   *)
(* entry back first and removes it only when client and description are    *)
(* the journaled ones (GetSpecificPortMappingEntry). The periodic verify   *)
(* checks the node's address (network change: release the old mapping,     *)
(* then map again) and the router's epoch (reboot: map the journaled port  *)
(* again under the same journal entry); a held lease is renewed at half    *)
(* life. The agent announces "mapped at port p" to the module (ann) and    *)
(* withdraws it when a verify fails or the listener is no longer wanted.   *)
(*                                                                         *)
(* Time is abstract: with VerifyInterval = 1, Tick is one verify interval. *)
(* A running agent verifies every held mapping at least every              *)
(* VerifyInterval ticks and renews a lease at half life, or releases it if *)
(* its listener is no longer wanted (Tick is disabled while either is      *)
(* overdue). A request's round trip is shorter than a tick, and a request  *)
(* sent before a crash is applied or lost before the agent is back.        *)
(*                                                                         *)
(* Faults (bounded by MaxFaults, kinds chosen by FaultKinds): agent crash, *)
(* router reboot, network change (Wi-Fi to Ethernet: a new internal        *)
(* address), a lost request or response. The agent may also stop forever   *)
(* (AgentMayDie). The foreign device adds up to MaxForeign mappings (on    *)
(* any port, including the agent's) and deletes its own. The owner turns   *)
(* listeners on and off at will.                                           *)
(*                                                                         *)
(* Not modelled: protocol discovery and fallback between PCP, NAT-PMP and  *)
(* UPnP, router_choice, external address changes, IPv6 pinholes, a second  *)
(* gateway (the old gateway after a network change is the same router).    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    NumListeners,       \* listeners 1..NumListeners; listener l asks for port 2l-1, fallback 2l
    Policy,             \* the listeners' fallback: "refuse" | "next_free" (range of 2 ports)
    PermanentOnly,      \* router mode: accepts only permanent mappings (UPnP 725 / 402)
    RouterLists,        \* router lists its mappings (GetGenericPortMappingEntry)
    DeleteNeedsSameClient, \* router deletes a mapping only for a request from its internal client
                        \* (PCP / NAT-PMP keyed deletes, miniupnpd secure mode)
    AgentMayDie,        \* the agent may stop and never return
    FaultKinds,         \* subset of {"crash", "reboot", "net", "lose"}
    MaxFaults,          \* fault budget
    MaxForeign,         \* mappings the foreign device may add
    Lease,              \* lease in ticks (>= 3: renewal at half life)
    VerifyInterval,     \* ticks between verifies
    \* Switches. The design's value is given after "="; the other value is a weakened variant.
    WriteAhead,         \* = TRUE   intended mapping journaled before the request (FALSE: variant a)
    ReadBackDelete,     \* = TRUE   delete only after reading back client and description (FALSE: variant b)
    EpochCheck,         \* = TRUE   verify and renewal compare the router's epoch (FALSE: variant c)
    ReleaseBeforeRemap, \* = TRUE   after a network change the old mapping is released before the
                        \*          listener maps again (FALSE: finding d)
    AtomicReadBack,     \* = TRUE   read-back and delete are one router step (FALSE: finding e,
                        \*          the two UPnP calls GetSpecific... then DeletePortMapping)
    EpochRemapKeepsEntry \* = TRUE  an epoch reset re-maps the journaled port under the same journal
                        \*          entry (FALSE: finding g, the entry is dropped and the listener
                        \*          maps afresh from its first port)

ASSUME NumListeners \in 1..2
ASSUME Policy \in {"refuse", "next_free"}
ASSUME FaultKinds \subseteq {"crash", "reboot", "net", "lose"}
ASSUME MaxFaults \in Nat /\ MaxForeign \in Nat /\ Lease \in 3..5 /\ VerifyInterval \in 1..2
ASSUME {PermanentOnly, RouterLists, DeleteNeedsSameClient, AgentMayDie, WriteAhead,
        ReadBackDelete, EpochCheck, ReleaseBeforeRemap, AtomicReadBack, EpochRemapKeepsEntry}
       \subseteq BOOLEAN

Listeners  == 1..NumListeners
Range(l)   == <<2 * l - 1, 2 * l>>          \* external port, then the next_free fallback
Ports      == 1..(2 * NumListeners)
AgentAddrs == {"a1", "a2"}                  \* the node's internal addresses (Wi-Fi, Ethernet)
Addrs      == AgentAddrs \cup {"f"}         \* "f": the foreign device
FDesc      == 0                             \* description of a foreign mapping (ours: the listener)
Epochs     == 0..MaxFaults
NewTTL     == IF PermanentOnly THEN 0 ELSE Lease   \* ttl 0 = permanent
NewLeft    == IF PermanentOnly THEN 0 ELSE Lease
Ops        == {"add", "get", "del", "delport"}
Min(a, b)  == IF a < b THEN a ELSE b
Other(a)   == IF a = "a1" THEN "a2" ELSE "a1"

\* A journal entry. st: intended (request may or may not have been applied), held (the router
\* answered), releasing (a delete is due). ep: router epoch of the answer; left: lease ticks left
\* as the agent computes them from the journaled expiry.
Entry(l, p, c, st, ep, left) == [l |-> l, ext |-> p, cl |-> c, st |-> st, ep |-> ep, left |-> left]
Entries == [l : Listeners, ext : Ports, cl : AgentAddrs, st : {"intended", "held", "releasing"},
            ep : Epochs, left : 0..Lease]
Mappings == [ext : Ports, cl : Addrs, ds : Listeners \cup {FDesc}, ttl : 0..Lease]

\* Requests carry the journaled client (cl), the sender's address at send time (from) and where
\* they came from (src: normal run, journal cleanup during start, listing cleanup).
Reqs  == [op : Ops \cup {"none"}, l : Listeners, ext : Ports, cl : AgentAddrs, from : AgentAddrs,
          src : {"run", "boot", "list"}]
Resps == [op : Ops \cup {"none"}, l : Listeners, ext : Ports, cl : AgentAddrs,
          src : {"run", "boot", "list"}, ok : BOOLEAN, ep : Epochs, to : BOOLEAN]
NoReq  == [op |-> "none", l |-> 1, ext |-> 1, cl |-> "a1", from |-> "a1", src |-> "run"]
NoResp == [op |-> "none", l |-> 1, ext |-> 1, cl |-> "a1", src |-> "run", ok |-> FALSE, ep |-> 0,
           to |-> FALSE]

VARIABLES
    maps,      \* router: set of mappings, at most one per external port
    repoch,    \* router: epoch (boot count; PCP / NAT-PMP seconds-since-start reset)
    up,        \* agent process running
    dead,      \* agent stopped forever
    boot,      \* agent: start-up cleanup in progress (volatile)
    addr,      \* node: current internal address (host state, survives an agent crash)
    wanted,    \* owner: listener assigned and enabled
    jr,        \* agent: write-ahead journal (persistent)
    ann,       \* agent: announced port per listener (0 = none) (volatile)
    clock,     \* agent: ticks since the last verify per listener (volatile)
    req,       \* request in flight (NoReq = none)
    resp,      \* response the agent has not handled yet (NoResp = none)
    stale,     \* history: ticks a listener has been announced while the router held no mapping
    ghost,     \* history: [fdel, rebootSeen, netSeen, bootClean]
    faults,
    foreign

vars == <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, req, resp, stale, ghost,
          faults, foreign>>

-----------------------------------------------------------------------------
TypeOK ==
    /\ maps \subseteq Mappings
    /\ \A m1, m2 \in maps : m1.ext = m2.ext => m1 = m2
    /\ repoch \in Epochs
    /\ up \in BOOLEAN /\ dead \in BOOLEAN /\ boot \in BOOLEAN /\ (dead => ~up)
    /\ addr \in AgentAddrs
    /\ wanted \in [Listeners -> BOOLEAN]
    /\ jr \subseteq Entries
    /\ ann \in [Listeners -> {0} \cup Ports]
    /\ clock \in [Listeners -> 0..VerifyInterval]
    /\ req \in Reqs /\ resp \in Resps
    /\ stale \in [Listeners -> 0..(VerifyInterval + 1)]
    /\ ghost \in [fdel : BOOLEAN, rebootSeen : BOOLEAN, netSeen : BOOLEAN, bootClean : BOOLEAN]
    /\ faults \in 0..MaxFaults /\ foreign \in 0..MaxForeign

MapAt(p)      == {m \in maps : m.ext = p}
Mapped(l, p)  == \E m \in maps : m.ext = p /\ m.cl = addr /\ m.ds = l   \* reaches the node now
MappingsOf(l) == {m \in maps : m.ds = l}
EntriesOf(l)  == {e \in jr : e.l = l}
Idle          == req.op = "none" /\ resp.op = "none"
CanFault(k)   == k \in FaultKinds /\ faults < MaxFaults
LostOk(lost)  == lost => CanFault("lose")
Req(op, l, p, c) == [op |-> op, l |-> l, ext |-> p, cl |-> c, from |-> addr,
                     src |-> IF boot THEN "boot" ELSE "run"]
\* The delete the agent sends: one read-back-and-delete step, or (finding e) a read-back ("get")
\* followed by a delete by port ("delport").
DelOp == IF AtomicReadBack \/ ~ReadBackDelete THEN "del" ELSE "get"
\* A held lease at half life: renewed if its listener is wanted, else released (Unmap).
LeaseDue(e) == e.st = "held" /\ ~PermanentOnly /\ e.left <= 1 /\ e.cl = addr
\* Every step but Tick restarts a listener's staleness count when, after the step, it is not
\* announced, announced afresh, or its announced mapping is on the router for the node's address.
StaleUpd ==
    stale' = [l \in Listeners |->
                IF \/ ann'[l] # ann[l] \/ ann'[l] = 0
                   \/ \E m \in maps' : m.ext = ann'[l] /\ m.cl = addr' /\ m.ds = l
                THEN 0 ELSE stale[l]]
Respond(r, ok, lost) ==
    IF ~up THEN NoResp     \* the agent that sent it is gone: nobody reads the answer
    ELSE [op |-> r.op, l |-> r.l, ext |-> r.ext, cl |-> r.cl, src |-> r.src, ok |-> ok,
          ep |-> repoch, to |-> lost]

Init ==
    /\ maps = {} /\ repoch = 0
    /\ up = TRUE /\ dead = FALSE /\ boot = TRUE
    /\ addr = "a1"
    /\ wanted = [l \in Listeners |-> TRUE]
    /\ jr = {}
    /\ ann = [l \in Listeners |-> 0]
    /\ clock = [l \in Listeners |-> 0]
    /\ req = NoReq /\ resp = NoResp
    /\ stale = [l \in Listeners |-> 0]
    /\ ghost = [fdel |-> FALSE, rebootSeen |-> FALSE, netSeen |-> FALSE, bootClean |-> FALSE]
    /\ faults = 0 /\ foreign = 0

-----------------------------------------------------------------------------
(* The router                                                              *)

\* AddPortMapping / PCP MAP / NAT-PMP map (lost = the response is lost).
ApplyAdd(lost) ==
    /\ req.op = "add" /\ LostOk(lost)
    /\ LET r  == req
           ms == MapAt(r.ext)
           ok == \A m \in ms : m.cl = r.cl
       IN /\ maps' = IF ok THEN (maps \ ms) \cup {[ext |-> r.ext, cl |-> r.cl, ds |-> r.l, ttl |-> NewTTL]}
                     ELSE maps
          /\ resp' = Respond(r, ok, lost)
    /\ req' = NoReq
    /\ faults' = IF lost THEN faults + 1 ELSE faults
    /\ UNCHANGED <<repoch, up, dead, boot, addr, wanted, jr, ann, clock, ghost, foreign>>
    /\ StaleUpd

\* GetSpecificPortMappingEntry (finding e only): is the entry at the port still ours?
ApplyGet(lost) ==
    /\ req.op = "get" /\ LostOk(lost)
    /\ resp' = Respond(req, \E m \in MapAt(req.ext) : m.cl = req.cl /\ m.ds = req.l, lost)
    /\ req' = NoReq
    /\ faults' = IF lost THEN faults + 1 ELSE faults
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, ghost, foreign>>
    /\ StaleUpd

\* "del": read back and delete in one step (only the journaled client and description), or by
\* port when ReadBackDelete = FALSE; "delport": the delete by port after a separate read-back.
ApplyDel(lost) ==
    /\ req.op \in {"del", "delport"} /\ LostOk(lost)
    /\ LET r       == req
           ms      == MapAt(r.ext)
           cand    == IF r.op = "del" /\ ReadBackDelete
                      THEN {m \in ms : m.cl = r.cl /\ m.ds = r.l} ELSE ms
           victims == IF DeleteNeedsSameClient THEN {m \in cand : m.cl = r.from} ELSE cand
       IN /\ maps' = maps \ victims
          /\ ghost' = [ghost EXCEPT !.fdel = @ \/ \E m \in victims : m.ds = FDesc,
                                    !.bootClean = @ \/ (victims # {} /\ r.src = "boot")]
          /\ resp' = Respond(r, victims # {}, lost)
    /\ req' = NoReq
    /\ faults' = IF lost THEN faults + 1 ELSE faults
    /\ UNCHANGED <<repoch, up, dead, boot, addr, wanted, jr, ann, clock, foreign>>
    /\ StaleUpd

\* The request never reaches the router; a running agent times out.
DropReq ==
    /\ req.op # "none" /\ CanFault("lose")
    /\ resp' = IF up THEN [op |-> req.op, l |-> req.l, ext |-> req.ext, cl |-> req.cl,
                           src |-> req.src, ok |-> FALSE, ep |-> repoch, to |-> TRUE]
               ELSE NoResp
    /\ req' = NoReq
    /\ faults' = faults + 1
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, ghost, foreign>>
    /\ StaleUpd

Reboot ==
    /\ CanFault("reboot")
    /\ maps' = {} /\ repoch' = repoch + 1 /\ faults' = faults + 1
    /\ UNCHANGED <<up, dead, boot, addr, wanted, jr, ann, clock, req, resp, ghost, foreign>>
    /\ StaleUpd

\* Time passes. A running agent verifies every held mapping within VerifyInterval ticks and
\* renews a lease at half life, so Tick waits for overdue verifies and renewals; it also waits
\* for the response the agent is handling (a round trip is shorter than a tick).
Tick ==
    /\ up => resp.op = "none"
    /\ ~(up /\ \E e \in jr : e.st = "held" /\ (clock[e.l] >= VerifyInterval \/ LeaseDue(e)))
    /\ maps' = {[m EXCEPT !.ttl = m.ttl - 1] : m \in {x \in maps : x.ttl > 1}}
               \cup {x \in maps : x.ttl = 0}
    /\ jr' = {IF e.st = "held" /\ e.left > 0 THEN [e EXCEPT !.left = e.left - 1] ELSE e : e \in jr}
    /\ clock' = [l \in Listeners |-> IF up /\ \E e \in EntriesOf(l) : e.st = "held"
                                     THEN Min(clock[l] + 1, VerifyInterval) ELSE 0]
    /\ stale' = [l \in Listeners |-> IF ann[l] # 0 /\ ~Mapped(l, ann[l])
                                     THEN Min(stale[l] + 1, VerifyInterval + 1) ELSE 0]
    /\ UNCHANGED <<repoch, up, dead, boot, addr, wanted, ann, req, resp, ghost, faults, foreign>>

-----------------------------------------------------------------------------
(* The foreign device, the owner, the host                                 *)

ForeignAdd(p) ==
    /\ foreign < MaxForeign /\ MapAt(p) = {}
    /\ maps' = maps \cup {[ext |-> p, cl |-> "f", ds |-> FDesc, ttl |-> 0]}
    /\ foreign' = foreign + 1
    /\ UNCHANGED <<repoch, up, dead, boot, addr, wanted, jr, ann, clock, req, resp, ghost, faults>>
    /\ StaleUpd

ForeignDel(p) ==
    /\ \E m \in MapAt(p) : m.ds = FDesc /\ maps' = maps \ {m}
    /\ UNCHANGED <<repoch, up, dead, boot, addr, wanted, jr, ann, clock, req, resp, ghost, faults, foreign>>
    /\ StaleUpd

Toggle(l) ==
    /\ wanted' = [wanted EXCEPT ![l] = ~@]
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, jr, ann, clock, req, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* Wi-Fi to Ethernet (or back): the node's internal address changes; old mappings point at an
\* address the node no longer has.
NetChange ==
    /\ CanFault("net")
    /\ addr' = Other(addr) /\ faults' = faults + 1
    /\ UNCHANGED <<maps, repoch, up, dead, boot, wanted, jr, ann, clock, req, resp, ghost, foreign>>
    /\ StaleUpd

\* The agent crashes: volatile state is lost, the journal and a request in flight are not.
Crash ==
    /\ up /\ CanFault("crash")
    /\ up' = FALSE /\ boot' = FALSE
    /\ ann' = [l \in Listeners |-> 0] /\ clock' = [l \in Listeners |-> 0] /\ resp' = NoResp
    /\ faults' = faults + 1
    /\ UNCHANGED <<maps, repoch, dead, addr, wanted, jr, req, ghost, foreign>>
    /\ StaleUpd

\* The agent stops and never returns (uninstalled without the release step, machine gone).
Die ==
    /\ AgentMayDie /\ ~dead
    /\ dead' = TRUE /\ up' = FALSE /\ boot' = FALSE
    /\ ann' = [l \in Listeners |-> 0] /\ clock' = [l \in Listeners |-> 0] /\ resp' = NoResp
   
    /\ UNCHANGED <<maps, repoch, addr, wanted, jr, req, ghost, faults, foreign>>
    /\ StaleUpd

\* A request sent before the crash is applied or lost before the agent is back.
Restart ==
    /\ ~up /\ ~dead /\ req.op = "none"
    /\ up' = TRUE /\ boot' = TRUE
    /\ UNCHANGED <<maps, repoch, dead, addr, wanted, jr, ann, clock, req, resp, ghost, faults, foreign>>
    /\ StaleUpd

-----------------------------------------------------------------------------
(* The agent. It handles one request at a time.                            *)

\* Request a mapping: journal it as intended, then send (with WriteAhead = FALSE, send only).
StartMap(l) ==
    /\ up /\ Idle /\ wanted[l]
    /\ IF ReleaseBeforeRemap THEN EntriesOf(l) = {}
       ELSE \A e \in EntriesOf(l) : e.st = "releasing"
    /\ LET p == Range(l)[1] IN
         /\ jr' = IF WriteAhead THEN jr \cup {Entry(l, p, addr, "intended", 0, 0)} ELSE jr
         /\ req' = Req("add", l, p, addr)
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, ann, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* The answer to an add (a first request or a renewal).
OnAdd ==
    /\ up /\ resp.op = "add" /\ ~resp.to
    /\ LET r       == resp
           mine    == {e \in jr : e.l = r.l /\ e.ext = r.ext
                                  /\ (e.st = "intended" \/ (e.st = "held" /\ e.cl = r.cl))}
           renewal == \E e \in mine : e.st = "held"
           nxt     == IF Policy = "next_free" /\ wanted[r.l] /\ r.ext = Range(r.l)[1]
                      THEN Range(r.l)[2] ELSE 0
       IN IF r.ok THEN
            \* held; the answer is the verification (announce, restart the verify timer) unless
            \* the node's address changed while the request was out: then the verify handles it
            /\ jr' = (jr \ mine) \cup {Entry(r.l, r.ext, r.cl, "held", r.ep, NewLeft)}
            /\ ann' = IF wanted[r.l] /\ r.cl = addr THEN [ann EXCEPT ![r.l] = r.ext] ELSE ann
            /\ clock' = IF r.cl = addr THEN [clock EXCEPT ![r.l] = 0] ELSE clock
            /\ ghost' = [ghost EXCEPT !.rebootSeen =
                            @ \/ (EpochCheck /\ \E e \in mine : e.st = "held" /\ e.ep # r.ep)]
            /\ req' = req
          ELSE IF renewal THEN
            \* the router lost the mapping and another client took the port: lost
            /\ jr' = jr \ mine
            /\ ann' = [ann EXCEPT ![r.l] = 0]
            /\ UNCHANGED <<clock, ghost, req>>
          ELSE IF nxt # 0 THEN
            \* conflict, next_free: journal the next port of the range, then request it
            /\ jr' = (jr \ mine) \cup (IF WriteAhead THEN {Entry(r.l, nxt, addr, "intended", 0, 0)}
                                       ELSE {})
            /\ req' = Req("add", r.l, nxt, addr)
            /\ UNCHANGED <<ann, clock, ghost>>
          ELSE
            \* conflict, refuse (or the range is exhausted): PORT_TAKEN, retried later
            /\ jr' = jr \ mine
            /\ UNCHANGED <<ann, clock, ghost, req>>
    /\ resp' = NoResp
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, faults, foreign>>
    /\ StaleUpd

\* The answer to a read-back (finding e): delete by port if the entry is still ours.
OnGet ==
    /\ up /\ resp.op = "get" /\ ~resp.to
    /\ IF resp.ok
       THEN /\ req' = [op |-> "delport", l |-> resp.l, ext |-> resp.ext, cl |-> resp.cl,
                       from |-> addr, src |-> resp.src]
            /\ jr' = jr
       ELSE /\ jr' = jr \ {e \in jr : e.l = resp.l /\ e.ext = resp.ext /\ e.cl = resp.cl
                                      /\ e.st = "releasing"}
            /\ req' = req
    /\ resp' = NoResp
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, ann, clock, ghost, faults, foreign>>
    /\ StaleUpd

\* The answer to a delete: the journal entry is cleared (whether or not anything was removed:
\* an entry that is not ours any more is left alone, and leases are the backstop).
OnDel ==
    /\ up /\ resp.op \in {"del", "delport"} /\ ~resp.to
    /\ jr' = jr \ {e \in jr : e.l = resp.l /\ e.ext = resp.ext /\ e.cl = resp.cl /\ e.st = "releasing"}
    /\ resp' = NoResp
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, ann, clock, req, ghost, faults, foreign>>
    /\ StaleUpd

\* No answer: send the same request again (the same port; the journal is unchanged).
OnTimeout ==
    /\ up /\ resp.to
    /\ req' = [op |-> resp.op, l |-> resp.l, ext |-> resp.ext, cl |-> resp.cl, from |-> addr,
               src |-> resp.src]
    /\ resp' = NoResp
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, ghost, faults, foreign>>
    /\ StaleUpd

\* The listener is no longer wanted: withdraw the announcement, journal the release, delete.
Unmap(l) ==
    /\ up /\ Idle /\ ~wanted[l]
    /\ \E e \in EntriesOf(l) :
         /\ e.st = "held"
         /\ jr' = (jr \ {e}) \cup {[e EXCEPT !.st = "releasing"]}
         /\ req' = Req(DelOp, l, e.ext, e.cl)
    /\ ann' = [ann EXCEPT ![l] = 0]
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* A journaled release that has not completed (after a crash): delete again.
Release(e) ==
    /\ up /\ Idle /\ e \in jr /\ e.st = "releasing"
    /\ req' = Req(DelOp, e.l, e.ext, e.cl)
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* An intended entry found at start (the request may or may not have been applied): request it
\* again if it is still wanted at the current address, else release it.
ResumeIntended(e) ==
    /\ up /\ Idle /\ e \in jr /\ e.st = "intended"
    /\ IF wanted[e.l] /\ e.cl = addr
       THEN /\ req' = Req("add", e.l, e.ext, e.cl)
            /\ jr' = jr
       ELSE /\ jr' = (jr \ {e}) \cup {[e EXCEPT !.st = "releasing"]}
            /\ req' = Req(DelOp, e.l, e.ext, e.cl)
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, ann, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* Renewal at half life (also the first thing after a restart that found the lease expired):
\* the same add again, which re-creates the mapping if the router lost it. A listener that is
\* no longer wanted is released instead (Unmap).
Renew(e) ==
    /\ up /\ Idle /\ e \in jr /\ LeaseDue(e) /\ wanted[e.l]
    /\ req' = Req("add", e.l, e.ext, e.cl)
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* The periodic verify: the node's address on the default route and the router's epoch.
Verify(l) ==
    /\ up /\ Idle
    /\ \E e \in EntriesOf(l) :
         /\ e.st = "held"
         /\ CASE e.cl # addr ->
                   \* network change: lost; release the old mapping (at once, or later: finding d)
                   /\ ann' = [ann EXCEPT ![l] = 0]
                   /\ jr' = (jr \ {e}) \cup {[e EXCEPT !.st = "releasing"]}
                   /\ req' = IF ReleaseBeforeRemap THEN Req(DelOp, l, e.ext, e.cl) ELSE req
                   /\ ghost' = [ghost EXCEPT !.netSeen = TRUE]
                   /\ clock' = clock
              [] EpochCheck /\ e.ep # repoch ->
                   \* the router rebooted and lost its mappings: lost; map the journaled port again
                   \* at once (a renewal whose answer was lost may already have re-created it)
                   /\ ann' = [ann EXCEPT ![l] = 0]
                   /\ jr' = IF EpochRemapKeepsEntry
                            THEN (jr \ {e}) \cup {[e EXCEPT !.st = "intended", !.ep = 0, !.left = 0]}
                            ELSE jr \ {e}
                   /\ req' = IF EpochRemapKeepsEntry THEN Req("add", l, e.ext, e.cl) ELSE req
                   /\ ghost' = [ghost EXCEPT !.rebootSeen = TRUE]
                   /\ clock' = clock
              [] OTHER ->
                   /\ clock' = [clock EXCEPT ![l] = 0]
                   /\ ann' = IF wanted[l] /\ (PermanentOnly \/ e.left > 0)
                             THEN [ann EXCEPT ![l] = e.ext] ELSE ann
                   /\ UNCHANGED <<jr, req, ghost>>
   
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, resp, faults, foreign>>
    /\ StaleUpd

\* Listing cleanup at start: mappings with our description and our current address that the
\* journal does not account for. (The listing is read in the same step; the delete reads back.)
ListCands == IF RouterLists /\ boot
             THEN {m \in maps : m.ds \in Listeners /\ m.cl = addr
                                /\ ~\E e \in jr : e.l = m.ds /\ e.ext = m.ext}
             ELSE {}
ListCleanup(m) ==
    /\ up /\ Idle /\ m \in ListCands
    /\ req' = [op |-> DelOp, l |-> m.ds, ext |-> m.ext, cl |-> m.cl, from |-> addr, src |-> "list"]
    /\ UNCHANGED <<maps, repoch, up, dead, boot, addr, wanted, jr, ann, clock, resp, ghost, faults, foreign>>
    /\ StaleUpd

\* Start-up cleanup is over: nothing intended or releasing, no held entry unwanted, nothing to list.
EndBoot ==
    /\ up /\ boot /\ Idle /\ ListCands = {}
    /\ ~\E e \in jr : e.st \in {"intended", "releasing"} \/ (e.st = "held" /\ ~wanted[e.l])
    /\ boot' = FALSE
    /\ UNCHANGED <<maps, repoch, up, dead, addr, wanted, jr, ann, clock, req, resp, ghost, faults, foreign>>
    /\ StaleUpd

-----------------------------------------------------------------------------
ApplyAny(lost) == ApplyAdd(lost) \/ ApplyGet(lost) \/ ApplyDel(lost)
OnResp == OnAdd \/ OnGet \/ OnDel \/ OnTimeout

Next ==
    \/ \E lost \in BOOLEAN : ApplyAny(lost)
    \/ DropReq \/ Reboot \/ Tick
    \/ \E p \in Ports : ForeignAdd(p) \/ ForeignDel(p)
    \/ \E l \in Listeners : Toggle(l)
    \/ NetChange \/ Crash \/ Die \/ Restart
    \/ OnResp
    \/ \E l \in Listeners : StartMap(l) \/ Unmap(l) \/ Verify(l)
    \/ \E e \in jr : Release(e) \/ ResumeIntended(e) \/ Renew(e)
    \/ \E m \in maps : ListCleanup(m)
    \/ EndBoot

\* Weak fairness on the router answering, on time passing (so unrenewed leases run out), on the
\* agent's steps and on its restart (unless it died). Faults, the foreign device and the owner
\* are unfair; faults are bounded.
Fairness ==
    /\ WF_vars(ApplyAny(FALSE))
    /\ WF_vars(Tick)
    /\ WF_vars(Restart)
    /\ WF_vars(OnResp)
    /\ \A l \in Listeners : WF_vars(StartMap(l)) /\ WF_vars(Unmap(l)) /\ WF_vars(Verify(l))
    /\ WF_vars(\E e \in jr : Release(e) \/ ResumeIntended(e) \/ Renew(e))
    /\ WF_vars(\E m \in maps : ListCleanup(m))
    /\ WF_vars(EndBoot)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties                                                               *)

\* The agent never deletes a mapping it did not create (a foreign description; the agent's own
\* mappings always carry one of its addresses as client and its own description).
NoForeignDelete == ~ghost.fdel

\* The module is never told "mapped at p" for longer than one verify interval while the router
\* holds no mapping of the listener at p for the node's current address.
AnnouncedImpliesMapped == \A l \in Listeners : stale[l] <= VerifyInterval

\* At most one router mapping per listener at any time.
AtMostOneExternalPortPerListener == \A l \in Listeners : Cardinality(MappingsOf(l)) <= 1

\* Once a listener is no longer wanted (and stays so), the router eventually holds no mapping of it.
EventuallyClean ==
    \A l \in Listeners : (<>[](~wanted[l])) => <>[](MappingsOf(l) = {})

-----------------------------------------------------------------------------
(* Reachability witnesses (vacuity checks). Each is written as an invariant *)
(* that TLC is EXPECTED to violate, proving the scenario is reachable.      *)

\* The agent noticed a router reboot and is mapped and announced again.
W_RebootRecovered == ~(ghost.rebootSeen /\ \E l \in Listeners : ann[l] # 0 /\ Mapped(l, ann[l]))

\* The foreign device holds the listener's port; next_free mapped and announced the fallback.
W_ConflictNextFree ==
    ~\E l \in Listeners : /\ ann[l] = Range(l)[2] /\ Mapped(l, Range(l)[2])
                          /\ \E m \in MapAt(Range(l)[1]) : m.ds = FDesc

\* After a network change the listener is mapped to the new address, announced, and the mapping
\* to the old address is gone.
W_NetChangeRemapped ==
    ~(ghost.netSeen /\ \E l \in Listeners : /\ ann[l] # 0 /\ Mapped(l, ann[l])
                                           /\ \A m \in MappingsOf(l) : m.cl = addr)

\* The start-up cleanup deleted a journaled mapping left from before a crash.
W_RestartCleanup == ~ghost.bootClean
=============================================================================
