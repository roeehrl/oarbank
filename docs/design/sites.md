# Sites: nodes that share one internet line

Status: built, ships in **core 2.10.0** and **oarbank-sdk 1.7.0** (PLAN D55; invariant S27).

Nodes behind one internet line slow each other's large transfers down, and the slowdown is not shared fairly with the
owner's own programs. For example, a large upload that takes about 40 s alone can take four times as long while another
machine on the same line uploads too. A protected program that must finish an upload by a deadline then misses it
because fleet work on *another* machine at the same place started a large transfer.
Host protection ([protection.md](protection.md)) only acts on the node it runs on, so it cannot prevent that.

A **site** (PLAN D55) groups the nodes that share a line. While a protected process at the site is in a phase its rule
tags `uplink`, network-heavy fleet work pauses on every node of the site; outside such phases the site's **uplink
budget** limits how much runs at once. Nothing here names a particular program: the protected program and its upload
phase are an owner rule, and the tag is the only link.

## Why a first-class site and not a group

Settings groups ([settings.md](settings.md), "Groups and labels") were considered: a group "home" with the members and
a few settings for the budget. They do not fit:

- **A site is a partition, a group is not.** A node shares exactly one internet line; groups overlap by design (a node
  is in Laptops and in macOS and in a canary group at once). A node in two "site groups" would have two budgets and two
  holds with no right answer.
- **Membership must be confirmed, not inferred.** Group membership follows facts and labels the moment they change. A
  site's hold pauses work on other machines, so its membership is the owner's explicit choice; facts only *suggest*.
- **A site has runtime state of its own:** the current hold and why, transfer leases with expiries, measured transfer
  rates. Settings are values resolved per node; none of that is a value.
- **Enforcement is cross-node.** A setting is resolved for one node and sent to it. A site's hold on node B is caused by
  node A's phase; it is computed on the coordinator from several nodes' heartbeats and pushed to all of them.

So sites are their own table (`sites`, `site_members` with the node as primary key) with their own operations. A group
can still select the same nodes for settings; the two do not interact.

## Model

```sql
sites (site_id, name UNIQUE, description, uplink_mbps, max_transfers, max_heavy_jobs, hold_on, hold_since, hold_why, ...)
site_members (node_id PRIMARY KEY, site_id, added_by, added_at)        -- a node is at one site at most
uplink_leases (lease_id, site_id, node_id, kind, dir, bytes, mbps, granted_at, renewed_at, expires_at, peak)
uplink_transfers (site_id, node_id, kind, dir, bytes, seconds, mbps, solo, paced, at)   -- the measured-capacity hint
node_net (node_id PRIMARY KEY, gateway_fp, public_fp, observed_at)    -- keyed fingerprints, never an address
site_dismissed (key, by, at, why)                                       -- suggestions accepted or dismissed
```

**The budget** is three owner values: `max_transfers` (bulk transfers at once, default 1), `max_heavy_jobs`
(network-heavy jobs at once, default 1; 0 admits none) and `uplink_mbps` (optional: the rate the fleet's transfers may
use together; each lease is paced at `uplink_mbps / max_transfers`). The defaults follow the example above: on a saturated
line one transfer at a time finishes each sooner than two.

## The hold

`sites.state(site)` is `protection.any_phase_on(members, "uplink")` (step 1's helper, never looser): **on** while any
member's `uplink`-tagged phase is on, or cannot be read, or a member that has such a phase has not reported for 60 s.
The causes are put in words from `protection.node_phases`: "paused because mini's rule trainer is in an upload phase
(trainer#0)", "...: its phase source cannot be read, so it counts as in an upload phase", "mini has an upload phase and
has not reported for over 60 s".

The coordinator recomputes a site in every member's heartbeat, on every lease request and renewal, and on the reaper's
pass (a member falling silent). A change is persisted (`hold_on`, `hold_since`, `hold_why`) with an event
(`site_uplink_hold`, `site_uplink_free`), and a hold revokes every lease at the site.

While a site holds:

| What | Where | How |
|---|---|---|
| Bulk transfers: dataset staging (origins and the coordinator), result and checkpoint uploads | every member's agent | no lease is granted; leases are revoked; the agent's gate stops the transfer between chunks and resumes it when the hold ends |
| Network-heavy jobs already running | every member's agent | paused (control document `pause` or a freeze); released as `preempt_site` (requeued, never charged) if they can do neither or wait past the node's longest pause |
| Network-heavy jobs not started | the coordinator's claim | not granted (`SITE_UPLINK_BUSY` in explain) |

The node whose protected process is in the phase does not wait for the coordinator: its agent hears the phase change
through the protection crate's phase listener and holds its own transfers and network-heavy jobs at once, and also when
it is at no site (a node is then its own one-node site for that purpose). Its own `during` block can of course still
carry `cap_fleet = { staging_mbps = 0 }` and `pause_fleet` as before; those act on that node only.

### The bound

From the phase source changing on node A to node B's transfers stopping: A's watcher sees the write (milliseconds,
[gpu-cotenancy.md](gpu-cotenancy.md)); the listener asks A's agent for a heartbeat at once; the coordinator holds the
site in that heartbeat and revokes the leases; B's agent renews its lease every `poll_s` (2 s) while it transfers, sees
it revoked, and stops before its next chunk. **SITE_HOLD_BOUND_S = 5 s** is the documented bound (two renewal periods
and the requests). The end-to-end test measured 0.13 s on a loaded development Mac. A node with no transfer and no
network-heavy job running is not polling; its next transfer asks for a lease and is refused, so it never starts one.

If B cannot reach the coordinator, it cannot renew: it treats its lease as gone `lease_ttl_s - 5` = 15 s after it sent
the last successful renewal, which is before the coordinator could give the slot away (20 s after it *received* that
renewal), and its transfer stops until it gets a new lease. Unreachable is never looser.

## The budget outside phases

- **Leases.** At a site every bulk transfer of at least 8 MiB (or of unknown size) needs a lease
  (`POST /v1/agent/uplink/lease`): granted while the site does not hold and has fewer live leases than
  `max_transfers`; refused with `SITE_UPLINK_BUDGET` and a retry time otherwise. The agent renews while it transfers
  and gives the lease back with the transfer's size and duration. A budget change revokes every lease, so the new terms
  apply within one renewal. S27 (below) checks the leases never exceed the budget.
- **A revoked lease keeps its slot** (and its rate) until its agent, having stopped, gives it back, or until it expires.
  The answer that granted or renewed it may still be on its way when the coordinator revokes it, and a revocation's
  answer may be lost: freeing the slot at once would let another node start while the first still transfers. The model
  checker found exactly that in the first version of this design (`specs/OarbankSiteUplink.tla`,
  `OarbankSiteUplink_c_slotfreed.cfg`). After a hold ends, the slots come back as the agents give them back, normally
  within one renewal.
- **Pace.** A transfer is paced at the smallest of its lease's rate, the node's `staging_mbps` cap (a setting that
  existed but was not enforced before) and a protection rule's staging cap.
- **Network-heavy jobs.** Claim grants a network-heavy job at a site only while fewer than `max_heavy_jobs` run there
  (counted over the site's live attempts, plus those granted in the same claim). Lowering the budget does not stop
  jobs already running; it only holds new ones.
- No fairness queue: nodes that wait for a lease ask again every couple of seconds and the first to ask wins. With one
  or two transfers at a time per site this has been enough; a queue is a later refinement if starvation shows.

## How work declares network-heavy use

The agent's own transfers need no declaration. A job whose stage makes heavy traffic itself declares it in the
manifest (oarbank-sdk, `stages[].requires.resources.network`):

```toml
[[stages]]
name = "publish"
requires = { resources = { cpu = 1, mem_gb = 1.0, network = "heavy" } }
```

`normal` (the default) changes nothing. The coordinator copies it into the job's resources and the spec envelope; the
agent marks the attempt network-heavy at grant. Cores before 2.10 ignore the key (the job runs as any other), so it is
not core-gated.

**Workloads** (docs/design/workloads.md) are long-running and the most likely network-heavy fleet work. They declare
it the same way (`workloads[].resources.network = "heavy"`, SDK; the release entry carries it only when heavy). The
agent marks such a workload's protection view `site_hold` while `Uplink::jobs_held()` reports a hold (its own uplink
phase or its site's), and the workload ladder treats it as a pause from the dynamic controller: a workload that can
pause (`cooperative_pause` or `freeze_ok`) pauses for at most its `pause_tolerance_s`, then is stopped and held; one
that cannot pause is stopped and held at once (`WORKLOAD_HOLD`, cause `site`, release `preempt_site`); no new start is
admitted while the hold lasts, and the hold ends with it. The coordinator counts the network-heavy workloads members
report running in `sites.heavy_running`, so they use the site's network-heavy budget; being owner-assigned, they are
counted but never refused.

**Inbound listeners** (docs/design/inbound-listeners.md) relay bytes between public clients and the module's service or
workload, and serving clients uses the uplink. The relay itself is **not** paused by a site hold: cutting or stalling
connections mid-protocol breaks the clients of a service that is otherwise light, and the bytes a listener carries are
the serving process's own traffic. A workload whose serving is network-heavy declares `network = "heavy"` and is paused
or held at the source (a held workload's listeners have nothing to relay to, as for any other hold). Module services
have no `network` declaration yet; a heavy serving service is a later step (a service-level declaration and a relay
pace).

## Suggestions

Sites are suggested from what nodes observe, never set automatically:

- **Gateway.** Every 10 minutes the agent reads its default gateway's hardware address from the OS's route and
  neighbour tables (`route -n get default` and `arp -n` on macOS, `/proc/net/route` and `/proc/net/arp` on Linux,
  `route print -4 0.0.0.0` and `arp -a` on Windows; nothing is sent to the gateway) and reports `gateway_fp`, an
  HMAC-SHA256 keyed with a fleet salt (from the coordinator) and truncated. Nodes behind one gateway report the same
  fingerprint; nobody outside the fleet can match it to a hardware address.
- **Public address.** When a node connects from a global address (a coordinator reachable over the internet), the
  coordinator keeps a keyed fingerprint of it (an IPv6 address by its /64). Private, loopback, link-local and CGNAT
  (tailnet) addresses are ignored.

Two or more nodes with the same fingerprint, not all at one site already, are a suggestion: "3 nodes share a default
gateway (gateway 3f9a1c)". The owner accepts it as a new site (`sites.create` with `suggestion`) or adds the nodes to
the site some of them are at (`sites.assign`), or dismisses it. Two routers on one line (double NAT) look like two
gateways: the page says so, and the owner merges them by hand. Neither a gateway address nor an IP address is stored,
logged or shown anywhere.

## The measured-capacity hint

Each released lease reports its bytes and seconds. The site's hint is the 90th percentile of the rates large transfers
(32 MiB or more) reached while no other lease ran at the site and nothing paced them, per direction, over 14 days:
"large transfers here reached 230 Mbit/s up (12 measured)". It measures the path to wherever those transfers went, often
the coordinator on the LAN, so the page presents it as a ceiling to start the budget from, not the line's capacity.

## Console, CLI and API

- **Sites** (`/sites`, in the main navigation): every site with its members, budget, state ("paused because ...") and
  hint; the suggestions with Create site, Add to <site> and Dismiss; the new-site form. A site's page
  (`/sites/<id>`): its state in words, members with their `uplink` phases and their agent's transfers (paused or not,
  and why), Add and Remove, the budget form, the leases in force, recent transfers and holds, Delete.
- **Node page:** a Site card naming the node's site and its state, or "at no site".
- **Explain:** `SITE_UPLINK_BUSY` ("Network-heavy: site home holds such work while mini's rule trainer is in an upload
  phase") and `SITE_UPLINK_BUDGET` ("... already runs 1 of its 1 network-heavy jobs", remedy `sites.update`); the
  predicate is in `predicates.placement`, shared by claim and explain (D16).
- **CLI:** `oarbank sites list|show <site>|create <name> --node N ... [--mbps M] [--transfers N] [--heavy-jobs N]|update
  <site> ...|add <site> <node>...|remove <node>...|delete <site>|suggest|accept <key> [--name N | --site S]|dismiss <key>`.
- **API:** `GET /api/v1/sites`, `GET /api/v1/sites/{site}`; operations `sites.create`, `sites.update`, `sites.assign`,
  `sites.unassign` (T1, previewed: the preview names each node that joins or moves), `sites.delete` (T2), `sites.dismiss`
  (T0); all admin.
- **Agent API:** docs/protocol.md, "Site uplink".

## Reason codes and journal

| Code | Where |
|---|---|
| `SITE_UPLINK_BUSY`, `SITE_UPLINK_BUDGET` | explain and the lease refusal |
| `TRANSFER_PAUSED`, `TRANSFER_RESUMED` | the agent's decision journal (`transfer_paused` with `why` and `paused_at`) |
| `SITE_PAUSE`, `SITE_RESUME` | the actuation record of a network-heavy job frozen or thawed for its site |
| `PREEMPT_SITE` (`preempt_site`) | an attempt released for its site: requeued, never charged to the job or the node |

## Invariant

**S27**: a site's live (unexpired, unrevoked) transfer leases never number more than its `max_transfers`, their rates
never sum past its `uplink_mbps`, and no lease is live while the site holds. Leases past their expiry are dead (their
agent stopped by its own clock earlier) and do not count; revoked ones are on their way out (a lowered budget revokes
every lease) and a grant still leaves room for them until they are given back. `oarbank verify` reports it with the others. The number of running network-heavy
jobs is not an invariant (lowering the budget does not stop running jobs); claim's admission is tested instead.

## Failure modes

| Failure | Behaviour |
|---|---|
| The protected node's phase source cannot be read | counts as on: the site holds (step 1's rule) |
| The protected node stops reporting | its site holds after 60 s, while it has an `uplink` phase configured |
| A transferring node loses the coordinator | its lease is treated as gone 15 s after its last successful renewal was sent: the transfer stops |
| The coordinator restarts | leases are in the database: renewals go on; unrenewed ones expire after 20 s |
| An agent that predates sites | it ignores `uplink` and takes no leases; claim still holds its network-heavy jobs; the site page shows "not reported (update its agent)" |
| A transfer's connection drops while it is held | the next attempt resumes the partial download; uploads resume at the coordinator's offset |
| Two routers on one line | suggested as two sites; the owner merges them |

## What it does not cover

- Releases and agent updates are not held: the agent fetches them on its control path, and holding them would hold its
  heartbeats. Container image pulls are made by the container runtime, outside the agent's byte stream. Both are
  occasional; a later step can move them off the control path and gate them.
- A site does not shape traffic it does not make: the owner's other programs and machines that are not nodes.
- Routers are never touched (no QoS changes); everything is the fleet holding itself back.

## Verification

| Layer | Tests |
|---|---|
| Coordinator | operations and one site per node, the hold (on, unreadable, silent), leases under the budget and revoked on a hold, network-heavy jobs held and budgeted in claim and explain, suggestions from fingerprints (no address stored), the hint, S27 (`tests/test_sites.py`) |
| Property | random sequences of leases, renewals, releases, phases on, off, unreadable and silent, time and budget changes: the leases never exceed the budget, no lease is granted or renewed while a tagged phase is on, unreadable or silent (`tests/test_sites.py`, Hypothesis) |
| Console | the Sites and site pages, the node's Site card, create and budget forms through the registry (`tests/test_console_sites.py`) |
| Protection crate | the phase listener hears every change with its tags (`tests/sources.rs`) |
| Workloads | the workload ladder pauses a network-heavy workload for its tolerance under a site hold, then holds it, holds one that cannot pause at once and releases both when the hold ends (`oarbank-protection` `workloads.rs`); the agent reads the declaration (`workloads.rs`); a running network-heavy workload counts against the site's budget (`tests/test_sites.py`) |
| Agent | a local phase holds a transfer until it ends, small transfers never wait, a lease not renewed for TTL - 5 s is gone, pacing, the gateway parsers per OS, HMAC vectors (`uplink.rs`); a site hold pauses network-heavy attempts and releases what cannot wait (`prot.rs`) |
| End to end | two agents at one site: a synthetic protected process's phase enters `uplink` on one; the other's staging (under a lease, from a slow https origin) pauses within the bound, resumes when the phase ends and finishes with the right digest (`tests/rust/test_agent_sites.py`) |
| TLA+ | `specs/OarbankSiteUplink.tla`: the lease protocol with lost and late messages keeps the budget (`Budget`) and stops every transfer within the bound after a hold (`HoldBound`), 6.5 million states in 37 s; without the agent's margin, without revoking on a hold, or with a revoked lease's slot freed before it is given back, TLC finds a violation (the last was its finding on the first design) |
