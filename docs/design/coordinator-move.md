# Moving the coordinator to another machine (design, built)

> **Status: built.** Decisions:
> - a 24 h time lock by default, with a per-move override down to 15 min given a reason;
> - the Tailscale tag deferred, so agents check the StableID only;
> - signing mode with an owner key set;
> - agents authenticate with mTLS client certificates (D29), which a move carries with the fleet's CA.
>
> Protocol: docs/protocol.md, "Coordinator identity and moves". The runbook is at the end.

## The goal

One operation moves oarbankd from machine A to machine B. That includes its database, blob stores, settings, keys and audit
chain. Every agent follows on its own, with no ssh and no hand edits, and nothing is lost or run twice. Nobody can
use the feature to send the fleet to a machine of their choosing.

## Why this is a trust problem, not a copy problem

An agent that trusted a **URL** (`coordinator` in its `agent.json`) would authenticate to whatever answers there, and
nothing at the application layer would bind "the coordinator" to a key. A VPN secures the transport, but any host the
agent is pointed at would receive its credential. A naive "oarbankd writes a new
URL into every agent" feature would hand the fleet to anyone who can reach that code path.

No mainstream system ships a signed "relocate to URL X" message. They either keep a stable name (Kubernetes, Fleet,
Jamf), or push new addresses over a channel the agents already trust (Nomad, Elastic, Teleport, BOINC). The design
combines four proven ideas:
- Salt's offline-signed master keys;
- TUF's root rotation: the old key signs the new one, the new key signs itself, and the version goes up by exactly one;
- OpenSSH's proof-of-possession for new host keys;
- Apple's OS 26 MDM migration, where an authority outside both servers names the new one, behind a visible deadline.

## Three rules

1. **Agents trust a key, not a URL.** oarbankd gets a **coordinator identity key (CIK)**, Ed25519. Each agent pins it at
   enrollment. Every session starts with a fresh-nonce challenge the coordinator must sign, and no credential is sent
   before that proof. A rogue host at the right address gets nothing.
2. **A new address arrives only in a signed move statement**, delivered in hello and heartbeat replies. No HTTP
   redirect, DNS change or unauthenticated hint can move an agent. Agents turn off redirect following, and any 3xx
   from the coordinator is an error.
3. **A coordinator epoch that only goes up, enforced by the agents.** Every change of coordinator raises it,
   rollbacks included. Agents reject any coordinator at a lower epoch than the highest they've seen. That alone makes
   a stale, restored or rebooted old machine harmless.

## The move statement

Canonical JSON, Ed25519-signed. Its fields:
- `type: oarbank.coordinator-move/v1`, `fleet_id`;
- `epoch`: exactly the current epoch + 1;
- `from: {url, cik}`;
- `to: {url, cik, ts_stable_node_id, required_tag?}`;
- `not_before` (the time lock), `expires`;
- `canary` nodes, `move_id`, and the hash of the previous statement.

| Signature | Proves | Stops |
|---|---|---|
| `from.cik` (A) | The current coordinator agreed | Injection by anything that isn't oarbankd (a module, a man in the middle) |
| `to.cik` (B) | The target exists, holds its key and consents | Naming a server the signer doesn't control |
| `owner` (signing mode only) | The owner, holding an offline key, authorized it | A stolen console login or a compromised oarbankd |

**What an agent does with it:**
1. **Check.** Every required signature against *pinned* keys; the epoch is current + 1; the `from` key is the current
   key; the statement hasn't expired; `to.cik` isn't on the retired list.
2. **Record it as pending, fsync it, and report it** (console banner, ntfy).
3. **Probe B after `not_before`, before sending any credential:**
   1. B's address is a tailnet address;
   2. Tailscale `whois` returns `Node.StableID` equal to the statement's;
   3. if `required_tag` is set, `Node.Tags` contains it (checked on Tailscale 1.102.2: `StableID` and `Key` are always
      present, `Tags` only when the node is tagged);
   4. the CIK nonce challenge passes.
4. **Authenticate and commit.** A hello to B with the node's client certificate succeeds (B holds the fleet's data and
   CA), then the agent commits: new URL and key, raised
   `max_seen_epoch`, old key retired. A's URL stays as a fallback for *network* failures, never for *identity*
   failures.
5. **On failure,** stay on A, report `move_failed`, and don't loop.
6. **An agent that was offline across several moves** walks the statement chain one epoch at a time.

## Moving the data

**A runs a five-state fence:**

| State | What A does |
|---|---|
| `ACTIVE(e)` | Normal operation |
| `DRAINING(e)` | No new leases; renewals and results still accepted |
| `FROZEN(e)` | Mutations get 503 with Retry-After; the final snapshot is taken |
| `HANDING_OFF` | B runs its health gate |
| `HANDED_OFF` | Redirect only: every agent call gets the move statement, and no writes are accepted |

`HANDED_OFF` is written to A's database *and* a marker file before B goes live, so a rebooted A comes back redirect-only.

**B starts as `STANDBY`.** It answers identity and health checks and grants nothing until promotion writes epoch e+1 as
its first transaction.

**No ssh at any step:**
- **If B is already an enrolled node,** A sends a signed standby bundle through B's own agent, which installs oarbankd under B's service manager.
- **Otherwise,** the owner runs the installer on B once, with a single-use pairing code from A's prepare step. A checks
  B's StableID against the plan, and the two exchange keys over a mutually signed session.

**Database:** a backup-API seed while A is live, then at the freeze `wal_checkpoint(TRUNCATE)` and a final
`VACUUM INTO`. These are the methods SQLite documents as safe; a file copy can corrupt the snapshot. On B: `integrity_check`, `foreign_key_check`, per-table row
counts, `user_version`, the audit head, and the SHA-256 as sent and as received. The staging copy is never opened
read-write before promotion.

**Blobs** are content-addressed, so they are copied early over A's blob endpoints. Each is resumable and checked against
its hash. Only the delta moves during the freeze. Promotion is blocked until every blob the final snapshot references
is present and verified.

**Running work keeps running ("drain dispatch, carry execution"):**
- At DRAINING, live leases are extended past the expected window.
- B honours epoch-e leases and re-stamps them on first renewal. Its lease reaper stays off for one TTL plus a margin.
- Outbox replays are idempotent: each result is keyed on attempt ID plus a submission ID.
- The invariant: **A accepts no mutation after the snapshot point.**

**Keys rotate, they are never exported.** The macOS Keychain can't copy local items, and non-extractable keys can never
leave the machine. B generates its own CIK, and A's last act is a signed audit record:

```
{type: coordinator_move, from, to, epoch: e+1, new_cik, snapshot_sha256, last_seq, last_hash}
```

B's chain continues from that record. The verifier accepts a signer change only at a `coordinator_move` record
signed by the previous key. Symmetric secrets (ntfy credentials) travel inside the mutually signed session. Module
secrets travel sealed: at pairing B sends an X25519 transport key, A seals every value to it in each snapshot it sends
(its own database stays as it is), and B opens them with its key the first time it starts active and re-encrypts them
under its own secrets key ([secrets-and-signed-images.md](secrets-and-signed-images.md)). The move preview lists them
by name and scope.

**The service on B** is the system service every coordinator is ([coordinator-system-service.md](coordinator-system-service.md)):
launchd daemons run by `_oarbankd` on macOS, systemd system units run by `oarbankd` on Linux, two services under virtual
accounts on Windows, installed by the build's own installer as root (`install-oarbankd.sh --build <bundle>
--agent-bind <address> --pair <code> --from <url> --from-ca <pin>`, `install-oarbankd.ps1 -Pair` on Windows). A node's
agent is unprivileged everywhere, so its `install_coordinator` downloads and verifies the signed build and then refuses
with that command, naming the verified bundle; an agent run as root runs it itself. Preflight warns that with FileVault
on, B serves nothing after a power loss until someone unlocks its disk. B restarts on its installed copy through
launchd, systemd or the services' recovery actions ([windows-coordinator.md](windows-coordinator.md)).
B loads the databases through SQLite's backup API, so no open file is replaced on any OS.

## Rollback

There is one recorded commit point: **the first write B accepts at epoch e+1.**
- **Before it,** any failure (snapshot, transfer, integrity, blob check, B's 120 s health gate) thaws A automatically.
  A records why and loses nothing; B's staging copy is wiped.
- **After it,** going back means a *reverse move* from B to A at epoch e+2, carrying B's data. Agents never accept a
  lower epoch, so even "undo" is a forward step.
- **A stays in redirect mode for a 72-hour probation,** so agents that were offline catch up. "Finalize the old
  machine" is a separate, later operation, and it archives A's data rather than deleting it.

## What signing changes

| Attacker | Signing on (owner key required) | Signing off (the default) |
|---|---|---|
| Stolen console or admin login | Can't move the fleet | Slowed and made visible: T3 confirmation, time lock with cancel, ntfy, one pending move at a time, and B must carry a Tailscale tag that only your Tailscale admin login can apply |
| Compromised old coordinator | Can't move the fleet; you can sign a **rescue move**, fetched from preset rescue locations | Can move the fleet, but it can already push unsigned agent updates, which is code execution on every agent. A move gives it nothing new; the docs say so plainly |
| Rogue tailnet host, spoofing, forged or replayed statement, downgrade | Blocked | Blocked |
| A malicious module on a node | Its processes run in the module sandbox, which cannot reach the agent's home | Same |

**In signing mode, the release key becomes the primary of an owner key set:** a primary plus an offline backup kept on
another device. A lost primary is recovered with the backup, with no node touched. The same mechanism also ends today's
"edit every agent by hand" release-key rotation. Turning signing off requires an owner signature.

## The user experience

**One T3 operation, `coordinator.move`:** `oarbank coordinator move --to <mac> [--dry-run]`, or the console's Move page.

**The plan screen shows every preflight result:**
- the target's StableID, tag and new key fingerprint;
- signing mode, with "unsigned move" in red when signing is off;
- which agents support moves;
- in-flight work that will carry over;
- the measured transfer speed and estimated frozen window;
- the FileVault and login warning;
- the time-lock deadline, with a Cancel button.

**Progress runs as named phases:** preflight → pair → seed blobs → seed DB → freeze → final delta → verify → promote →
agents switching (k of N) → committed → probation.
- A banner stays up for as long as a move is pending.
- ntfy fires on request, accept, commit, fail and cancel.
- Every pre-commit failure rolls back by itself and says which check failed.
- The verification report (hashes, row counts on A and B, audit continuity, which agents followed and which straggle)
  is itself an audit record.

**A stable name is optional insurance, not the safety mechanism.** A Tailscale Service, generally available since
February 2026, gives a name and virtual IP that stay the same when the host changes. The move protocol is identical
with or without one.

## As built

- **The commit decision is the old coordinator's.** A freezes and takes the final snapshot; B verifies it.
  A then tells B to install, and B asks back whether to go active. A answers yes only after writing its
  HANDED_OFF marker. Until that answer, every failure thaws A at the same epoch with nothing lost, and B
  discards its copy. So two coordinators are never active, even if B dies or the network splits mid-move.
- **The identity key is a 0600 file** in the coordinator's home, not a Keychain item. It is never exported:
  a move gives the target its own key.
- **The audit chain moves with a key handover.** The audit digests are signed with a key in the secret store that
  cannot move. The last digest on A therefore names B's audit key, and the verifier accepts a signer change only at
  such a digest.
- **Not built:**
  - the `canary` list in the statement (every agent follows; the field is reserved);
  - the required Tailscale tag (deferred by decision).
- **Tested end to end** with the real agent (`tests/rust/`): a move to a standby, the enrolled target's agent
  installing the standby (developer mode, and a signed coordinator build with an owner-signed move), and agents
  following.
- **Tested by units:** the reverse move (`--archive-home`), and rescue moves on both sides (`tests/test_rescue.py`
  and the agent's `rescue.rs` tests).

## Runbook

**Before the first move**
- On the Coordinator page, confirm each node's pinned key against oarbankd's (`oarbank node confirm-identity
  <node>`).
- Optional, recommended: signing mode with an owner key set. Run `oarbank owner set --key <primary>
  --backup-key <backup> [--rescue URL]`, then keep the backup offline.

**Moving**
1. `oarbank coordinator prepare --to <enrolled node>`. Its agent installs the standby coordinator. For a host
   that is not enrolled, use `--to http://<host>:7443` and run the printed `oarbankd --standby --pair <code>
   --from <url>` there once.
2. Wait until `oarbank coordinator status` shows the plan `paired`.
3. `oarbank coordinator move [--timelock 24h | 15m --reason "…"]`, adding `--owner-key <key>` in signing
   mode. Agents report it pending; a banner and an ntfy message announce it. `oarbank coordinator cancel`
   withdraws it before the cutover.
4. At the time lock:
   - **dispatch pauses** and running work continues;
   - **A freezes for about a minute**, B verifies and takes over at the next epoch, and A answers agents with
     the signed statement;
   - **agents follow by themselves**, shown per node on the Coordinator page.
5. Nothing to move by hand. Everything a module keeps through oarbank-sdk moves with the coordinator: store, files,
   datasets, settings. Modules take part through the SDK (spec/module-protocol.md, "Coordinator moves"):
   - their **rules** say what is rebuilt or dropped instead of transferred (shown in the move preview);
   - **`move.preflight`** can block the cutover while a module finishes something. The move waits up to 10 minutes,
     then aborts unless it was requested with `--force`;
   - **`integrity.check`** runs on the frozen old coordinator and on the target's copy, and the fingerprints must match;
   - **`move.postflight`** runs once on the new coordinator (resume, rebuild); **`move.cancelled`** runs on the old
     one after a cancel or an abort.
   Module coordinator venvs are not carried: the new coordinator rebuilds them at its first start.
   State a job keeps outside the SDK, or a job that calls the admin API on A directly, is not part of the fleet
   and does not move. When a module needs something the SDK lacks, file an issue on the oarbank-sdk repository.
6. After the 72 h probation, on A: `oarbank coordinator finalize`. The data stays there for you to archive.

**If something goes wrong**
- **Before the commit decision:** nothing to do. A thawed and kept serving; the console says why.
- **After it, B unhealthy:** restart B. If it cannot be fixed, move back with `coordinator prepare` on B
  targeting A; A starts as a standby with `--archive-home`.
- **A compromised or lost, signing mode:** a rescue move to a fresh coordinator, from a copy of A's home (a backup
  or its disk):
  1. on the new machine, `python -m oarbank.coordinator.rescue adopt <copy of A's home> --url https://<it>:7443`
     (with `OARBANKD_HOME` naming a new home). It takes the fleet's data, makes its own identity key, audit key and
     TLS CA, keeps A's CA only to verify the client certificates the nodes hold (they renew under the new CA at their
     first hello), stays standby and writes `rescue-request.json`;
  2. where the owner key is, `oarbank owner rescue-move --request rescue-request.json --out move.json`;
  3. on the new machine, `python -m oarbank.coordinator.rescue sign move.json`: it checks the move against the
     adopted fleet, adds its signature, records the move and becomes active at the next epoch;
  4. start oarbankd and publish `move.json` at a rescue location of the owner key set. Agents read the locations
     once their coordinator has been unreachable for 30 minutes (and every 6 hours in any case), verify the move like
     any other and follow it. The audit chain continues under the key the move names.
- **A compromised, no signing:** the agents must be presumed compromised too, because the coordinator could
  push agent updates. Reinstall them.
