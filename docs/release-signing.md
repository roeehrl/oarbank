# Signing (on by default)

Everything the coordinator hands a node to run is signed by the owner, and nodes refuse what is not (PLAN D31).
A compromised coordinator or admin account can still queue work, but it cannot make nodes run code the owner did
not sign: the keys live with the owner, not on the coordinator.

## What is signed

| What | Statement names | Signed with | Command |
|---|---|---|---|
| A release (the module composition for one platform) | release id, bundle sha256, a rising seq | the release key | `oarbank release sign <release> [--promote]` |
| An agent build | the binary's sha256, version, platforms, a rising seq | the release key | `oarbank agent sign <build>` |
| A coordinator build (what a move installs) | the archive's sha256, version, platform, a rising seq | an owner key | `oarbank coordinator-build sign <build>` |
| A coordinator move | both coordinators, the next epoch, the time lock | both coordinators and an owner key | `oarbank coordinator sign --owner-key <key>` |
| The owner key set (primary, offline backup, rescue locations) | the keys and a rising version | every new key and one current key | `oarbank owner set --key <primary> --backup-key <backup>` |
| Leaving signing mode | the fleet and the owner set's version | an owner key | `oarbank owner disable` |

The release key is the owner set's primary key. Keep the backup offline (another machine or a hardware key).

## Setting it up

The native coordinator installer's first-run wizard creates and pins the primary and backup keys before it
finishes. Keep that backup offline. If you used the wizard, proceed to signing your module releases (after enabling a
module, [sign each platform's release](#after-enabling-a-module-sign-each-platforms-release)) and agent builds below;
do not create a second key set. For manual/archive setup or keys held on another trusted machine:

1. Make the keys on a machine you trust, not necessarily the coordinator:
   `oarbank release keygen` writes the primary to `keys/release-ed25519.key` (0600) in the config directory
   (`~/.config/oarbank` on Linux, `~/Library/Application Support/Oarbank` on macOS; `OARBANK_RELEASE_KEY` names
   another file; `oarbank release --help` prints it); make the backup the same way with `--key <path>`.
2. Pin the owner key set: `oarbank owner set --key <primary> --backup-key <backup>`. The primary becomes the
   release key the coordinator advertises.
3. Sign each release before it can be promoted (`oarbank release sign <id> --promote`, once per platform after every
   module change: see below), each agent build before a canary, each coordinator build before a move can install it.

## After enabling a module: sign each platform's release

Enabling, upgrading, canarying, pinning or rolling back a module changes what nodes run, so oarbankd builds a new
release for every platform of the fleet (a macOS and a Windows node: two releases, one of them perhaps without the
module, where it does not run). With signing on, each one stays a **candidate** and no node gets anything until the
owner signs it, on the machine that holds the owner key:

```bash
oarbank release list                         # RELEASE, PLATFORM, STATUS, SIGNED, CONTENTS (module@version), and
                                             # the releases waiting for your signature, each with its command
oarbank release sign <release> --promote     # once per waiting platform release
oarbank release sign <release>               # a canary or pinned node's own release (never --promote it)
```

`oarbank release build` builds every platform's release from the enabled modules (it refuses while none is enabled)
and, when the owner key is on that machine, signs and promotes each one. oarbankd builds a platform's release once
per composition: hellos while a candidate waits change nothing.

Until a release is signed it is named everywhere the owner looks: a banner on the Fleet, Modules and Settings pages
with each release's platform, contents and command; the `release_awaiting_owner:<release>` alert (after five
minutes; it clears when the release is signed and current, or a newer build replaces it); each waiting node's card
("release needs your signature"); the node's explain (`RELEASE_UNSIGNED`, with the command); and the module's
readiness checklist. A node with no release at all says why: `NO_RELEASE` (no module enabled yet),
`RELEASE_UNSIGNED` (its release waits for the owner), `RELEASE_PENDING` (it is installing it).

## What nodes do

The signature checks are always compiled into the agent; there is no unsigned build.

- **Pinning.** A node pins the release key and the owner key set the first time its coordinator advertises them.
  The coordinator's own identity is pinned before that (its CIK, through the enrollment or a join code), so the
  keys come from the coordinator the node trusts.
- **Refusing.** Once a key is pinned, a node refuses an unsigned release, agent build or coordinator build, one
  signed by another key, and one whose seq is not above the highest it accepted (no rollback to an older signed
  statement). A coordinator build must also name the node's platform.
- **Moves.** A node that pinned the owner keys follows a move only with an owner signature on the statement, after
  its time lock.
- **Rotation.** A new owner set is accepted only when every new key and one key of the current set signed it, and
  its version is the next one.

## Developer mode

`OARBANK_RELEASE_SIGNING=0` in the coordinator's environment turns signing off: no key is advertised, statements
are not required, and a move can install the coordinator's own checkout. Nodes that never pinned a key accept
unsigned work. A node that already pinned keys keeps refusing unsigned work until the owner signs
`oarbank owner disable`, which tells it to unpin them. Use developer mode only for a fleet you are building on.

## Vendor update trust (TUF)

Agent builds carry a second, vendor-level check (PLAN D31). A release agent is built with the Oarbank vendor's TUF
root compiled in (`OARBANK_TUF_ROOT=<repo>/root.json`). Before it installs an agent build it fetches the vendor's
metadata through its coordinator, which only mirrors it, and accepts the build only if the vendor's targets list it
with exactly its length and sha256: root rotations signed by the old and new roots, then timestamp, snapshot and
targets, each version, hash and expiry checked, with versions remembered against rollback.

- The vendor's keys stay off the coordinator and out of CI: `scripts/tuf_vendor.py init|add|timestamp|rotate-root`
  on the machine that holds them (keep the root key offline).
- The owner mirrors what the vendor publishes: `oarbank vendor-metadata upload <repo>` (or the Agents page).
- Developer builds without a compiled-in root skip the check; the owner's signature (above) still applies.

## Testing

`tests/test_signing.py` and `tests/test_coordinator_move.py` cover the statements and the owner rules;
`tests/test_release_signing_ux.py` the waiting releases (one build per platform and composition, the banner, alert,
reason codes and `oarbank release list`) and the module readiness checklist;
`tests/rust/test_agent_tuf.py` installs a vendor-listed agent build and refuses an unlisted one;
`tests/rust/test_agent_coordinator_install_signed.py` runs a whole signed move against real processes: the owner key
set pinned by the agent, a signed coordinator build installed by it, and an owner-signed move it follows.
