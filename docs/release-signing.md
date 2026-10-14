# Signing (on by default)

Everything the coordinator hands a node to run is signed by the owner, and nodes refuse what is not (PLAN D31).
A compromised coordinator or admin account can still queue work, but it cannot make nodes run code the owner did
not sign: the keys live with the owner, not on the coordinator.

## What is signed

| What | Statement names | Signed with | Command |
|---|---|---|---|
| A release (the module composition for one platform) holding module code; an [empty release](#empty-releases) needs none | release id, bundle sha256, a rising seq | the release key | `oarbank release sign <release> [--promote]` |
| An agent build | the binary's sha256, version, platforms, a rising seq | the release key | `oarbank agent sign <build>` |
| A fleet release (`oarbank-fleet-<v>.json`: every package, agent and coordinator build of a version) | the manifest's sha256, version, its seq | an owner key | `oarbank update sign <version>` |
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
release for every platform of the fleet (a macOS and a Windows node: two releases). With signing on, each one that
holds module code stays a **candidate** and no node gets it until the owner signs it, on the machine that holds the
owner key. A platform none of the enabled modules runs on gets an [empty release](#empty-releases) instead, which
needs no signature: it is current at once and its nodes become ready with no module.

```bash
oarbank release list                         # RELEASE, PLATFORM, STATUS, SIGNED, CONTENTS (module@version, or
                                             # "(no module: needs no signature)"), and
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
`RELEASE_UNSIGNED` (its release waits for the owner), `RELEASE_PENDING` (it is installing it). None of this ever
names an empty release.

## Empty releases

A release whose platform (or, for a canary or pinned node, whose node) runs no enabled module is **empty**: its
`modules.json` lists no module and no tool definition, and its `MANIFEST.json` lists `modules.json` alone. The
signature exists so that nodes run only code the owner approved; an empty release carries none, so it needs no
signature, and asking for one would only make the owner sign the same nothing again after every module change.

- **Coordinator.** oarbankd promotes (or assigns) an empty release as soon as it builds it, signing on or off. It is
  never a candidate waiting for the owner: no banner, no `release_awaiting_owner` alert, no `RELEASE_UNSIGNED`, no
  "sign" step in a module's readiness checklist. A module change that keeps a platform empty builds the same empty
  release again (same id), so nothing changes for its nodes.
- **Agent.** A node with a pinned release key installs a release without a statement and signature only if it is
  exactly empty: after unpacking it (at most 64 KiB) and before switching to it, the agent checks that `modules.json`
  lists no module and no tool definition, that `MANIFEST.json` vouches for `modules.json` alone, and that the
  directory holds nothing else; the same check runs when the release is already on disk under that id. Anything else
  unsigned is refused (`unsigned release refused: a release key is pinned and it holds 1 module(s) ...`), as is a
  directive with half a signature, a forged one or one for another release. The node then runs no module and is
  ready: it reports the empty release as the one it runs, and the coordinator counts it as ready with no module.
- **What it does not protect.** A coordinator can send an empty release to a node that ran modules, which stops
  them there. That is no new power: a coordinator can already stop giving a node work. What it can never do is make
  a node run module code, or a tool definition's version command, that the owner did not sign.
- **Upgrading.** An older oarbankd held empty releases for the owner's signature (and put the fleet's tool
  definitions in them). After the upgrade, oarbankd's background loop builds and promotes each platform's empty
  release, retires the waiting empty candidates and resolves their alerts; there is nothing to sign. An agent older
  than this change still refuses an unsigned empty release; it takes it once updated.

## What nodes do

The signature checks are always compiled into the agent; there is no unsigned build.

- **Pinning.** A node pins the release key and the owner key set the first time its coordinator advertises them.
  The coordinator's own identity is pinned before that (its CIK, through the enrollment or a join code), so the
  keys come from the coordinator the node trusts.
- **Refusing.** Once a key is pinned, a node refuses an unsigned release (unless it is
  [empty](#empty-releases)), agent build or coordinator build, one signed by another key, and one whose seq is not
  above the highest it accepted (no rollback to an older signed statement). A coordinator build must also name the
  node's platform.
- **Moves.** A node that pinned the owner keys follows a move only with an owner signature on the statement, after
  its time lock.
- **Rotation.** A new owner set is accepted only when every new key and one key of the current set signed it, and
  its version is the next one.

## Developer mode

`OARBANK_RELEASE_SIGNING=0` in the coordinator's environment turns signing off: no key is advertised, statements
are not required, and a move can install the coordinator's own checkout. Nodes that never pinned a key accept
unsigned work. A node that already pinned keys keeps refusing unsigned work until the owner signs
`oarbank owner disable`, which tells it to unpin them. Use developer mode only for a fleet you are building on.

## Fleet releases

A fleet update ([design/fleet-updates.md](design/fleet-updates.md), D56) installs whole packages on every node and
updates the coordinator itself, so it asks more of the signatures than an agent build: the owner's says this fleet
should run the release, the vendor's that the release exists, and both sign one hash, the manifest's.

1. **CI writes the manifest.** `scripts/fleet-manifest.py <version> dist` lists every asset of the release (node
   packages per OS, architecture and format, the agent binaries, the coordinator builds) with its sha256, size,
   platform, format and role, plus the release's `seq` (major×10000 + minor×100 + patch), `agent_min` and `stops`.
   It is canonical JSON (sorted keys, no whitespace, ASCII, no trailing newline), so nobody re-serializes it: every
   party hashes the same bytes. The `fleet-manifest` job of `ci.yml` attaches `oarbank-fleet-<version>.json` to the
   release's artifacts; publish it with the release's other files.
2. **The vendor lists it** as a TUF target, on the machine that holds the vendor keys:
   `scripts/tuf_vendor.py add KEYS REPO oarbank-fleet-<version>.json dist/oarbank-fleet-<version>.json`, then
   `scripts/tuf_vendor.py timestamp KEYS REPO` and publish the metadata. Agents and update runners built with the
   vendor root accept a manifest only when the vendor's targets name it with exactly its length and sha256. Owners
   mirror the metadata as for agent builds (`oarbank vendor-metadata upload <repo>`).
3. **The owner signs it** after importing the release (`oarbank update fetch <version>` or `oarbank update import
   <dir>`): `oarbank update sign <version>`, with the owner key on that machine (the Updates page shows the command
   while a release waits for it). The statement is `{"type": "oarbank.fleet-release/v1", "version", "seq",
   "manifest_sha256", "signed_at"}`, signed like every other owner statement. A release is **ready** only once it is
   signed; `update_auto = on` needs signed releases too.

Each node's update runner checks the manifest and its signature again, on its own copy of the package, against the
owner keys root pinned on that machine (`<system data>/update/trust.json`, pinned by an administrator's package
install), and refuses a `seq` below the last release it committed unless it is rolling back to the package it kept.
A test fleet without owner keys pins `oarbank-launcher update-trust --unsigned` explicitly, on each node. Where the
build pins one, the package's own signature is checked too: the Developer ID Installer team on macOS
(`pkgutil --check-signature`) and the Authenticode subject on Windows.

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

## macOS code signatures

Separate from the owner's statements above, the macOS packages carry Apple code signatures:
`OARBANK_CODESIGN_IDENTITY` (a Developer ID Application identity) signs every Mach-O file with the hardened runtime
and a secure timestamp, as notarization requires ([install.md](install.md); without it, everything is signed ad hoc).

**The interpreters that run module code have library validation off.** The node runtime's
`/Library/Oarbank/bin/runtime/bin/python3.12` and the coordinator's `python/bin/python3.12` (the coordinator build and
`Oarbank Coordinator.app`) are signed with [`deploy/macos/python.entitlements`](../deploy/macos/python.entitlements),
which holds one entitlement, `com.apple.security.cs.disable-library-validation`. Module environments (`uv venv`) link
to these interpreters, so every module process runs under that signature.

- **Why.** The hardened runtime turns on library validation: a process may map only code signed by Apple or by the
  same team as its executable. Modules install wheels from PyPI (numpy, pysam, ...) whose extension modules and
  bundled libraries are signed ad hoc by the linker or by their own publishers, never by the fleet's team, so without
  the entitlement every one of them fails to import under a Developer ID build: `code signature ... not valid for use
  in process: mapping process and mapped file (non-platform) have different Team IDs`. 2.8.0 shipped that way; only
  the wheels the build itself signed (pydantic_core) loaded.
- **The trade-off.** With library validation off, the interpreter will map any validly signed library, including one
  a module brings. That is the point: module code is the owner's chosen code, already admitted by the release
  signature checks above. What confines it does not depend on library validation: module processes still run in the
  Seatbelt sandbox ([design/module-sandbox.md](design/module-sandbox.md)), which limits what they read, write, execute
  and reach. The rest of the hardened runtime stays on (no DYLD_* environment variables, no unsigned executable
  memory, no debugger attachment), every library must still carry a valid signature, and the entitlement is on the
  interpreters alone: the agent, the launcher, uv and the apps keep library validation. Apple's notary service accepts
  this entitlement.
- **Checks.** `scripts/macos-codesign.sh` is the one place that signs the interpreters; the packaging scripts
  (`scripts/package-macos.sh`, `scripts/build-coordinator.sh`, `scripts/package-coordinator-macos.sh`) then run
  `scripts/check-macos-signing.py`, and a build fails unless each interpreter carries exactly that entitlement (with
  `--developer-id`, also the hardened runtime and a team) and no other executable carries any. Its `--canary` makes a
  fresh environment on the signed interpreter with the build's own uv, installs a pinned native wheel from PyPI that
  the build did not sign, and imports its extension module: under a Developer ID build without the entitlement that
  import fails as it did on 2.8.0 (an ad hoc build never enforces library validation, which is why the static check
  exists too). CI builds the node runtime on every change, signs it ad hoc through the same script and runs both
  checks; `tests/test_node_packages_macos.py` and `tests/test_coordinator_native_macos.py` cover the scripts and, given
  `OARBANK_NODE_PKG`, `OARBANK_NODE_RUNTIME` or `OARBANK_COORDINATOR_PKG`, a built artifact.

## Testing

`tests/test_signing.py` and `tests/test_coordinator_move.py` cover the statements and the owner rules;
`tests/test_release_signing_ux.py` the waiting releases (one build per platform and composition, the banner, alert,
reason codes and `oarbank release list`), the module readiness checklist, and empty releases (never waiting, module
code still waiting, the upgrade clearing old empty candidates); the agent's `signing` and `release` unit tests refuse
an unsigned release with a module, a tool definition or any other file and take an empty one;
`tests/rust/test_agent_release_empty.py` runs it against real processes: with the key pinned, a node no module runs
on installs its empty release unsigned and is ready, then gets a release with module code only once it is signed;
`tests/rust/test_agent_tuf.py` installs a vendor-listed agent build and refuses an unlisted one;
`tests/rust/test_agent_coordinator_install_signed.py` runs a whole signed move against real processes: the owner key
set pinned by the agent, a signed coordinator build installed by it, and an owner-signed move it follows.
