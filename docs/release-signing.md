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
finishes. Keep that backup offline. If you used the wizard, proceed to signing your module releases and agent builds
below; do not create a second key set. For manual/archive setup or keys held on another trusted machine:

1. Make the keys on a machine you trust, not necessarily the coordinator:
   `oarbank release keygen` writes the primary to `keys/release-ed25519.key` (0600) in the config directory
   (`~/.config/oarbank` on Linux, `~/Library/Application Support/Oarbank` on macOS; `OARBANK_RELEASE_KEY` names
   another file; `oarbank release --help` prints it); make the backup the same way with `--key <path>`.
2. Pin the owner key set: `oarbank owner set --key <primary> --backup-key <backup>`. The primary becomes the
   release key the coordinator advertises.
3. Sign each release before it can be promoted (`oarbank release sign <id> --promote`), each agent build before a
   canary, each coordinator build before a move can install it.

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
`tests/rust/test_agent_tuf.py` installs a vendor-listed agent build and refuses an unlisted one;
`tests/rust/test_agent_coordinator_install_signed.py` runs a whole signed move against real processes: the owner key
set pinned by the agent, a signed coordinator build installed by it, and an owner-signed move it follows.
