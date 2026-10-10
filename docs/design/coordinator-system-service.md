# The coordinator as a system service on macOS and Linux

**Status (2026-10-10):** built for 2.9.0. Decision **D44** in [PLAN.md](PLAN.md). The macOS and Linux coordinator moves
from per-user services (LaunchAgents, systemd user units) to system services run by a dedicated unprivileged account,
as Windows already does ([windows-coordinator.md](windows-coordinator.md), decisions 8, 9 and 16). No protocol,
manifest or schema change. A per-user coordinator is migrated once, on upgrade (below); nothing else keeps the
per-user form.

## The problem

A LaunchAgent runs only inside its person's login session, and a systemd user unit only while that person's user manager
runs (a login, or lingering). With FileVault on, a Mac does not log anyone in after a restart, so after an update or a
restart the fleet had no coordinator until its owner logged in, and none while they were logged out or someone else
was. Agents kept their work and waited, but no new work was dispatched, nothing was recorded and the console was gone.
The secret store made it worse on macOS: the login Keychain is locked until that same login, so even a coordinator
started some other way could not have read its keys.

What a system service fixes, and what it cannot: it runs whenever the machine's disk is unlocked, with nobody logged
in: after a logout, while another person uses the Mac, and after a restart that unlocks the disk by itself (macOS
updates that do, `sudo fdesetup authrestart`; on Linux any boot without disk encryption, or with unattended unlock).
A Mac with FileVault that lost power still stops at the disk unlock screen: the data volume, where
`/Library/LaunchDaemons` and the coordinator's home live, stays locked until someone types a password at the Mac, and
no program on it runs before. The release notes and the move preflight say so.

## Decisions

1. **Two system services under one dedicated account.** oarbankd and the console stay two services with the same names
   (`dev.codonic.oarbank.oarbankd`, `dev.codonic.oarbank.console`), now launchd daemons in `/Library/LaunchDaemons`
   (`UserName`/`GroupName` `_oarbankd`) and systemd system units in `/etc/systemd/system` (`User=oarbankd`). They start
   at boot, before anyone logs in, and restart as before: oarbankd after a failed exit (75: a standby restarts on its
   installed copy; 0: a finalized coordinator stays down), the console always.

   | | macOS | Linux |
   |---|---|---|
   | Service account | `_oarbankd`: hidden, shell `/usr/bin/false`, a free id below 500, primary group `_oarbankd` | `oarbankd`: `useradd --system`, shell `/usr/sbin/nologin`, its own group |
   | Owners' group | `_oarbankadmin` ("Oarbank coordinator owners") | `oarbank-admin` |
   | Home | `/Library/Application Support/Oarbank/coordinator`, `_oarbankd` 0700 | `/var/lib/oarbank/coordinator` (`StateDirectory`), `oarbankd` 0700 |
   | Admin socket | `/Library/Application Support/Oarbank/coordinator-run/admin.sock`, directory `_oarbankd:_oarbankadmin` 0750 | `/run/oarbank-coordinator/admin.sock` (`RuntimeDirectory`), directory `oarbankd:oarbank-admin` 0750 |
   | Service definitions | `/Library/LaunchDaemons/dev.codonic.oarbank.{oarbankd,console}.plist`, root 0644 | `/etc/systemd/system/dev.codonic.oarbank.{oarbankd,console}.service` |
   | Service record | `/Library/Application Support/Oarbank/coordinator-service.json` (root 0644) | `/etc/oarbank/coordinator-service.json` |
   | Programs | the package's app (`/Applications/Oarbank Coordinator.app/…/coordinator`) or an archive under `/Library/Oarbank/Coordinator/<v>-<sha12>` with `current` | `/opt/oarbank/coordinator` (package) or `/opt/oarbank/coordinator-builds/<v>-<sha12>` with `current` |

   The node's account (`_oarbank`, `oarbank`) is a different account on purpose: on a machine that is both, a
   compromised agent must not reach the coordinator's database and keys.

   **The console runs as `_oarbankd` too.** It reads the database (WAL mode writes the `-shm` file even for a reader),
   `console.secret` and module files in the home; a second account would need a group-readable database and secret,
   which is weaker than one owner-only home. Windows separates the two virtual accounts but gives both full control of
   the home, so the split buys nothing there either.

2. **The home is the system path on every OS** (`paths.coordinator_home()`): the CLI of any owner finds the same
   coordinator, as on Windows. `OARBANKD_HOME` still overrides it (tests, development). `<home>/logs` keeps the two
   logs. Owner-only stays modes 0600/0700, now owned by the service account; `tighten_home` repairs it at every start.

3. **Programs are root's.** A service must not be able to rewrite its own code, and nobody but root may change what
   `_oarbankd` runs: the installer refuses an `--installed` directory that is not owned by root or that a group or other
   can write, and archives unpack into root-owned directories.

4. **The local admin channel moves out of the home and admits the owners' group.** The socket used to sit in
   `<home>/run`, whose owner-only directory was the credential; with a home that only `_oarbankd` may enter, the owner's
   CLI could not reach it. The system form puts it in its own directory, `_oarbankd`-owned, mode 0750, group
   `_oarbankadmin` / `oarbank-admin` (`OARBANKD_ADMIN_SOCKET` and `OARBANKD_ADMIN_GROUP` in the service definition; the
   CLI derives the same path from the system home). uvicorn makes the socket itself 0666, so the directory is the whole
   credential, as before: a member of the group is an owner, anyone else cannot even see the socket. The installer adds
   the person who installs (`--owner`, else `SUDO_USER`, else the console user) to the group.
   - **Why a dedicated group, not `admin`/`sudo`:** an administrator can already read everything with sudo, but sudo
     asks for a password and is logged; the socket asks for nothing. Every administrator of a shared Mac holding the
     fleet without a prompt is a broader grant than "the people who own this coordinator", and Linux has no single
     administrators' group. Membership is explicit and reviewable (`dscl . -read /Groups/_oarbankadmin`,
     `getent group oarbank-admin`).
   - **When membership takes effect:** macOS resolves group membership dynamically for login processes (the
     credential carries the person's id for the directory service), so a new member reaches the socket without logging
     out; Linux reads groups at login, so the installer says to log in again (or run `newgrp oarbank-admin`). The CLI
     and the wizard explain this when the socket exists but cannot be opened.
   - The admin token (`<home>/admin.token`) stays readable only by `_oarbankd`; `sudo oarbank …` reads it as before.

5. **The secret store is the owner-only file store on macOS too** (`<home>/keys/<name>.key`, 0600 in a 0700 directory),
   as on Linux; it already holds the coordinator's identity key (`coordinator_key`) the same way. Considered:
   - *The login Keychain:* locked until the person logs in, the cause of the problem.
   - *The System keychain* (`/Library/Keychains/System.keychain`): writing needs root, and an item's access control
     list is per application, not per account, so `_oarbankd` could neither create nor reliably read items. Running
     oarbankd as root to use it would give module tooling and every parser root.
   - *A keychain of `_oarbankd`'s own:* it needs an unlock password at boot, which would have to be stored in a file
     next to it: a file store with extra steps.
   - *The file store:* the home is 0700 `_oarbankd`, the files 0600; FileVault encrypts them at rest; root can read
     them, as root can read any keychain item's secret by running code in the right context. Chosen.
   The Keychain backend stays only as an explicit `OARBANK_SECRET_STORE=keychain`, for a per-user coordinator whose
   migration waits for its owner (below), and its reader serves the migration's key export. The default is `file` on
   macOS and Linux and DPAPI on Windows.

6. **Owner signing keys stay with the person.** The service never signs anything as the owner: it verifies statements
   with the owner public keys pinned in its database. The keys stay where the person's CLI keeps them
   (`~/Library/Application Support/Oarbank/keys`, `~/.config/oarbank/keys`, `OARBANK_RELEASE_KEY`); the wizard
   creates them there as the person. Putting them in the service's home would let a compromised coordinator sign its
   own move statements and builds, which is exactly what the owner key set exists to prevent.

7. **Setup: the package prepares, the wizard starts the services with one administrator prompt.** The service's agent
   address is the person's choice in the wizard, so the package cannot start oarbankd at install time. The macOS pkg
   postinstall (root) creates the accounts, the group (adding the person at the console), the home and the socket
   directory, and runs the migration or the upgrade below; the deb/rpm postinstall does the same. The wizard keeps
   running as the person (it opens a browser, and the owner keys are theirs). Its **start** step runs the build's
   installer as root, the one privileged step: through AppleScript's `do shell script … with administrator privileges`
   on macOS (the system's own administrator prompt, each argument passed with `quoted form of`), `pkexec` on Linux,
   directly when already root. Everything after it (the admin account, the owner key set, the authenticator check)
   goes through the admin channel, which the person reaches as a member of the group. The wizard's own journal
   (`setup.pending.json`, `setup.lock`, `setup.active.json`, `setup.complete.json`) moves to the person's data
   directory (`~/Library/Application Support/Oarbank/setup`, `~/.local/share/oarbank/setup`), since the person cannot
   write the service's home; Windows keeps it in the home (its wizard is elevated). The sign-in ceremony that proves the
   authenticator works runs over the admin channel: the channel is the owner's credential, so admitting it to the
   sign-in endpoints grants nothing new.

8. **Upgrades refresh the services without the wizard.** The installer records how it set the services up (agent
   address, port, URL, programs, signing) in the service record; on upgrade the package postinstall runs
   `install-oarbankd.sh --refresh`, which writes the definitions again from that record and restarts both services.
   Reopening the wizard reinstalls only when the services do not answer.

9. **The app shows the system service.** Oarbank Coordinator reads the two LaunchDaemon property lists: "Runs as a
   system service — starts with the Mac, before anyone logs in, as _oarbankd, and keeps running when this app quits."
   Allow in the Background still names Oarbank Coordinator (`AssociatedBundleIdentifiers`
   `dev.codonic.oarbank.coordinator` on both daemons; `SMAppService.statusForLegacyPlist` reports a daemon switched off
   there as `.requiresApproval`). "Hide from Menu Bar" stays true as written: the services do not depend on the app.
   When this account still has the per-user LaunchAgents, the window and the menu show **Move the coordinator to a
   system service…** (decision 12).

10. **Local Network privacy no longer applies.** TN3179: macOS automatically allows "any daemon started by launchd"
    (and any program running as root), and "the exception for launchd daemons doesn't apply to launchd agents". The
    per-user coordinator could be asked about, or refused, Bonjour and LAN connections; the daemon is exempt, so
    discovery works with nobody at the Mac.

11. **Moves install the system form.** A move's standby is installed by the build's own installer, so it is a system
    service like any other coordinator: `install-oarbankd.sh --build <bundle> --agent-bind <address> --pair <code>
    --from <url> --from-ca <pin> [--archive-home]`, as root. The agent's `install_coordinator` runs exactly that when the
    agent runs as root, and otherwise refuses with that command. A node's agent never runs as root (`_oarbank`,
    `oarbank`, or a person's account), so on macOS and Linux, as on Windows (windows-coordinator.md, decision 15), the
    owner runs that one command on the target; `coordinator.prepare` with the target's URL pairs it. The node's root
    helper is not given an "install this bundle as a service" operation: the agent controls its own trust files, so such
    an operation would let a compromised agent run code of its choosing as a service account.

12. **The coordinator says what form it runs in.** `hostinfo` asks launchd for `system/<label>` first, then
    `gui/<uid>/<label>`, and systemd for the system unit first, then the user unit; each service reports its `domain`
    (`system` or `user`) and its account (launchd's `username`, systemd's `User`). The document gains `form`:
    `system`, `per-user` or `none`. `oarbank coordinator status` prints `form  system service — runs from boot, as
    _oarbankd`; the Coordinator page shows the same, and a per-user coordinator gets a warning there and in the
    fleet-wide banner ("runs only while <user> is logged in; move it to a system service"), with the pending migration
    if one is recorded.

## Migration from the per-user form

The 2.9.0 package migrates a per-user coordinator when it upgrades one, and the app finishes the job when the
package cannot. The code is `oarbank/sysmigrate.py` (`oarbank coordinator migrate`), with every system path
parametrized so the tests run it on copies.

**Detection.** macOS: every local account (`dscl . -list /Users NFSHomeDirectory`, uid ≥ 500) whose
`~/Library/LaunchAgents/dev.codonic.oarbank.oarbankd.plist` exists. Linux: every account whose systemd user
directories (`~/.config/systemd/user`, the package registry's `unit_dir`) hold `dev.codonic.oarbank.oarbankd.service`.
From the definition: the old home (`OARBANKD_HOME`, else the old per-user default), the agent address and the other
oarbankd arguments, and the program (which build ran it). More than one per-user coordinator on one machine is refused
with their names (`--user` picks one).

**The key export (macOS only), as the person.** Linux kept its keys in `<home>/keys` already. On macOS the audit key
(`oarbank-audit-key`), the module secrets key (`module-secrets`) and, during a move, the transport key
(`move-transport`) are generic passwords in the person's login Keychain, readable only in their session.
`oarbank coordinator migrate --export-keys` reads each one present (`security find-generic-password -w`; the items
were created by `security`, so no access prompt) and writes it into the old home's file store
(`<home>/keys/<name>.key`, 0600), the format the system service reads. It is idempotent; a file that already exists
with different bytes stops it (a coordinator that made a new key). The Keychain items stay where they are. The
exported keys are checked against the database: the audit key's public key must equal `audit_pubkey`, and every module
secret must decrypt with the module secrets key; otherwise nothing moves.

**Who runs what.**
- *The package (root), on upgrade.* It finds the per-user coordinator. On Linux it migrates at once. On macOS, if the
  coordinator's owner is the person at the console, it runs the export in their session (`launchctl asuser <uid> sudo
  -u <user> … --export-keys`) and then migrates. If it cannot (nobody logged in, a locked Keychain, an install over
  ssh or MDM), it leaves the per-user coordinator running and pins its secret store: it adds
  `OARBANK_SECRET_STORE=keychain` to the two LaunchAgents and reloads them, so the coordinator, now on 2.9.0's code,
  keeps its Keychain keys instead of making new ones in the file store. It records the migration as waiting for the
  person.
- *The person, once, if needed.* Oarbank Coordinator shows **Move the coordinator to a system service…** (and the
  console and `oarbank coordinator status` say it is pending). The app runs the export as the person, then the
  migration as root through the administrator prompt. In a terminal: `oarbank coordinator migrate` does the same
  (`sudo` for the second half).

**The root steps**, journaled in `<system data>/coordinator-migration.json` (root-owned, readable by all, no secrets)
with a line per step:
1. *Preflight.* The old home holds a coordinator and no unfinished wizard; the new home holds none (a partial copy
   from an interrupted run of the same migration is set aside); the keys are in the old home's file store and match
   the database (above).
2. *Stop* the per-user services (`launchctl bootout gui/<uid>/…`; `systemctl --user --machine=<user>@ stop`) and wait
   for oarbankd to exit, so the database and its WAL are at rest.
3. *Copy* the old home to the new one as a clone (`cp -c`, APFS clones: instant and no extra space; `cp -a
   --reflink=auto` on Linux), leaving out what is per-process (`run/`, `console.secret`, the wizard's lock and live
   link) and module environments (`.venv`, whose scripts name the old path; oarbankd rebuilds them at start,
   `modlife.runtimes_ok`). The wizard's completion record moves to the person's setup directory. The service account,
   the owners' group (with the person) and the directories are created (`install-oarbankd.sh --prepare`), then
   ownership becomes `_oarbankd`, the home 0700.
4. *Install* the system services with the build and the agent address the per-user ones used (`install-oarbankd.sh
   --installed <build> --agent-bind <address> --owner <user>`), which also adds the person to the owners' group.
5. *Verify* within two minutes: both services run under the service account, the admin channel answers, and it serves
   the same fleet id as the old database; the console answers its health check.
6. *Finish.* The old LaunchAgents or user units are disabled and removed (copies kept beside the old home), the old
   home is renamed `<home>.migrated-<time>` with a `FINALIZED` marker (so a stray old oarbankd refuses to start on it),
   and the journal says `done`. The old home and the Keychain items are the person's to delete once they are content.

**Rollback.** A failure at any step after the stop removes the new services, sets the new home aside
(`coordinator.failed-<time>`, for diagnosis) and starts the per-user services again on the untouched old home; the
journal says `rolled-back` with the error. Nothing of the old home is changed before step 6, so a rollback cannot lose
data. Running the migration again after a rollback starts over; after `done` it is a no-op.

**What the owner of tnt-studio experiences** (one per-user coordinator, logged in, double-clicking the 2.9.0 pkg):
Installer asks for an administrator password as for any pkg; the postinstall exports the three keys in the person's
session, stops the LaunchAgents, clones the 211 MB home in a moment, starts the two daemons, verifies them and removes
the LaunchAgents. Agents reconnect within their retry interval (the same address, port and TLS identity); jobs keep
running on the nodes and report when it is back, as after any coordinator restart. The app then says "Runs as a system
service", the console's Coordinator page shows `system service — runs from boot, as _oarbankd`, and
`/Library/Application Support/Oarbank/coordinator-migration.json` records each step. The old home stays as
`~/Library/Application Support/Oarbank/coordinator.migrated-<time>`. If the export could not run, the coordinator keeps
running per-user and the app offers the one-click move.

## Threat model (what changes)

| Threat | Defence |
|---|---|
| Another local account reads the database, keys or admin token | The home is `_oarbankd` 0700, secrets 0600; only root and the service account can read them. |
| A person who is not an owner uses the admin channel | The socket's directory admits `_oarbankd` and the owners' group only; membership is explicit. |
| A compromised node agent on the coordinator machine reaches the coordinator | Different accounts (`_oarbank` vs `_oarbankd`); the agent cannot read the home or join the group. |
| A compromised agent installs a coordinator service | Agents run unprivileged and cannot; the root helper has no such operation (decision 11). |
| The service rewrites what it runs | Programs are root-owned; the installer refuses writable builds. |
| A compromised coordinator signs as the owner | The owner keys never enter the service's home (decision 6). |
| Secrets exposed during the migration | Keys go from the Keychain straight into the old home's 0600 file store (the person's own 0700 home), then into the clone; no secret is in the journal, on a command line or in the install log. |

Residual: root reads everything (as on any Unix); an owner-group member is an owner, as the coordinator's account was.

## Testing

- Unit level everywhere: the installer's dry run renders the plists and units exactly (accounts, groups, socket
  directory, environment, keep-alive, `AssociatedBundleIdentifiers`); the service record round-trips through
  `--refresh`; `hostinfo` parses launchd's and systemd's answers for both domains; the admin channel admits a group.
- The migration runs end to end on a copy of a real per-user home (path-parametrized roots, a throwaway keychain in
  the test's directory holding fake keys with the same item names, recorded launchctl/chown calls): export, preflight
  checks, clone, verify against the database, finish, the rollback after a failed start, and idempotency.
- The Linux form in a container (systemd as PID 1): package install, accounts, units, the socket's group, migration of
  a user unit.
- What only a real Mac shows (no administrator prompt is allowed on the development Mac; listed in the release
  checklist): the pkg postinstall creating `_oarbankd` and `_oarbankadmin`, the daemons starting at boot with FileVault
  before login, Allow in the Background listing them as Oarbank Coordinator, dynamic group membership reaching the
  socket without logging out, the `launchctl asuser` export in the person's session, and the AppleScript prompt from
  the wizard and the app.
