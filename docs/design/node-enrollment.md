# Node enrollment: installed, then joined

Status: implemented in 2.8.0. Research and rationale: the enrollment UX study (installer argument channels per OS,
vendor practice, installer UX guidance). This document is the contract the agent, launcher, packages, join window,
console and docs follow.

## Principles

1. **A package installs; it never needs the join code.** Every package installs the programs and exits 0 whatever the
   network does. Joining is a separate step with one engine (`oarbank-node join`) that every channel feeds.
2. **No hand-made files.** Nothing tells a person to `mkdir` or `tee` into a system folder. `/Library/Oarbank/etc` and
   `/etc/oarbank/join-code` are gone.
3. **The code never sits on a command line a person types.** It comes from a hidden prompt, stdin, a file, a package
   variable (Linux `apt`/`dnf`, Windows MSI properties, both seen only by root/administrators), managed policy, or the
   join window.
4. **Verify before sending.** The node checks the code offline (format, check digits, expiry), then the network (DNS,
   TCP, TLS with the pinned CA key, the coordinator identity key, clock), and only then sends the secret.
5. **A code that merely arrives is confirmed.** A deep link or a file is shown with the coordinator's address and
   fingerprint and joins only after the person confirms. Joining the wrong coordinator hands it the machine.
6. **One status, everywhere.** The agent writes a status document; the join window, the menu bar/tray app,
   `oarbank-node status` and installers read it. Errors carry stable codes.

## Join code format (OB2)

`OB2-` + Crockford base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, upper case, no padding) of:

| Field | Size | Meaning |
|---|---|---|
| version | 1 | `2` |
| flags | 1 | bit 0 approved at once; bit 1 system service (macOS default scope); bit 2 container jobs; bit 3 multi-use |
| expires | 4 | Unix minutes, big-endian (the coordinator's record is authoritative; this lets a node say "expired" offline) |
| cik | 32 | The coordinator identity key (raw Ed25519 public key): pinned before the first identity proof |
| pins | 1 + 32·n | SHA-256 of the TLS CA SubjectPublicKeyInfo; the first is current, a second is the CA's successor |
| urls | 1 + Σ(1 + len) | Coordinator agent URLs, UTF-8, each at most 255 bytes |
| id | 8 | The code's id (lookup, listing, revocation) |
| secret | 16 | Bearer secret; the coordinator stores only its SHA-256 |
| crc | 4 | CRC-32 (IEEE) of every byte above, big-endian |

Parsing strips whitespace and dashes after the prefix, folds case, maps `I`/`L` to `1` and `O` to `0`, and refuses a
code whose CRC does not match ("copy it again from the console"). A one-URL code is about 200 characters: it is pasted,
never typed. Codec: `oarbank.coordinator.joincodes` (Python) and `oarbank_core::joincode` (Rust), tested against the
shared vectors in `src/oarbank/contracts/vectors/joincode.json`.

The enrollment request carries `join: "<id hex>.<secret hex>"`.

## Code types

| | Single-use (default) | Multi-use |
|---|---|---|
| For | one machine, attended or over SSH | MDM, images, config management |
| Uses | 1 | 2–10000, required |
| Lifetime | 4 h default, 10 min – 7 d | required, up to 30 d |
| Approval | at once | pending (console approval) unless the owner ticks "approve automatically" |

Revoking or expiring a code never removes a node that already joined. Failed redemptions (unknown, expired, used up,
revoked) are recorded as `join_code_refused` events with the source address.

Operations: `nodes.join_code {label, ttl_s, uses, approve, system, containers}`, `nodes.join_codes` (list, with each
code's enrollments), `nodes.revoke_join_code {target: code id}`, `nodes.admit_code {user_code}` (device code, below).
CLI: `oarbank join-code [--label] [--ttl] [--uses N] [--approve|--no-approve] [--system] [--containers]`,
`oarbank join-codes`, `oarbank join-code revoke <id>`, `oarbank node approve-code <CODE>`.

## Device code (no paste available)

`oarbank-node join --coordinator https://host:7443` enrolls without a code. The node shows the coordinator's
fingerprint (first 16 hex of the CA key hash) and an 8-letter code from the RFC 8628 alphabet
`BCDFGHJKLMNPQRSTVWXZ` (`WDJB-MJHT`). The owner checks the fingerprint the console shows and enters the code under
Fleet, "Approve a machine by its code"; that approves the pending enrollment with that code.

## The node's states and status document

The agent writes `status/node.json` beside its home (and a `joined` marker file there while it holds a certificate) (`<data root>/status/node.json`; readable by everyone, no secrets):

```json
{"format": 1, "state": "unjoined|checking|joining|pending|joined|connected|error",
 "coordinator": "https://host:7443", "fingerprint": "9f2c41ab…", "node_id": "n_…", "name": "build-07",
 "enrollment_id": "enr_…", "user_code": "WDJB-MJHT", "key_fingerprint": "sha256:…", "code_expires_at": 1790000000,
 "managed_by": "Example Corp", "error": {"code": "E_TLS_PIN_MISMATCH", "message": "…"}, "updated_at": 1790000000}
```

A service started without a coordinator and without a code waits (`unjoined`) and looks every 5 s for a staged code
(`state/join-code`) and for managed policy. A staged code is redeemed with backoff until it expires; a code the
coordinator refuses, or a pin mismatch, ends the attempt with an error and deletes the code (`E_*` below).

### Error codes

| Code | Meaning | Retry |
|---|---|---|
| `E_CODE_FORMAT` | not a complete OB2 code (prefix, check digits) | no |
| `E_CODE_EXPIRED` | expired (offline or by the coordinator) | no |
| `E_CODE_USED` | already used / no uses left | no |
| `E_CODE_REVOKED` | revoked by the owner | no |
| `E_CODE_UNKNOWN` | the coordinator does not know it (another coordinator?) | no |
| `E_DNS` | the coordinator's name does not resolve | yes |
| `E_TCP` | no answer on the port (firewall, coordinator down) | yes |
| `E_TLS_PIN_MISMATCH` | the server's CA key is not the one the code names (TLS-inspecting proxy, wrong coordinator) | no |
| `E_IDENTITY` | the coordinator's identity key or proof is not the one the code names | no |
| `E_CLOCK_SKEW` | this computer's clock is more than 5 minutes off | after fixing |
| `E_NOT_ACTIVE` | the coordinator is a standby or handed off | yes |
| `E_APPROVAL_DENIED` | the owner rejected this machine | no |
| `E_ALREADY_JOINED` | joined to another coordinator (`--force` leaves it first) | — |
| `E_PRIVILEGE` | a system install needs root / an administrator | — |

## `oarbank-node`

The node's command-line front end (the launcher binary under a second name: a symlink on macOS and Linux, a copy on
Windows, on PATH: `/usr/local/bin/oarbank-node`, `/usr/bin/oarbank-node`, `C:\Program Files\Oarbank\oarbank-node.exe`).
The coordinator's own CLI keeps the name `oarbank`; the node CLI is `oarbank-node` so one machine can run both.

```text
oarbank-node join [--code-stdin | --code-file PATH | --coordinator URL] [--scope system|personal]
                  [--containers] [--name NAME] [--wait SECONDS | --no-wait] [--no-input] [--json] [--force]
                  [--progress-file PATH]
oarbank-node status [--json] [--follow]
oarbank-node check  [--code-stdin | --code-file PATH] [--json]      the checks, nothing sent or written
oarbank-node leave
oarbank-node doctor [--json]
```

With no code source on a terminal, `join` prompts with hidden input; `--no-input` fails instead. There is no
`--code <value>` flag. `--scope` exists on macOS (default: system when run as root, else personal); Linux and Windows
always install the system service. `--containers` installs Windows' container prerequisites (waiting for any other
Windows installation to finish first). `--progress-file` writes
the check rows and states as JSON lines (the join window runs `join` elevated and reads them).

Exit codes: 0 joined (or already joined to this coordinator), 2 usage or a malformed code, 3 pending approval
(`--no-wait` or the wait ran out), 4 code expired/used/revoked/unknown, 5 pin or identity mismatch, 6 network
unreachable (retryable), 7 joined to another coordinator, 8 needs root/administrator.

Under the hood `join` runs `oarbank-agent check` (the network checks), then the install plan (`setup`) with the code
staged in `state/join-code` (0600, the service account's), then follows the status document.

## Channels

| Channel | macOS | Linux | Windows |
|---|---|---|---|
| Attended GUI | the pkg opens **Oarbank Node** (menu bar) at the join window after a double-click install | the **Oarbank Node** app entry opens the join window | the MSI's last page opens **Oarbank Node** (tray) at the join window; or paste the code on the MSI's join page |
| SSH / script | `sudo installer -pkg … -target /` then `sudo oarbank-node join` (prompt or `--code-stdin`) | `sudo OARBANK_JOIN_CODE=… apt install ./….deb`, or install then `sudo oarbank-node join` | `msiexec /i … /qn JOINCODEFILE=…` or `JOINCODE=…` |
| One-liner | `curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh \| sudo sh` installs and verifies; with `OARBANK_JOIN_CODE` (the console's command) it also joins, otherwise run `sudo oarbank-node join` afterwards (it never prompts: see below) | same | `irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1 \| iex` (asks for the code with `Read-Host -AsSecureString` when it has none) |
| MDM / policy | profile, domain `dev.codonic.oarbank.agent` | `/etc/oarbank/policy.json` | `HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent` (ADMX template in the release) |
| Deep link | `oarbank://join?code=…` → join window, confirmation first | same (`x-scheme-handler/oarbank`) | same (`HKCR\oarbank`) |

The one-liner never prompts for the code when its standard input is not a terminal (piped, as above). sudo 1.9.14 and
later (`use_pty`) runs the command on a pseudo-terminal of its own and puts the person's terminal in raw mode only when
sudo's own standard input is a terminal; piped from curl it is not, so the person's terminal keeps echoing, and a prompt
that turns echo off on sudo's pseudo-terminal would show the pasted code. Without `OARBANK_JOIN_CODE`,
`OARBANK_JOIN_CODE_FILE` or `OARBANK_COORDINATOR` it installs, prints `Installed. Join this computer with: sudo
oarbank-node join`, and exits 0; run as a file (`sudo sh oarbank-install.sh`, standard input the terminal) it runs
`oarbank-node join` there. `OARBANK_COORDINATOR` may still ask the device-code fingerprint question (y/N, nothing secret)
on the terminal. `oarbank-node join`'s own prompt reads the terminal back after turning echo off and says the code will
show when the terminal did not take it; it cannot see a terminal beyond sudo's, which is why the one-liner does not
prompt.

### Managed policy keys

| Key | Type | Meaning |
|---|---|---|
| `JoinCode` | string | A code (usually multi-use, pending); honoured only while the node has not joined |
| `Coordinator` | string | Join by URL instead (device code/pending approval) |
| `Containers` | boolean (Windows DWORD) | Install container prerequisites (Windows) |
| `Name` | string | The node's name when the code has no label |
| `AllowUserJoin` | boolean | `false` hides Join and Leave in the app |
| `ManagedByOrganizationName` | string | Shown in the app and status |

A managed node is always the system service. Values are never logged. On macOS a root launchd job (`dev.codonic.oarbank.agent.policy`, `WatchPaths` on the
managed-preferences file) applies policy, so a profile delivered before or after the pkg both work. On Linux and
Windows the waiting service reads policy every 5 s.

### Linux package variables

`OARBANK_JOIN_CODE`, `OARBANK_JOIN_CODE_FILE`, `OARBANK_COORDINATOR`, `OARBANK_NAME`, `OARBANK_CONTAINERS` (apt and dnf
pass the environment to package scripts; sudo needs SETENV, which an `ALL` rule grants). The postinstall installs the
waiting service, stages the code, and exits 0.

### Windows MSI properties

`JOINCODE` (Secure, Hidden), `JOINCODEFILE`, `COORDINATOR`, `CONTAINERS`, `NAME`, `NOLAUNCH`. The join page's field is a
password control (never logged). A code that is not valid (a wrong paste) installs the node waiting, with a warning
in the installer's log, rather than failing the install. An installed node ignores them on repair and upgrade, except
`CONTAINERS=1`. Intune: a Win32 app with
`msiexec /i oarbank-agent-<v>-windows-x64.msi /qn JOINCODE=…` and the file detection rule
`%ProgramData%\Oarbank\status\joined` (the agent writes it once the node has joined, and removes it when it leaves).

**Container support never runs inside the MSI.** `CONTAINERS=1` (the property, the join page's "Run container jobs"
box) and a code made for container jobs (flag bit 2; `setup --containers-later`, which only the MSI passes) ask for
the WSL components the container runtime needs (docs/design/windows-containers.md). The WSL package is itself a
Windows Installer package, and Windows Installer runs one installation at a time: installing it from a custom action
is a nested installation, which Microsoft deprecates ("Concurrent Installations": hard to service, and they share the outer
installation's user interface and logging), and on a real PC it failed the agent's install with error 2755 (1622: the log) and
status 1603 although the node had joined. A bootstrapper (a WiX Burn bundle that chains the WSL package before the MSI)
would install it outside, but WSL's own installer picks the package (Windows Update, else its GitHub release) at run
time and may need a restart in between, and the bundle would be a second artifact for every deployment channel. So the
MSI's deferred action (`ScheduleContainers`, LocalSystem, `Return="ignore"`) runs `oarbank-launcher container-support
schedule`, which only registers the task `\OarbankContainerSupport`:

| | |
|---|---|
| Runs as | LocalSystem, highest privileges, on battery too, one run at a time, at most 2 h |
| When | the installer logs that it installed or reconfigured the Oarbank agent (Application log, MsiInstaller event 1033 or 1035 with the product's name: the installation has ended), and 1 min after every start of Windows |
| Does | `oarbank-launcher container-support run`: `oarbank-agent containers install --wait 1800` (which waits until no installation holds the `Global\_MSIExecute` mutex and exits 1618 if one still does), records the outcome, deletes the task once it is `done` or `failed` |
| Records | `HKLM\SOFTWARE\Codonic\Oarbank\ContainerSupport`: `State` (`scheduled`, `installing`, `waiting`, `restart`, `done`, `failed`), `Detail`, `Attempts`, `Updated`; administrators and SYSTEM write it, everyone reads it (the status directory lets every user create files, which a LocalSystem task must not write through) |
| Restart | exit 3010 records `restart` and keeps the task: the run after the next start of Windows finds nothing missing and records `done` |
| Gives up | after 5 runs that still need a restart or found another installation running: `failed` |
| Again | `"C:\Program Files\Oarbank\oarbank-launcher.exe" container-support run` as an administrator runs it now and records the outcome (`container-support status` prints the record) |
| Goes | a first install or upgrade that rolls back cancels it (`RollbackContainers`); uninstalling ends and deletes it and the record (`CancelContainers`); a node whose agent is gone deletes it at its next run |

The MSI exits 0 (3010 when Windows Installer itself asks for a restart) whatever WSL makes of it. Oarbank Node shows a line while it is not done ("Installing container
support…", "Restart Windows to finish container support", "Container support failed: …"); `oarbank-node status` and
`doctor` print the same line (`container_support` in `--json`). `oarbank-node join --containers` (and a code made for
container jobs, unless `--no-containers`) runs `oarbank-agent containers install --wait 600` itself, outside any
installer, records the outcome the same way, and leaves the task behind only when Windows must restart or another
installation kept running.

## Join window

One page served by the bundled runtime on 127.0.0.1 (the coordinator setup wizard's hardened pattern: exact Host and
Origin, a capability in the URL fragment, strict CSP), opened in the default browser by the menu bar/tray app, the
desktop entry, or a deep link. States: Join (code field, Paste, offline summary, options) → Confirm (only for codes
that arrived by link or file) → checks (rows with plain-language errors and codes, Retry, Copy diagnostics) →
administrator approval (the OS's own prompt) → Waiting for approval (user code, key fingerprint) → Ready.
When the node has joined, the page shows its status and Leave (unless policy forbids).

## Console

Fleet → **Add machine…**: name, options (system service, container jobs), one machine or many (uses, lifetime,
approve automatically). The result shows the code once with Copy, an **Open in Oarbank Node** deep link, per-OS tabs
(download, attended steps, command line with the code filled in), an MDM tab (`.mobileconfig`, Intune command,
`policy.json`, Ansible), and live status of the code's enrollments (waiting → pending with Approve/Decline → joined).
Outstanding codes are listed with uses left and Revoke. **Approve a machine by its code** takes a device code.

### Join window: files and launch contract

Source: `deploy/node/join-window.py` and `deploy/node/join-window.html` (standard library only; run by the node
package's bundled runtime). Installed at:

| OS | Join window | Runtime Python | Launcher (`oarbank-node`) |
|---|---|---|---|
| macOS | `/Library/Oarbank/share/join/` | `/Library/Oarbank/bin/runtime/bin/python3` | `/Library/Oarbank/bin/oarbank-launcher` (symlink `/usr/local/bin/oarbank-node`) |
| Linux | `/usr/lib/oarbank/join/` | `/usr/lib/oarbank/runtime/bin/python3` | `/usr/lib/oarbank/oarbank-launcher` (symlink `/usr/bin/oarbank-node`) |
| Windows | `[INSTALLFOLDER]join\` | `[INSTALLFOLDER]runtime\python.exe` (`pythonw.exe` from the tray) | `[INSTALLFOLDER]oarbank-node.exe` |

`python -I join-window.py [--launcher PATH] [--elevator PATH] [--link URL | --code-file PATH] [--no-browser]` serves the page on
127.0.0.1 (a random port), prints `Open this private link on this computer: http://127.0.0.1:<port>/#<capability>` on
stdout and opens it in the default browser unless `--no-browser`. A second launch while one is open reopens the open
one (a private `join.active.json` in the user's temporary directory, as the coordinator setup wizard does).
`--link oarbank://join?code=…` and `--code-file` prefill the code and show the confirmation screen first. The page
checks the code unprivileged (`oarbank-node check --code-stdin --json`), then runs `oarbank-node join --no-input
--no-wait --progress-file P` with the code on standard input (macOS, `--code-stdin`) or in a file (`--code-file F`:
Linux, Windows) and the OS's own elevation (macOS: personal scope unelevated, system scope through Oarbank Node.app's
`--elevate`, below; Linux: `pkexec` with the polkit actions `dev.codonic.oarbank.node.join` and `.leave`
(`/usr/share/polkit-1/actions/dev.codonic.oarbank.node.policy`), whose messages and icon replace pkexec's generic
prompt; Windows: UAC) and follows the status document. `--elevator` names the app's executable (the app passes its
own; default `/Applications/Oarbank Node.app/Contents/MacOS/Oarbank Node`).

A bare or empty `--link` means no link (the desktop entry's `--link %u` opened from the menu); a second launch with a
link hands its code to the open window. An explicit `--launcher` must exist; without one the window looks at
`OARBANK_NODE_LAUNCHER`, the package layout beside the script, then `oarbank-node` on PATH. The code file and the
progress file live in a 0700 directory of the user's (`oarbank-join-<uid>` in the temporary directory, with the lock and
`join.active.json`); the code file goes as soon as the launcher exits, and the window stays open until it has. Without
`pkexec` Linux asks for `sudo oarbank-node join` in a terminal, and without Oarbank Node.app so does macOS (there is no
`osascript` fallback). A dismissed prompt is exit 126 on macOS and Linux, 1223 on Windows: the page says nothing
changed. The page's API (all `POST`, JSON, with the capability
in `X-Oarbank-Join`): `/state`, `/check {code}`, `/join {code, scope, containers, name}`, `/progress {offset}`, `/leave`,
`/prefill {code, source}`, `/ping`, `/close`. Policy reaches the page only as `AllowUserJoin` and
`ManagedByOrganizationName`, and `AllowUserJoin: false` refuses `/join` and `/leave`.

Native front ends: macOS **Oarbank Node.app** (`/Applications`, menu bar; registers `oarbank://`), Windows **Oarbank
Node** tray app (`[INSTALLFOLDER]Oarbank Node.exe`, Start menu, registers `oarbank://`), Linux desktop entry
`dev.codonic.oarbank.node.desktop` (registers `x-scheme-handler/oarbank`). Each shows the status document (state,
coordinator, errors), offers **Join this machine…** while not joined (hidden when policy `AllowUserJoin` is false) and
**Status…** once joining started, and runs the join window for both (a node does not know its console's address).

### macOS elevation

The system-service join and leave need root. `osascript -e 'do shell script … with administrator privileges'`, which
2.8.0 used, is out: macOS 27 words its prompt "Allow administrator access for a script started by python3.12? … Apple
could not verify this script is free of malware", the very prompt a person should refuse, and it runs a shell command
line as root for whoever asked. `AuthorizationExecuteWithPrivileges` is deprecated since 10.7 and checks nothing about
what it runs; a setuid tool is ruled out the same way (Apple DTS, "BSD Privilege Escalation on macOS",
developer.apple.com/forums/thread/708765). `SMAppService.daemon` (macOS 13) does not bootstrap a daemon "until an admin
approves the LaunchDaemon in System Preferences" (`SMAppService.register()`): a detour through Login Items in the
middle of joining, while the pkg already runs as root and can install a daemon outright (the installer-package route
the same DTS note calls "by far the easiest"). So:

- **The helper** `/Library/Oarbank/bin/oarbank-node-helper` (Swift, `deploy/macos/node/NodeHelper.swift` with
  `Elevation.swift`), the LaunchDaemon `dev.codonic.oarbank.agent.helper` (Mach service of the same name, no RunAtLoad,
  exits after a minute idle). It lives with the programs in `/Library/Oarbank` (root's alone), not in the app bundle,
  which any administrator can move or replace in `/Applications` without a prompt. It accepts an XPC connection only
  from a process whose code signature satisfies a requirement compiled in at package time
  (`xpc_connection_set_peer_code_signing_requirement`, macOS 12+, checked on the peer's audit token): `anchor apple
  generic and identifier "dev.codonic.oarbank.node" and` the Developer ID intermediate and leaf markers `and certificate
  leaf[subject.OU] = "MKNM96EU7J"` (`OARBANK_TEAM_ID`); an ad-hoc test package pins its own app's cdhash instead
  (`identifier "dev.codonic.oarbank.node" and cdhash H"…"`), which only that build satisfies, but an ad-hoc app has no
  hardened runtime, so a local process able to start it with an injected library passes too (the administrator still
  authenticates). `package-macos.sh` checks the app it ships satisfies the requirement (`codesign -R`).
- **Two authorization rights**, registered by the postinstall (`oarbank-node-helper register-rights`, i.e.
  `AuthorizationRightSet` as root) and removed by `oarbank-uninstall`: `dev.codonic.oarbank.node.join` ("Oarbank Node
  wants to join this Mac to an Oarbank fleet.") and `dev.codonic.oarbank.node.leave` ("Oarbank Node wants to make this
  Mac leave its Oarbank fleet."): class user, group admin, timeout 0, not shared, so an administrator authenticates for
  each request and no credential cached by another prompt serves. One right per operation, so the prompt says which,
  and a site can allow or deny each with `security authorizationdb`.
- **The request.** The join window runs `Oarbank Node --elevate join --code-stdin --no-input --no-wait --progress-file P
  --scope system [--name N]` (or `--elevate leave --progress-file P`) with the code on standard input. The app opens P
  itself, as the person (`O_NOFOLLOW`, a regular file of theirs), makes an empty AuthorizationRef, and sends `{op, auth:
  its external form, progress: the open descriptor, code, name}`. The helper checks every field again (exactly the
  operation's keys, the name rule, a printable code of at most 4096 bytes, the descriptor a regular single-link file of
  the caller's uid open for writing, the launcher root's and not writable by others), then asks for the operation's
  right on the client's AuthorizationRef with interaction (`AuthorizationCopyRights`, extend rights, the prompt and the
  app's icon in the environment). The system prompt names the AuthorizationRef's creator, Oarbank Node, with its icon,
  and shows no unverified-script warning. Only then it runs `oarbank-launcher join --scope system --code-stdin
  --no-input --no-wait --progress-file /dev/fd/3 [--containers] [--name N]` (or `leave --progress-file /dev/fd/3`)
  with an argv it builds itself, the code on the launcher's standard input, the app's descriptor as fd 3, nothing else
  inherited, launchd's kind of environment, an hour at most. Root never opens a path a request named, and nothing a
  request sends reaches an argv but a checked name.
- **The answer.** The helper replies `ok` with the launcher's exit code, `cancelled`, `denied` or `refused`; the app
  exits with the launcher's code, 126 for a dismissed prompt, 8 (`E_PRIVILEGE`) for someone who is not an administrator,
  1 when the helper is missing or refused, and writes a `result` line to the progress file for those so the page shows
  why. Progress itself keeps flowing through the file the launcher writes.

The menu bar app never handles a code; `--elevate` relays the one on its standard input and exits. What can only be
seen on a Mac with the package installed: the XPC round trip, the prompt's wording and icon, and the code signature
check of a notarized build.
