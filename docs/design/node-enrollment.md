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

The agent writes `status/node.json` beside its home (`<data root>/status/node.json`; readable by everyone, no secrets):

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
oarbank-node leave  [--purge]
oarbank-node doctor [--json]
```

With no code source on a terminal, `join` prompts with hidden input; `--no-input` fails instead. There is no
`--code <value>` flag. `--scope` exists on macOS (default: system when run as root, else personal); Linux and Windows
always install the system service. `--containers` installs Windows' container prerequisites. `--progress-file` writes
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
| One-liner | `curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh \| sudo sh` (prompts on the terminal, or reads `OARBANK_JOIN_CODE`) | same | `irm https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.ps1 \| iex` |
| MDM / policy | profile, domain `dev.codonic.oarbank.agent` | `/etc/oarbank/policy.json` | `HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent` (ADMX template in the release) |
| Deep link | `oarbank://join?code=…` → join window, confirmation first | same (`x-scheme-handler/oarbank`) | same (`HKCR\oarbank`) |

### Managed policy keys

| Key | Type | Meaning |
|---|---|---|
| `JoinCode` | string | A code (usually multi-use, pending); honoured only while the node has not joined |
| `Coordinator` | string | Join by URL instead (device code/pending approval) |
| `Scope` | `system`\|`personal` | macOS only; default `system` when managed |
| `Containers` | boolean (Windows DWORD) | Install container prerequisites (Windows) |
| `Name` | string | The node's name when the code has no label |
| `AllowUserJoin` | boolean | `false` hides Join and Leave in the app |
| `ManagedByOrganizationName` | string | Shown in the app and status |

Values are never logged. On macOS a root launchd job (`dev.codonic.oarbank.agent.policy`, `WatchPaths` on the
managed-preferences file) applies policy, so a profile delivered before or after the pkg both work. On Linux and
Windows the waiting service reads policy every 5 s.

### Linux package variables

`OARBANK_JOIN_CODE`, `OARBANK_JOIN_CODE_FILE`, `OARBANK_COORDINATOR`, `OARBANK_NAME`, `OARBANK_CONTAINERS` (apt and dnf
pass the environment to package scripts; sudo needs SETENV, which an `ALL` rule grants). The postinstall installs the
waiting service, stages the code, and exits 0.

### Windows MSI properties

`JOINCODE` (Secure, Hidden), `JOINCODEFILE`, `COORDINATOR`, `CONTAINERS`, `NAME`, `NOLAUNCH`. The join page's field is a
password control (never logged). An installed node ignores them on repair and upgrade. Intune: a Win32 app with
`msiexec /i oarbank-agent-<v>-windows-x64.msi /qn JOINCODE=…` and the detection rule
`HKLM\SOFTWARE\Codonic\Oarbank\Agent\Joined = 1` (written once the node has joined).

## Join window

One page served by the bundled runtime on 127.0.0.1 (the coordinator setup wizard's hardened pattern: exact Host and
Origin, a capability in the URL fragment, strict CSP), opened in the default browser by the menu bar/tray app, the
desktop entry, or a deep link. States: Join (code field, Paste, offline summary, options) → Confirm (only for codes
that arrived by link or file) → checks (rows with plain-language errors and codes, Retry, Copy diagnostics) →
administrator approval (the OS's own prompt) → Waiting for approval (user code, key fingerprint) → Ready (Open console).
When the node has joined, the page shows its status and Leave (unless policy forbids).

## Console

Fleet → **Add machine…**: name, options (system service, container jobs), one machine or many (uses, lifetime,
approve automatically). The result shows the code once with Copy, an **Open in Oarbank Node** deep link, per-OS tabs
(download, attended steps, command line with the code filled in), an MDM tab (`.mobileconfig`, Intune command,
`policy.json`, Ansible), and live status of the code's enrollments (waiting → pending with Approve/Decline → joined).
Outstanding codes are listed with uses left and Revoke. **Approve a machine by its code** takes a device code.
