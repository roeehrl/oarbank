# Architecture

Oarbank runs batch work on a fleet of machines: macOS, Linux and Windows nodes, reachable over any network (PLAN D25).
This page describes how the pieces fit and how each works on each operating system. The wire protocol is in
[docs/protocol.md](../protocol.md); decisions and their reasons are in [PLAN.md](PLAN.md).

## Components

| Component | What it is |
|---|---|
| **oarbankd** (`src/oarbank/coordinator`, Python) | The coordinator: one process, one SQLite database (WAL, one writer lock), the agent API on an mTLS listener, the admin API on loopback and an owner-only local socket, the background loops (reaper, campaigns, discovery, audit digests, invariants, backups) and one sandboxed process per enabled module (the module host, D1). |
| **oarbank-console** (`src/oarbank/console`) | The web console, a separate read-only process (D10): it renders pages from its own snapshot of the database and sends every change to oarbankd's operation endpoint. Module frames are served from a second origin. |
| **oarbank** (`src/oarbank/cli`) | The admin CLI: the same admin API the console uses; every write is an operation (D14). |
| **oarbank-agent** (`rust/crates/oarbank-agent`) | The node agent (D26): enrollment, sessions, staging, jobs in the module sandbox, services and probes, host protection (`oarbank-protection`, [protection.md](protection.md)), self-update requests, coordinator moves and rescue moves. |
| **oarbank-launcher** (`rust/crates/oarbank-launcher`) | Keeps the agent running under the OS service manager and owns which agent version runs. |
| **oarbank-core** (`rust/crates/oarbank-core`) | The contracts that must match byte for byte: canonical JSON, portable paths, bundle digests and release verification, sandbox policies and profiles, the protection matcher. The SDK's Python code is held to it by parity tests through `oarbank-core-py`. |
| **oarbank-sdk** (`vendor/oarbank-sdk`, Apache-2.0) | The open module contract: manifest, module, runner and service protocols, bundles, the sandbox contract, the conformance kit and the reference `toy` module. The core consumes it, never the other way round. |
| **Modules** | Bundles built on the SDK, installed into the coordinator's store, approved per version by digest. |

## Platforms and the node model

- **Platform tokens** are `<os>-<arch>` with `os` in `darwin`, `linux`, `windows` and `arch` in `arm64`, `amd64`. The
  set is open: an unknown token means "no node of this platform here", not an error. `linux-*` means glibc.
- **Facts.** Every hello carries the node's facts (format 2, the SDK's `spec/platforms.md`): `platform {os, arch,
  os_version, os_build, kernel, distro, libc}`, `cpu`, `memory_gb`, `gpus`, `addresses` and `sandbox.enforcement` per
  capability. Nodes have indexed `platform`, `os` and `arch` columns.
- **Placement.** A module version runs on a node only when its manifest lists the platform (`requires.platforms`), the
  node's OS version is in `requires.os`, every host tool it was approved for is in the operator's tool registry for
  that OS, the node's sandbox enforces every capability it needs, and the agent is recent enough. Each refusal has a
  reason code that `explain` shows, with the module's own reason when it gives one (`requires.unsupported.runner`). A
  stage limited to some platforms runs only there, and so does a job limited to some platforms (jobs.enqueue `platforms`)
  or reading a platform-bound dataset (datasets.create `platform`).
- **Units of work** ([per-platform-modules.md](per-platform-modules.md), D33). A module's `[placement]`, or a stricter
  campaigns.create `placement`, keeps each unit of work (a campaign, a job group, a dataset's jobs, a pipeline) on one
  platform class (`mix`: any, same-os, same-arch, same-platform) while other units use other classes. Each unit has one
  binding (`placement_bindings`): by capacity when it is created (campaigns), by its first claim (inside claim's
  transaction; groups, datasets, pipelines) or by a pin; soft until its first accepted result or cache hit, then hard.
  claim and explain decide on the same predicates (`STAGE_PLATFORM_UNSUPPORTED`, `DATASET_PLATFORM_MISMATCH`,
  `PLACEMENT_UNPINNED`, `PLATFORM_BOUND_ELSEWHERE`); the result cache reuses only results of the unit's class. A unit
  whose class has no eligible node for `stranded_after_s` raises `placement_stranded:<unit>`, or (`rebind =
  "if-stranded"`) moves to the best feasible class and runs its finished jobs again there; `campaigns.rebind_platform`
  moves one by hand and `campaigns.set_placement` tightens a campaign's mix before its first result. Invariant S20 holds
  every live and finished job of a bound unit to its class.
- **Coordinator platforms.** `requires.coordinator_platforms` lists where a module's coordinator side runs (absent: any).
  Install, enable, canary, promote, pin and rollback refuse a version whose coordinator side does not run on this
  coordinator's platform; a coordinator move to such a platform needs force, and the target then disables the module
  with an alert. The coordinator process runs `[coordinator]` with the variant for this platform (exec, runtime,
  timeouts, concurrency, env); `initialize` names the core's version, the host features it implements and the platform.
- **Per-platform adjustments.** Runner variants also carry `env`, which the release renders per platform and the agent
  applies after its own variables (reserved names are refused on both sides). Stage variants change a stage's timeout
  and resources per platform: jobs store the overrides and claim, explain and the grant's envelope resolve them for the
  node. Goldens may be limited to some platforms and expect a value per platform; each node gets its own.
- **Releases are per platform**: a composition filtered by platform, the platform bound into the release id, one
  current release per platform, a release built when a node of a new platform enrolls. A release holds only the bundle
  files its platform receives (`[bundle.platform_files]`) and the wheels that install there.
- **Agent builds are keyed by platform**: the coordinator reads the Mach-O, ELF or PE header and an embedded version
  marker and never executes an upload; one channel per platform.
- **Determinism scope.** `results.determinism_scope` (`global`, `os`, `arch` or `platform`; unknown: `platform`) is the
  class results compare within: replicas and tie-breaks run in the original result's class (`COMPARED_ON_PLATFORM`), and
  results from different classes are never disputed. The class comes from `results.platform`, a snapshot taken when the
  result was recorded, and the module version that produced it.
- **Stored paths** are `/`-separated and relative to the coordinator's home when inside it, so a home moves between
  machines and operating systems unchanged.

## Host interfaces

The agent reaches the OS only through these interfaces, one backend per OS:

| Interface | macOS | Linux | Windows |
|---|---|---|---|
| Service manager (the launcher) | launchd: a LaunchAgent (personal scope) or a LaunchDaemon run by `_oarbank` (system scope) | systemd units, user or system (`Delegate=yes`) | the service manager, a service run by its virtual account with recovery actions, or a logon task for the personal scope |
| Job container | a process group | a cgroup v2 leaf where systemd delegated the agent's cgroup (kill, freeze, usage), else a process group | a Job Object, kill-on-close for attempts |
| Hard limits (`hard_limits` policy) | none | cgroup `cpu.max` and `memory.max` | Job Object limits |
| Process inspection | libproc, `sysctl kern.proc` (every account's), `KERN_PROCARGS2`, code-signing identity | `/proc` (stat, status, cmdline, exe, schedstat) | the native process list (`NtQuerySystemInformation`: processes, threads' states, image paths), command lines |
| Meters | rusage, IORegistry GPU time, memory pressure, thermal state, battery | `/proc` (CPU time, run-queue wait from `schedstat`, major faults), DRM `fdinfo` and NVML GPU time, PSI memory pressure, thermal zones, power supplies, hybrid core types | the process list (CPU time, threads waiting for a core, hard faults), `GlobalMemoryStatusEx`, GPU Engine counters, efficiency classes, power status |
| Front app | `lsappinfo` | the seat's session from logind: an X11 session's active window (EWMH), a text console's foreground group | the console session from WTS, its foreground window |
| Presence | HID idle, screen sharing | systemd-logind's sessions a person is using: an active desktop's idle hint, a text session's terminal input time (logind's, else its processes' controlling terminal); sessions without a terminal (ssh commands), user managers, greeters, background and closing sessions do not count | the sessions WTS lists (logged on, connected, locked), the last input in each person's session (the session helper's, for the system service) |
| Session helpers (the system service) | a LaunchAgent in every GUI login, reporting over `/Library/Application Support/Oarbank/run/session.sock` | a global systemd user unit per person, reporting over `/run/oarbank/session.sock` | started by the elevated helper in each person's session, reporting over `\\.\pipe\oarbank-session` |
| Discovery (browse) | dns-sd | Avahi | `DnsServiceBrowse` |
| Module sandbox | Seatbelt | Landlock and seccomp | AppContainer in a Job Object, plus an elevated helper for the egress allowlist |
| Containers | an agent-owned Colima profile | rootless Podman, else Docker Engine | not yet |

Host protection runs on every OS ([protection.md](protection.md), "On each OS" and "Whose processes"): the rules,
their process trees and triggers, presence, the front app, GPU time, the dynamic controller's measured signals and its
actions on fleet jobs.

## The coordinator

- **`oarbank/platform`** holds every OS-touching helper: owner-only files (POSIX modes; the per-user data roots on
  Windows are private to the account), the secret store, interpreter paths, process launch.
- **The secret store** keeps small secrets out of the database: the login Keychain on macOS, an owner-only file under
  `<home>/keys/` elsewhere (and in tests, `OARBANK_SECRET_STORE=file`). The audit signing key lives there.
- **Module processes** run in the OS's sandbox through the agent's launcher (`bin/oarbank-sandbox` in a coordinator
  build; `sandboxexec.py`), with the module's own venv (`python` resolves to the bundle's `.venv`). A coordinator on an
  OS without a sandbox backend refuses to start module processes.
- **Coordinator builds** are relocatable: a pinned CPython with the locked dependencies and the SDK, the core compiled
  with Nuitka into one native module (no `.py` shipped), per platform, signed by the owner key set. A move installs one
  on the target (developer mode bundles the running checkout instead). The coordinator runs on macOS and Linux.

## Data roots

| | personal scope | system scope |
|---|---|---|
| macOS | `~/Library/Application Support/Oarbank` | `/Library/Application Support/Oarbank` |
| Linux | `$XDG_DATA_HOME/oarbank` (`~/.local/share/oarbank`) | `/var/lib/oarbank` |
| Windows | `%LOCALAPPDATA%\Oarbank` | `%ProgramData%\Oarbank` |

The coordinator lives in `<root>/coordinator` (`OARBANKD_HOME` overrides it), the agent in `<root>/agent`. Unix sockets
go in `<home>/run`, or a short owner-only directory under `/tmp` when that path would exceed the socket path limit.

## The module sandbox

The contract is the SDK's [spec/sandbox.md](https://github.com/roeehrl/oarbank-sdk/blob/main/spec/sandbox.md); the decisions and threat model
are [module-sandbox.md](module-sandbox.md). In short: read the bundle, write only the job's data and work directories,
no network unless granted, the broker as the only IPC, children inherit the sandbox, and the parent verifies
confinement and fails closed. Grants are whole directories or files, approved per module version by digest.

- **Network** has three modes: `none`, `egress-allowlist` (`host[:port]` entries through the agent's local proxy, which
  refuses IP literals and names resolving to non-public addresses; every other route is blocked) and a separately
  approved full-trust `egress-any`. Loopback and link-local are never reachable.
- **Tools** are ids in the operator's tool registry, mapped to absolute paths per OS (`settings.tools.update`).
- **GPU** is one coarse `compute` device class per backend.
- **Every node reports enforcement per capability** (enforced, cooperative, unavailable) with its backend and ABI; work
  is placed only where every capability it needs is enforced.
- **Bootstrap jobs** ([bootstrap-stages.md](bootstrap-stages.md)) run with less: the module's egress allowlist and their
  work directory, no tools, GPU, containers, module data or settings. The agent narrows them from the signed release's
  module entry and reports `grants.bootstrap`; they run before the module is certified on the node, and the
  coordinator registers their output only when it is exactly the module's pinned datasets.

| Backend | Enforcement | Floor |
|---|---|---|
| macOS | Seatbelt through the launcher's `sandbox-exec`, with a loopback deny and the proxy route | macOS 15 (docs/install.md) |
| Linux | Landlock for the detected ABI (files; TCP connect only to the proxy port from ABI 4; abstract sockets and signals scoped from ABI 6), seccomp (socket families, no listen, ptrace, mounts, namespaces, BPF or keyrings) and no_new_privs, checked through `/proc`; `egress-any` is unavailable | full parity from kernel 6.12 (ABI 6); older kernels report network enforcement unavailable |
| Windows | a per-module AppContainer started by a shim inside the Job Object (ACL grants, `internetClient` only for `egress-any`, loopback isolation); the enforced allowlist needs the elevated helper, a LocalSystem service that exempts one job's container from loopback isolation and filters every loopback port but its proxy | Windows 10 1809 |

## Job control

Every attempt runs in its job container. The runner protocol's control document (`control.json`) carries `stop`,
`pause` and `threads`; after every change the agent nudges the runner (SIGUSR1 to the runner, which starts with it
ignored, on POSIX; on Windows an inheritable auto-reset event, `OARBANK_CONTROL_EVENT`, which the sandbox shim passes
on with the standard handles and nothing else), and runners re-read it only when nudged. Stop writes `stop` and nudges
(plus SIGTERM on POSIX), then kills the container after the runner's `stop_grace_s`. Protection freezes `freeze_ok`
runners through the containers (SIGSTOP of the process group on macOS, `cgroup.freeze` on Linux, suspending the Job
Object on Windows), pauses `cooperative_pause` runners through `control.json`, and lowers jobs through them too
(background QoS on macOS; on Linux the background CPU quota of the container's `run` leaf, below the container that
holds the hard limits; the Job Object's idle priority class and EcoQoS on Windows). Exit codes 2, 3 and 75 count only with a `failure.json`, whose
`fault` (`job`, `host`, `transient`) decides who is charged. A failure spends one of the job's attempts when its end
reason counts against the job; the job is quarantined once no node that could run it has attempts left under its
stage's `retry.max_attempts` (the variant for that node's platform).

Every coordinator time a node acts on is relative: a grant carries `issued_at` next to its deadlines and the agent times
the attempt on its monotonic clock, and move time locks are compared with the coordinator's clock as last seen. A node
clock over 60 s off shows as `CLOCK_SKEW` (protocol.md, "Clocks").

## Network and access

No network is required or assumed (D25): a fleet runs the same on one LAN, over Tailscale, ZeroTier or any VPN.

- **Coordinator identity.** The coordinator identity key (CIK, Ed25519, `<home>/coordinator_key`) signs the identity
  proof agents check before trusting anything (`GET /v1/identity` over a nonce). The proof names the fleet, the epoch,
  the role and the TLS CA's SPKI pin (and a successor's during a rotation).
- **Agent ↔ coordinator: mTLS** (D29). The coordinator's internal CA (P-256, `<home>/tls/`) issues the listener's
  server certificate and every node's client certificate. A node enrolls with a CSR for its own P-256 key (the key
  never leaves the node) and is admitted by the owner (`nodes.admit`) or by a one-time join code; its certificate lasts
  30 days and is renewed in-band. The coordinator stores only certificate fingerprints, so a database leak gives nobody
  a credential; retiring a node clears them. Host names are never checked: the pinned CA is the authentication, so
  LAN addresses, `.local` names and changing addresses all work.
- **Join codes** (`oarbank join-code`) carry the coordinator's addresses, the CA pin and a one-time secret; a node
  enrolling with one is approved at once.
- **People.** Nothing is admin for being local, and identity headers are never trusted. The owner's admin token
  (`<home>/admin.token`, 0600) serves the CLI on the coordinator's own account; console accounts sign in with a
  password plus TOTP, a passkey (WebAuthn) or a one-time link (`oarbank console login`); sessions are HttpOnly and
  SameSite=Strict with a per-session CSRF token; personal access tokens are hashed, expiring and role-capped; roles
  (viewer, operator, admin) are enforced on every operation. Both listeners answer only allowed Host names (DNS
  rebinding), and Tailscale Funnel traffic is refused.
- **The local admin channel** is the admin API on `<home>/run/admin.sock`, whose owner-only directory is the
  credential; the CLI on the coordinator's account uses it without a token. (A Windows named pipe comes when the
  coordinator runs on Windows.)
- **Discovery is a hint, never trust.** The active coordinator advertises `_oarbank._tcp` (dns-sd, Avahi); an agent
  finds it with `oarbank-agent discover` or `run --coordinator discover`, verifies the identity proof, and the owner
  still admits the node. `tailscale status` peers appear in the console as candidates.
- **Ports**: the agent listener 7443 (TLS), the admin API 7401 and the console 7400 on loopback, module frames 7402.
  Agents are outbound-only.
- **Coordinator moves** ([coordinator-move.md](coordinator-move.md)) work across operating systems: the data is
  portable, the standby is installed through the service manager, and file modes are applied on the target, not copied.

## Updates and trust

- **Agent builds follow TUF** (D31): agents built with the vendor root verify an agent build against the vendor's
  metadata, which the coordinator only mirrors (`vendor.metadata.upload`; root rotation, timestamp, snapshot, targets,
  rollback and expiry). `scripts/tuf_vendor.py` manages the vendor's keys.
- **Release signing is on by default** (`OARBANK_RELEASE_SIGNING=0` is developer mode): releases, agent builds and
  coordinator builds carry statements signed by the owner key set, with a rising `seq` against rollback;
  [docs/release-signing.md](../release-signing.md).
- **The launcher owns `current`.** Versions live side by side in `versions/<v>/`; a staged build is checked (sha256,
  signature, platform header, version marker), started on trial, and kept only when it confirms within three starts
  and 600 s, else the launcher flips back and records why. A symlink on Unix, a pointer file on Windows.

## Containers

The agent's container broker is the only way a module reaches a container runtime: images approved by digest, mounts
confined to the job's directories, no other flags; the `containers` pool is sized by the runtime. macOS uses an
agent-owned Colima profile, Linux the host's rootless Podman or Docker Engine (platforms from binfmt: any enabled
handler for x86-64 or AArch64 executables, QEMU's or Rosetta's). Windows has no
runtime yet (planned: an agent-owned WSL2 distribution running Podman).

## Packaging and CI

- **One declarative install plan** (`deploy/install-plan.json`: scopes, home, directories with modes, the join code,
  purge), rendered by `oarbank-launcher setup|remove`. The join code goes to an owner-only file the agent consumes
  and deletes, never into a service definition.
- **Packages:** a macOS pkg (`scripts/package-macos.sh`: universal binaries, Developer ID with hardened runtime or ad
  hoc, a postinstall that runs the install plan; `deploy/macos/oarbank-uninstall`), deb, rpm and a tarball through
  nFPM (`scripts/package-linux.sh`, `deploy/linux`), and a WiX MSI (`scripts/package-windows.ps1`,
  `deploy/windows/oarbank-agent.wxs`; `JOINCODEFILE`, `JOINCODE` or `COORDINATOR`). The coordinator is installed from a
  build by `deploy/oarbankd/install-oarbankd.sh --build`, or by a move.
- **CI** (`.github/workflows/ci.yml`) holds no signing keys: the coordinator suite and the Rust workspace with the agent
  end-to-end tests and the oarbank-core parity tests on macOS, the Rust workspace on Linux and Windows (x64 and arm64
  each), and unsigned packages on tags, which the owner signs: the macOS pkg and coordinator build, deb and rpm for x64
  and arm64, and an x64 and an arm64 MSI.

## Not built yet

- Containers on Windows, and the Windows admin channel (the coordinator runs on macOS and Linux).
- Protection measurements on hardware other than Apple Silicon.
- The apt/dnf repository (its hosting and key are the owner's).
