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
| **oarbank-agent** (`rust/crates/oarbank-agent`) | The node agent (D26): enrollment, sessions, staging, jobs in the module sandbox, services and probes (with the endpoints jobs reach a warm service through, [service-endpoints.md](service-endpoints.md)), host protection (`oarbank-protection`, [protection.md](protection.md)), self-update requests, coordinator moves and rescue moves. |
| **oarbank-launcher** (`rust/crates/oarbank-launcher`) | Keeps the agent running under the OS service manager and owns which agent version runs. |
| **oarbank-core** (`rust/crates/oarbank-core`) | The contracts that must match byte for byte: canonical JSON, portable paths, bundle digests and release verification, sandbox policies and profiles, the protection matcher. The SDK's Python code is held to it by parity tests through `oarbank-core-py`. |
| **oarbank-sdk** (`vendor/oarbank-sdk`, Apache-2.0) | The open module contract: manifest, module, runner and service protocols, bundles, the sandbox contract, the conformance kit and the reference modules `toy` and `reel`. The core consumes it, never the other way round. |
| **Modules** | Bundles built on the SDK, installed into the coordinator's store, approved per version by digest. |

## Platforms and the node model

- **Platform tokens** are `<os>-<arch>` with `os` in `darwin`, `linux`, `windows` and `arch` in `arm64`, `amd64`. The
  set is open: an unknown token means "no node of this platform here", not an error. `linux-*` means glibc.
- **Facts.** Every hello carries the node's facts (format 2, the SDK's `spec/platforms.md`): `platform {os, arch,
  os_version, os_build, kernel, distro, libc}`, `cpu`, `memory_gb`, `gpus`, `addresses` and `sandbox.enforcement` per
  capability. Nodes have indexed `platform`, `os` and `arch` columns.
- **Placement.** A module version runs on a node only when its manifest lists the platform (`requires.platforms`), the
  node's OS version is in `requires.os`, every host tool it asks for resolves to an installation the node detected in a
  version it accepts ([host-tools.md](host-tools.md)), the node's sandbox enforces every capability it needs, and the
  agent is recent enough. Each refusal has a
  reason code that `explain` shows, with the module's own reason when it gives one (`requires.unsupported.runner`). A
  stage limited to some platforms runs only there, and so does a job limited to some platforms (jobs.enqueue `platforms`)
  or reading a platform-bound dataset (datasets.create `platform`). A job whose stage needs GPU APIs (the runner's
  `gpu.apis_any` for the node's platform, a GPU service's it reserves) runs only where the node's doctor reports one of
  each (`GPU_API_MISSING`; [gpu-placement.md](gpu-placement.md)).
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
  current release per platform, a release built when a node of a new platform enrolls or the composition changes, and
  only then (a candidate waiting for the owner's signature is not rebuilt on hellos). The candidates the owner must sign
  are named on the console, in an alert and by `oarbank release list` (releases.awaiting); a module's readiness
  checklist (coordinator/readiness.py) walks from install to its first operation. A release holds only the bundle
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
| Meters | rusage, IORegistry GPU time, memory pressure, thermal state, battery | `/proc` (CPU time, run-queue wait from `schedstat`, major faults), DRM `fdinfo` and NVML GPU time, `MemAvailable`, PSI memory pressure, thermal zones, power supplies, physical cores and hybrid core types from sysfs | the process list (CPU time, threads waiting for a core, hard faults), `GlobalMemoryStatusEx` (available memory, the commit charge), the paging files' use, GPU Engine counters, physical cores and efficiency classes, power status |
| Front app | `lsappinfo` | the seat's session from logind: an X11 session's active window (EWMH), a text console's foreground group | the console session from WTS, its foreground window |
| Presence | HID idle, screen sharing (unless the policy's `screen_sharing_present` is off) | systemd-logind's sessions a person is using: an active desktop's idle hint, a text session's terminal input time (logind's, else its processes' controlling terminal); sessions without a terminal (ssh commands), user managers, greeters, background and closing sessions do not count | the sessions WTS lists (logged on, connected, locked), the last input in each person's session (the session helper's, for the system service) |
| Session helpers (the system service) | a LaunchAgent in every GUI login, reporting over `/Library/Application Support/Oarbank/run/session.sock` | a global systemd user unit per person, reporting over `/run/oarbank/session.sock` | started by the elevated helper in each person's session, reporting over `\\.\pipe\oarbank-session` |
| Discovery (browse) | dns-sd | Avahi | `DnsServiceBrowse` |
| Module sandbox | Seatbelt | Landlock and seccomp | AppContainer in a Job Object, plus an elevated helper for the egress allowlist |
| Containers | agent-owned Colima profiles in the agent's home, brought up when a release wants containers: one on Virtualization.framework with Rosetta, and one on krunkit for GPU jobs where krunkit is installed ([macos-containers.md](macos-containers.md)) | rootless Podman, else Docker Engine | an agent-owned WSL containers session (a VM of its own) |

Host protection runs on every OS ([protection.md](protection.md), "On each OS" and "Whose processes"): the rules,
their process trees and triggers, presence, the front app, GPU time, the dynamic controller's measured signals and its
actions on fleet jobs.

## The coordinator

- **`oarbank/platform`** holds every OS-touching helper: owner-only files (POSIX modes; on Windows a protected DACL
  for SYSTEM, Administrators and the coordinator's accounts), the secret store, interpreter paths, process containers
  (a process group; a kill-on-close Job Object on Windows), the local admin channel, the service host and the DNS-SD
  announcement ([windows-coordinator.md](windows-coordinator.md)).
- **The secret store** keeps small secrets out of the database: the login Keychain on macOS, a DPAPI-wrapped file under
  `<home>/keys/` on Windows, an owner-only file there elsewhere (and in tests, `OARBANK_SECRET_STORE=file`). The audit
  signing key lives there, and so does the key that encrypts module secrets.
- **Module secrets** ([secrets-and-signed-images.md](secrets-and-signed-images.md)) are write-only: `secrets.set` takes
  the value beside its params, the `secrets` table holds it AES-256-GCM encrypted, pages and reads show only a keyed
  fingerprint, and only the grant of a job whose stage lists it (resolved per node) or `host.secrets.get` (with
  `secrets:read:self`) carries it. A coordinator move seals each value to the target's transport key.
- **Module processes** run in the OS's sandbox (Seatbelt on macOS; elsewhere through the agent's launcher,
  `bin/oarbank-sandbox` in a coordinator build: Landlock and seccomp, an AppContainer; `sandboxexec.py`), each in a
  process container of its own, with the module's own venv (`python` resolves to the bundle's `.venv`). A coordinator
  on an OS without a sandbox backend refuses to start module processes.
- **Coordinator builds** are relocatable: a pinned CPython with the locked dependencies and the SDK, the core compiled
  with Nuitka into one native module (no `.py` shipped), per platform, signed by the owner key set. A move installs one
  on the target (developer mode bundles the running checkout instead). The coordinator runs on macOS, Linux and
  Windows; on Windows it is a system service with x64 CPython on both architectures (D40).

## Data roots

| | personal scope | system scope |
|---|---|---|
| macOS | `~/Library/Application Support/Oarbank` | `/Library/Application Support/Oarbank` |
| Linux | `$XDG_DATA_HOME/oarbank` (`~/.local/share/oarbank`) | `/var/lib/oarbank` |
| Windows | `%LOCALAPPDATA%\Oarbank` | `%ProgramData%\Oarbank` |

The coordinator lives in `<root>/coordinator` (`OARBANKD_HOME` overrides it), on Windows always in the system scope's
(`%ProgramData%\Oarbank\coordinator`: it is a service there), the agent in `<root>/agent`. Unix sockets go in
`<home>/run`, or a short owner-only directory under `/tmp` when that path would exceed the socket path limit.

## The module sandbox

The contract is the SDK's [spec/sandbox.md](https://github.com/roeehrl/oarbank-sdk/blob/main/spec/sandbox.md); the decisions and threat model
are [module-sandbox.md](module-sandbox.md). In short: read the bundle, write only the job's data and work directories,
no network unless granted, the broker as the only IPC, children inherit the sandbox, and the parent verifies
confinement and fails closed. Grants are whole directories or files, approved per module version by digest.

- **Network** has three modes: `none`, `egress-allowlist` (`host[:port]` entries through the agent's local proxy, which
  refuses IP literals and names resolving to non-public addresses; every other route is blocked) and a separately
  approved full-trust `egress-any`. Loopback and link-local are never reachable.
- **Tools** ([host-tools.md](host-tools.md)) are requests, never paths: a fleet tool definition id (`jdk`, `python`,
  or one an admin defines) with a version constraint and an arch. Each node detects its installations (a JDK from its
  `release` file, other tools by a sandboxed version command), reports them, and grants each module the one
  installation its request resolves to; a path an operator adds that the node did not find travels in the node's signed
  statement and is verified on the node before it is granted.
- **Folders** ([datasets-media-checkpoints.md](datasets-media-checkpoints.md)) are ids too: read-only input folders and
  write-only outboxes, for runners only, mapped to a path per node in the folder registry and delivered to each node in
  its statement (`oarbank.node/v1`), which the owner signs in signing mode; the agent checks each path on the node and grants its canonical
  path (Seatbelt rules, Landlock rules, or entries for a capability SID only the module's runner tokens carry).
- **GPU** is one coarse `compute` device class per backend.
- **Every node reports enforcement per capability** (enforced, cooperative, unavailable) with its backend and ABI; work
  is placed only where every capability it needs is enforced.
- **Service endpoints** ([service-endpoints.md](service-endpoints.md)): a job reaches its module's warm endpoint service
  through a connector the agent hands it, and the service is handed each connection on its own endpoint channel; both
  are inherited, already-connected handles (socketpairs and SCM_RIGHTS on macOS and Linux, pipe handles duplicated into
  a member of the right Job Object on Windows), so no backend rule names a socket or pipe and nothing listens.
- **Bootstrap jobs** ([bootstrap-stages.md](bootstrap-stages.md)) run with less: the module's egress allowlist and their
  work directory, no tools, GPU, containers, module data or settings. The agent narrows them from the signed release's
  module entry and reports `grants.bootstrap`; they run before the module is certified on the node, wherever its runner
  starts, and the coordinator registers their output only when it is exactly the module's pinned datasets.
- **Stage gating** ([stage-gating.md](stage-gating.md)): certification gates only the stages whose results it vouches
  for. A stage that compares nothing (`determinism = "none"`) and needs no capability or pool runs, like a bootstrap
  stage, on any node where the module's runner starts; a failed doctor check named after a capability keeps off only
  the stages requiring that capability; an unmapped host tool keeps off only the stages that need certification.

| Backend | Enforcement | Floor |
|---|---|---|
| macOS | Seatbelt through the launcher's `sandbox-exec`, with a loopback deny and the proxy route | macOS 15 (docs/install.md) |
| Linux | Landlock for the detected ABI (files; TCP connect only to the proxy port from ABI 4; abstract sockets and signals scoped from ABI 6), seccomp (socket families, no listen, ptrace, mounts, namespaces, BPF or keyrings) and no_new_privs, checked through `/proc`; `egress-any` is unavailable | full parity from kernel 6.12 (ABI 6); older kernels report network enforcement unavailable |
| Windows | a per-module AppContainer started by a shim inside the Job Object (ACL grants, `internetClient` only for `egress-any`, loopback isolation); the enforced allowlist needs the elevated helper, a LocalSystem service that exempts the container from loopback isolation and filters its loopback connections to its jobs' proxy ports, each opening for as long as the job's shim runs | Windows 10 1809 |

## Job control

Every attempt runs in its job container. The runner protocol's control document (`control.json`) carries `stop`,
`pause` and `threads`; after every change the agent nudges the runner (SIGUSR1 to the runner, which starts with it
ignored, on POSIX; on Windows an inheritable auto-reset event, `OARBANK_CONTROL_EVENT`, which the sandbox shim passes
on with the standard handles and nothing else), and runners re-read it only when nudged. Stop writes `stop` and nudges
(plus SIGTERM on POSIX), then kills the container after the runner's `stop_grace_s`. Protection freezes `freeze_ok`
runners through the containers (SIGSTOP of the process group on macOS, `cgroup.freeze` on Linux, suspending the Job
Object on Windows), pauses `cooperative_pause` runners through `control.json` (at most 10 minutes, or the node's
`max_pause_s`; then the job is released, after a portable checkpoint when its runner keeps them, so it resumes on any
node: [datasets-media-checkpoints.md](datasets-media-checkpoints.md)), and lowers jobs through them too
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
- **Join codes** (`oarbank join-code`; [node-enrollment.md](node-enrollment.md)) carry the coordinator's addresses,
  its identity key and CA pins, their expiry and a secret; a node checks all of it before it sends the secret. A
  single-use code approves its node at once; a multi-use code (MDM, images) has a use cap and leaves its machines
  waiting for the owner unless it was made to approve automatically. A node joined by address shows a device code the
  owner approves it by (`nodes.admit_code`).
- **People.** Nothing is admin for being local, and identity headers are never trusted. The owner's admin token
  (`<home>/admin.token`, 0600) serves the CLI on the coordinator's own account; console accounts sign in with a
  password plus TOTP, a passkey (WebAuthn) or a one-time link (`oarbank console login`); sessions are HttpOnly and
  SameSite=Strict with a per-session CSRF token; personal access tokens are hashed, expiring and role-capped; roles
  (viewer, operator, admin) are enforced on every operation. Both listeners answer only allowed Host names (DNS
  rebinding), and Tailscale Funnel traffic is refused.
- **The local admin channel** is the admin API on `<home>/run/admin.sock`, whose owner-only directory is the
  credential, and on Windows on the named pipe `\\.\pipe\oarbank-admin-<home id>`, whose owner-only security
  descriptor is (an elevated prompt reaches it); the CLI on the coordinator's account uses it without a token.
- **Discovery is a hint, never trust.** The active coordinator advertises `_oarbank._tcp` (the system responder's API
  in its own process on macOS, Avahi on Linux, `DnsServiceRegister` on Windows), so the announcement ends with the
  coordinator however it ends; an agent finds it with `oarbank-agent discover` or `run --coordinator discover`
  (`DNSServiceBrowse` on macOS), verifies the identity proof, and the owner still admits the node. `tailscale status`
  peers appear in the console as candidates.
- **Local Network privacy (macOS 15 and later).** macOS asks the person before a program uses the local network:
  Bonjour (announcing, browsing, resolving) and connections to addresses on a Wi-Fi or Ethernet network, not listening
  and not VPN or tailnet addresses. It exempts launchd daemons, root and programs started from Terminal or SSH, but not
  LaunchAgents (Apple's TN3179): the coordinator and the agent's personal scope run as LaunchAgents, the system scope
  as a daemon (exempt), and the session helpers use only a local socket. What was measured: on macOS 27.0.1, a
  LaunchAgent whose program is a standalone executable (no app bundle) registered, browsed and connected on the LAN
  with no alert and no refusal, Oarbank's ad hoc signed binaries and fresh ones alike, with or without an embedded
  Info.plist. On macOS 26.6.2 (GitHub's runner, a session no one answers alerts in) the same registration from
  python.org's interpreter, which runs as an app (Python.app, `org.python.python`), was held with no answer, while
  Apple's interpreter, `dns-sd` and a standalone executable built there went through: macOS asks about programs that
  belong to an app. The coordinator build's Python (uv's standalone CPython) and Oarbank's binaries are standalone
  executables; a coordinator run from a checkout on an app-like interpreter (python.org's, Homebrew's) makes macOS ask
  about "Python", and the coordinator logs that the responder has not answered after 10 s. For a macOS that asks about
  standalone programs too (Developer ID–signed ones were not tested), the agent and the launcher (the personal
  LaunchAgent's program, which the agent's requests are attributed to) carry an Info.plist in the binary
  (`__TEXT,__info_plist`) with `NSLocalNetworkUsageDescription` and `NSBonjourServices` (`_oarbank._tcp`): the alert
  names the program and says why, once per person and program, and the answer is kept in System Settings, Privacy &
  Security, Local Network. Bonjour goes
  through the system responder's API, not a `dns-sd` child, so a refusal is reported as one
  (`kDNSServiceErr_PolicyDenied`: the agent's `discover` and the coordinator's log say what to allow) and the request
  is the program's own. `AssociatedBundleIdentifiers` is not set: it ties a LaunchAgent to an app, and Oarbank ships
  none. Where no one can answer an alert, macOS 15.5 and later let an administrator exempt networks
  (`AllowedEthernetLocalNetworkAddresses`, `AllowedWiFiLocalNetworkAddresses` in `com.apple.network.local-network`,
  then a restart); MDM cannot set Local Network privacy, and a join code or tailnet address avoids it.
- **Ports**: the agent listener 7443 (TLS), the admin API 7401 and the console 7400 on loopback, module frames 7402.
  Agents are outbound-only.
- **Coordinator moves** ([coordinator-move.md](coordinator-move.md)) work across operating systems: the data is
  portable (`/` paths, modes recorded rather than read back), the standby is installed through the service manager (on
  Windows by the owner's installer with the pairing code: an agent's account cannot create services), file modes are
  applied on the target, not copied, and the target loads the databases through SQLite's backup API.

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

The agent's container broker is the only way a module reaches a container runtime: images approved by digest, or by
an approved image set (a registry and repository prefix with a pinned cosign key, or a signed index) for images the job
lists, mounts confined to the job's directories, no other flags; the `containers` pool is sized by the runtime. The agent
verifies a set image's signature before the runtime pulls it, offline with the key, through its own small OCI registry
client (`imageset.rs`, on `oarbank-core`'s `images.rs`), and reports each set image an attempt ran so the coordinator
audits each digest's first run ([secrets-and-signed-images.md](secrets-and-signed-images.md)). macOS uses an
agent-owned Colima profile in the agent's own home, started when a release first wants containers and reported in the
facts (`containers.runtime = "colima"`, its state and each missing prerequisite with its fix;
[macos-containers.md](macos-containers.md)), Linux the host's rootless Podman or Docker Engine (platforms from binfmt: any enabled
handler for x86-64 or AArch64 executables, QEMU's or Rosetta's). GPU passthrough: a Linux node with a CDI spec for its
GPU offers the `gpu` pool and runs `gpus = "all"` containers with `--device <kind>=all`, its containers' GPU APIs read
from the spec; a Mac with krunkit runs the containers of jobs that reserved the `gpu` pool in a second agent-owned
Colima VM, `oarbank-gpu`, whose virtio-gpu device gives them Vulkan on the Mac's GPU (`--device /dev/dri`, Mesa's Venus
driver in the image, MoltenVK on the host; `containers.gpu = "virtio-gpu:venus"`; [gpu-placement.md](gpu-placement.md)).
Windows uses a WSL containers (WSLc) session the agent creates through the WSLc SDK and drives with `wslc.exe`
([windows-containers.md](windows-containers.md), D39): its own name, storage, VM size and settings, no host loopback,
Windows paths mounted as they are, its host's architecture only, and GPU-PV through the CDI spec its guest writes
(`cdi:microsoft.com/wslc`; container APIs `directml`, and `cuda` with NVIDIA's WSL library). The broker's endpoint there
is a named pipe only the agent's account and the module's AppContainer may open.

## Packaging and CI

- **One declarative install plan** (`deploy/install-plan.json`: scopes, home, directories with modes, the join code,
  purge), rendered by `oarbank-launcher setup|remove`. Packages install the node unjoined; `oarbank-node join` (the
  launcher under a second name) checks a code and stages it in an owner-only file the waiting service consumes and
  deletes, never in a service definition or on a command line. The agent reports joining and its session in a status
  document every front end reads ([node-enrollment.md](node-enrollment.md)).
- **Packages:** a macOS pkg per architecture (`scripts/package-macos.sh`: `-macos-arm64.pkg` and `-macos-x86_64.pkg`,
  Developer ID with hardened runtime or ad hoc, the interpreters that run module code with library validation off
  ([release-signing.md](../release-signing.md#macos-code-signatures)), a postinstall that runs the install plan;
  `deploy/macos/oarbank-uninstall`), deb, rpm and a tarball through
  nFPM (`scripts/package-linux.sh`, `deploy/linux`), and a WiX MSI (`scripts/package-windows.ps1`,
  `deploy/windows/oarbank-agent.wxs`; a join page, or `JOINCODEFILE`, `JOINCODE`, `COORDINATOR` silently). Coordinator builds from
  `scripts/build-coordinator.sh` / `.ps1` are wrapped in software-only native `.pkg`, `.deb`/`.rpm`, and `.msi`
  installers by `scripts/package-coordinator-*`. Their application launcher opens the local browser setup wizard;
  submitting configures per-user LaunchAgents/systemd services or Windows services under virtual accounts, then
  initializes the admin account, TOTP and primary/backup owner signing keys. Windows calls its Start shortcut
  **Oarbank coordinator setup** and requires Windows 11 on ARM64 for bundled x64 Python; see
  [installation requirements](../install.md#windows-coordinator). Bundled helpers accept an installed
  payload through `--installed` / `-Installed`. Advanced archives use `--build` / `-Build` and remain the signed move
  format.
- **CI** (`.github/workflows/ci.yml`) holds no signing keys: the coordinator suite and the chaos tests on macOS and
  Windows (x64 and arm64), the Rust workspace with the agent end-to-end tests and the oarbank-core parity tests on
  macOS, the agent end-to-end tests on Windows (x64 and arm64), the Rust workspace on Linux and Windows (x64 and arm64
  each), the Windows container runtime against a real WSL containers session (x64), and unsigned packages on tags,
  which the owner signs: the arm64 and x86_64 macOS agent pkgs, the arm64 coordinator pkg and archive, agent and
  coordinator deb/rpm packages and archives for amd64 and arm64 Linux, agent and coordinator MSI packages for x64
  and ARM64 Windows, and the Windows coordinator archives. Coordinator package jobs smoke-test software-only
  installation and retained-data removal on disposable Linux and Windows runners. `.github/workflows/msi.yml` installs the agent MSI for real on a throwaway Windows
  runner whenever the package or what it installs changes, and on every tag: both services with their accounts and
  start types, the elevated helper's openings across a major upgrade, and an uninstall that leaves nothing behind
  (`scripts/ci-windows-msi.ps1`). Its manual coordinator fixture also checks repair after wizard-owned services are
  created, restart across a major upgrade, and removal that preserves fleet data.
- **Native files are checked against the architecture they run as.** Agent packages and POSIX coordinator packages
  contain native files for the platform named in the filename (spec/platforms.md): the Rust binaries are built for its target,
  the interpreter is python-build-standalone's build for it (uv requests name the architecture), the wheels are the
  ones that interpreter asks uv for, and uv is its release for that platform, pinned by hash (`scripts/fetch-uv.py`,
  the version CI builds with), which does the installing (uv writes Windows console-script launchers for its own
  architecture). Coordinator builds ship that uv too, first on the services' PATH, for module dependencies.
  Windows ARM64 coordinators bundle x64 CPython, wheels and the compiled core under Windows 11 emulation, alongside
  ARM64 module launchers, uv and console-script launchers; validation checks each tree against its architecture.
  `scripts/check-package.py --platform` reads every Mach-O (thin or universal), ELF and PE file and every object of a
  static or import library in what a build ships, and refuses one without code for the platform (an x64 header over
  Arm64EC code, as in Microsoft's Arm64 runtime libraries, counts as Windows on Arm); its run check then loads every
  extension module from a moved copy, on the package's platform. Building for another architecture than the build
  machine's runs that architecture's code: Rosetta 2 on Apple silicon for x86_64, Windows on Arm's emulation for x64.
  What a release builds:

  | Artifact | Built on | Native files |
  |---|---|---|
  | `oarbank-agent-<v>-macos-arm64.pkg`, `oarbank-agent-<v>-darwin-arm64` | macos-26 (arm64) | arm64: agent, launcher, CPython, extension modules, uv |
  | `oarbank-agent-<v>-macos-x86_64.pkg`, `oarbank-agent-<v>-darwin-amd64` | macos-26, Rosetta 2 | x86_64: the same |
  | `oarbank-coordinator-<v>-macos-arm64.pkg`, `oarbank-coordinator-<v>-darwin-arm64.tar.gz` | macos-26 | arm64: setup app, CPython, wheels, the Nuitka module, uv |
  | `oarbank-agent_<v>_<arch>.deb`, `oarbank-agent-<v>-1.<rpm-arch>.rpm`, `oarbank-agent-<v>-linux-<arch>.tar.gz` | ubuntu-24.04 (amd64), ubuntu-24.04-arm | the runner's: agent, launcher, CPython, extension modules, uv |
  | `oarbank-coordinator-<v>-linux-<arch>.tar.gz`, `.deb`, `.rpm` | the same | the runner's: CPython, wheels, the Nuitka module, module launcher, uv |
  | `oarbank-agent-<v>-windows-<arch>.msi` | windows-2025 (x64), windows-11-arm | the MSI's: agent, launcher, `wslcsdk.dll`, CPython, extension modules, uv |
  | `oarbank-coordinator-<v>-windows-<platform-arch>.tar.gz`, `oarbank-coordinator-<v>-windows-<msi-arch>.msi` | the same | x64 CPython, wheels and Nuitka module; the platform's module launcher, uv and console-script launchers |

  Linux filenames use `amd64`/`arm64`, with `x86_64`/`aarch64` in agent rpm names. Windows archive platform names
  use `amd64`/`arm64`; MSI names use `x64`/`arm64`. Published Linux binaries require glibc 2.39 or newer.

  There is no universal macOS pkg. A universal one would fuse two python-build-standalone builds and two sets of
  wheels with `lipo`: PyPI's wheels for the runtime's dependencies are per architecture, so every extension module
  would be a file no upstream ships or tested, their wheel metadata (`RECORD` hashes, `WHEEL` tags) would no longer
  describe them, the build configuration exists once per architecture, and every Mac would carry both halves (about
  twice the runtime). Two native pkgs hold exactly what upstream builds for each architecture, each checked against
  one platform and run on it; each refuses a Mac of the other architecture (its distribution's `hostArchitectures` and
  an installation check, so an Apple silicon Mac is not offered Rosetta 2 for the Intel package). The agent binary
  for the update channel is per platform as on Linux and Windows. The macOS coordinator build stays arm64 only.
- **A package names nothing of the machine that built it.** Every package build runs `scripts/check-package.py` on
  what it ships: no link out of the tree (on Windows no reparse point at all), no path of the build (the checkout, its
  work directories, the build account's home, `CARGO_HOME`) in any file, metadata, bytecode and binaries included, and
  the bundled interpreter runs from another directory. What it found and the builds now do: the interpreter is uv's
  managed CPython copied as files of its own (`scripts/bundle-python.*`: never the checkout's `.venv`, which `uv python
  find` returns first, nor uv's link), without the bytecode this machine wrote into uv's store, with its build
  configuration and (macOS) its library naming nothing of the store; nothing the build runs writes bytecode, and all
  of it is compiled afresh with relative paths and hash checks; uv's `direct_url.json` for the SDK is dropped; Rust
  binaries name `CARGO_HOME` as `/cargo` (`--remap-path-prefix`) and Windows binaries their debug database by file
  name; the Nuitka module loses its debug information and (macOS) its build-directory install name; the coordinator
  archive names no owner (`scripts/pack-tar.py`).

## Not built yet

- Protection measurements on hardware other than Apple Silicon.
- The apt/dnf repository (its hosting and key are the owner's).
