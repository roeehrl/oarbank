# Containers on macOS: how the runtime comes up

Status: built (agent 2.9.0), to be verified on a real system-install node (checklist at the end). It
changes no protocol: the facts' `containers` gains on macOS the keys Windows already reports
([windows-containers.md](windows-containers.md), "The node's report"), and facts are format 2 and open.

The macOS runtime is the agent's own Colima profiles ([architecture.md](architecture.md), "Containers"):
`oarbank` on Virtualization.framework with Rosetta for every container, and `oarbank-gpu` on krunkit for the
containers of jobs that reserved the `gpu` pool ([gpu-placement.md](gpu-placement.md)). This note says when they come
up, where their state lives, what the node reports, and what the owner must do.

## What 2.8.0 did

Seen on a test fleet of Macs on 2.8.0 (system installs run by `_oarbank`, Colima 0.10.3, Lima 2.2.0, docker
29.8 in `/opt/homebrew/bin`):

- **No Mac reported a runtime.** On Unix the facts' `containers` was only `{"gpu": ...}`, computed from the binaries;
  `oarbank-agent containers doctor` printed the same. A Mac with krunkit reported `"gpu": "virtio-gpu:venus"` because krunkit,
  Colima and docker are installed, with no VM and no way to start one.
- **Every Mac with Colima offered the `containers` pool** (2 to 12 tokens, by the machine) as soon
  as a release wanted containers: `ColimaRuntime::pool_tokens` was the VM's size, whether or not it could run. The
  coordinator would place a module's container jobs there.
- **The VM started only with the first container job**, inside `ensure_started`, and that start could not succeed under
  the system service: `ColimaRuntime.home` was `$HOME`. launchd gives a `UserName` job its account's home, and
  `_oarbank`'s is `/Library/Application Support/Oarbank` (`dscl . -read /Users/_oarbank NFSHomeDirectory`), owned by
  `root:admin` 0755. Colima creates `~/.colima` there first thing and exits fatally (`cannot make required directory`).
  Without HOME the code fell back to `/`, also root's.
- **Finding the tools was not the problem.** `find_bin` already looked in `/opt/homebrew/bin` and `/usr/local/bin`
  whatever PATH was, the agent's launchd plist sets PATH to include both (launchd's own default for a daemon is
  `/usr/bin:/bin:/usr/sbin:/sbin`), and Homebrew's prefix is world-readable on every Mac checked (`/opt/homebrew` 0755,
  `Cellar` 0775). A Colima only in a person's home (one Mac's `~/.local/bin/colima` is a wrapper around the
  Homebrew one) is invisible to `_oarbank`, as it should be.
- **One Mac has no Rosetta** (`/Library/Apple/usr/libexec/oah/libRosettaRuntime` missing, `arch -x86_64` fails), so
  `--vz-rosetta` would fail there and linux/amd64 images cannot run until it is installed. The others have it.

## Can a VM run under `_oarbank`, from a LaunchDaemon?

Yes, as far as the platform goes; this is the part to verify on a node.

- Virtualization.framework needs the `com.apple.security.virtualization` entitlement on the process that creates the
  VM. That process is Lima's `limactl` (Colima drives it), and Homebrew's `limactl` carries it (ad-hoc signed;
  `codesign -d --entitlements - $(readlink -f /opt/homebrew/bin/limactl)` on all three Macs). It is not a restricted
  entitlement, so an ad-hoc signature is enough. The agent itself needs no entitlement.
- VZ does not need a GUI session for a Linux guest. Lima ships exactly this deployment:
  `limactl autostart enable --condition=boot` installs `/Library/LaunchDaemons/io.lima-vm.daemon.<instance>.plist`
  with `UserName` and `LIMA_HOME`, starting the VM at boot before anyone logs in ([Lima, automatic
  startup](https://lima-vm.io/docs/usage/autostart/); `pkg/autostart/launchd/io.lima-vm.daemon.INSTANCE.plist`).
- What a daemon account lacks is a writable home: Colima keeps its configuration in `$COLIMA_HOME` (else
  `$HOME/.colima`), Lima its instances in `$LIMA_HOME` (Colima sets `<colima home>/_lima`), both their caches in
  `$HOME/Library/Caches`. All of that is now in the agent's own home (below).
- macOS limits a socket path to 103 bytes, and Lima's longest is ssh's control socket in the instance directory
  (`ssh.sock.` plus 16 random characters; `limactl create` refuses a longer path). That is why Lima uses `~/.lima`
  rather than `~/Library/Application Support`. `<agent home>/colima` keeps the system install's longest socket at 100
  bytes (`/Library/Application Support/Oarbank/agent/colima/_lima/colima-oarbank-gpu/ssh.sock.<16>`); a personal
  install's `~/Library/Application Support/Oarbank/agent/colima` would not fit, so it keeps Colima in the person's
  `~/.colima` as before.
- Spaces in the path: Lima quotes `ControlPath` and `IdentityFile` in its ssh options and escapes mount points for
  `fstab` (`\040`), so `Application Support` is handled. The krunkit profile's reverse-sshfs mount with a space is
  the least exercised case; the checklist covers it.

Not proven here (no sudo on the nodes, and nothing may be started on them): a VZ VM created by a hidden account with a
uid below 500 (`_oarbank` is 499; Lima makes the guest user with the host's name and uid), and krunkit's Metal
access from a daemon. If either fails, the fallback is below.

## Decision: the agent's own account runs the VMs, from the agent's own home

- **Where:** a personal install keeps Colima in the person's `~/.colima` (its own profiles, never the default one).
  Any other agent home (a system install's above all) keeps it in `<agent home>/colima`: every Colima, Lima and docker
  call gets `HOME` and `COLIMA_HOME` pointing there (Colima honours `COLIMA_HOME` only when the directory exists, so the
  agent creates it 0700), plus `USER`/`LOGNAME`, the helper `PATH` (the directories the tools were found in, then
  Homebrew's and the system's) and the agent's empty `DOCKER_CONFIG`. `--ssh-config=false` keeps Colima out of the
  account's `~/.ssh/config`. Who runs the agent's CLI does not change the choice (root's HOME is `/var/root`).
- **Tools:** `colima`, `docker`, `limactl` and `krunkit` are looked up in `/opt/homebrew/bin`, `/usr/local/bin`, then
  PATH's absolute entries; a tool that exists but the agent's account may not run is reported as such
  (`account_access`), not as absent.
- **Size:** the budget every runtime gets (`sizing`: 8 GB on <= 32 GB Macs, 12 GB up to 96 GB, 32 GB above; 6 or 8
  CPUs), within half the host's memory and its processor count (`wslc::session_size`). Intel Macs get an x86_64 VM
  without Rosetta (2.8.0 asked for aarch64 everywhere, which would have emulated).

### Bring-up

1. No release wants containers: no runtime, no VM. The facts show `state: "absent"` with whatever is missing now,
   so the owner can prepare a node before deploying a container module. At every agent start the previous run's
   state file is removed (its VM may be gone).
2. A release with a module approved for containers arrives (`Agent::container_runtime`): the agent makes both
   profiles (`for_node_mac`, one shared report) and calls `recheck`, which brings the CPU profile up **in the
   background**:
   - check the prerequisites (below); anything missing: `state: "missing"`, each piece with its fix, nothing started;
   - else `state: "starting"`, `colima status oarbank`, and `colima start oarbank --vm-type vz --vz-rosetta --arch
     aarch64 --cpu C --memory M --disk 100 --ssh-config=false --mount <work>:w --mount <modules-data>:w` unless it runs
     (600 s: the first start downloads the VM image into `<colima home>/Library/Caches/colima`);
   - `ready` with its platforms (`linux/arm64`, `linux/amd64`), or `failed` with the exit and the end of the Colima
     log (`logs/colima-oarbank.log`; the report carries the tail because the logs directory is the account's only).
3. Every change is written to `state/containers.json` (what the facts and the GPU probe, a child process, read). The
   agent sees the report change on its next protection tick: it sends its facts again and reruns its doctors, so the
   GPU APIs follow.
4. The `containers` pool is offered **only while the runtime is ready**, as on Windows; a node whose runtime is missing
   something is not offered container work.
5. A release or restart while `missing` or `failed` tries again (`recheck`). A container job whose VM stopped starts it
   again (`ensure_started`).
6. The VM is expected to keep running when the agent restarts or updates (Colima runs in a process group of its own,
   and launchd kills only the job's group when the job exits; checklist item 5); the next agent finds it running and
   is ready at once.

### The GPU profile

The `oarbank-gpu` VM still starts with the first job that reserved the `gpu` pool (a second resident VM of the same size
is not worth it), and its first start proves the device (`/dev/dri/renderD128` in the guest). What changed is what the
node claims before that:

- `containers.gpu = "virtio-gpu:venus"`, `gpu_apis.containers = ["vulkan"]` and the `gpu` pool only while the CPU
  runtime is **ready**, krunkit is installed on Apple silicon, and the GPU profile has not failed. 2.8.0 claimed them
  from the binaries alone.
- `containers.gpu_profile` says `unavailable` (with what is missing: `krunkit`, `apple_silicon`), `on_demand`,
  `starting`, `ready` or `failed` (with why). A failed start withdraws the GPU until the next release or restart.

## The node's report (facts `containers`, macOS)

```json
{"runtime": "colima", "state": "missing", "profile": "oarbank",
 "colima_home": "/Library/Application Support/Oarbank/agent/colima",
 "platforms": [], "gpu": "undetected",
 "missing": [{"what": "rosetta", "detail": "Rosetta 2 is not installed (...)",
              "fix": "install Rosetta 2 as an administrator: `softwareupdate --install-rosetta --agree-to-license`"}],
 "gpu_profile": {"profile": "oarbank-gpu", "state": "unavailable", "missing": [{"what": "krunkit", "...": "..."}]},
 "detail": "only when failed: the exit and the end of the Colima log"}
```

`state` is `absent`, `starting`, `ready`, `missing` or `failed`. `oarbank node list` and `oarbank node show` already
print a runtime's state and each missing piece with its fix (they were written for Windows' report).

| `what` | Means | Fix |
|---|---|---|
| `colima`, `docker`, `lima` | not in `/opt/homebrew/bin`, `/usr/local/bin` or PATH | `brew install colima docker` (Lima comes with Colima) |
| `account_access` | the tool exists but the agent's account may not run it (a prefix in a person's home) | install with Homebrew in `/opt/homebrew` or `/usr/local`, or `chmod o+rx` the custom prefix |
| `rosetta` | Apple silicon without Rosetta 2 (the CPU profile runs amd64 images under it) | `softwareupdate --install-rosetta --agree-to-license` |
| `colima_home` | the agent's account may not write `<agent home>/colima` | give the account its home back (`chown -R`), or reinstall |
| `socket_path` | Lima's longest socket would pass 103 bytes | a shorter agent home |
| `account` | the doctor was run by another account than the one that owns the agent's home | `sudo -u _oarbank /Library/Oarbank/bin/oarbank-agent --home "/Library/Application Support/Oarbank/agent" containers doctor` |
| `krunkit`, `apple_silicon` (in `gpu_profile.missing`) | no GPU in containers | `brew tap slp/krun && brew trust slp/krun && brew install krunkit` |

`oarbank-agent containers doctor` prints the running agent's last report with the prerequisites as they are now
(exit 3 while anything is missing); `--probe` brings the runtime up and runs real containers through it. Run it as the
agent's account: the `_oarbank` home is 0700, and another account's access is not the agent's.

## What the owner does

On each Mac, as the administrator who owns Homebrew:

```bash
brew install colima docker                                  # Colima brings Lima
softwareupdate --install-rosetta --agree-to-license         # Apple silicon, for linux/amd64 images
brew tap slp/krun && brew trust slp/krun && brew install krunkit   # optional: GPU containers
```

Nothing else: no `colima start`, no Docker Desktop, no setting. The agent brings its own profile up when a release
wants containers, in its own home, and the node reports `ready` (or what is still missing) in its facts.

## Fallback if VZ refuses the daemon account: a per-user helper

If the checklist shows Virtualization.framework (or krunkit's Metal) failing for `_oarbank` from a LaunchDaemon, the
VMs move to a person's GUI session the way host protection's session helper does: a LaunchAgent
(`dev.codonic.oarbank.agent.containers`, `LimitLoadToSessionType` Aqua, installed by a system install beside the
session helper) runs `oarbank-agent containers-helper` as that person. It owns the two Colima profiles in
`~/.colima` with the agent's mounts (the agent's work and modules-data directories, which it grants that person read
and write through an ACL for the VM's lifetime), and serves the agent one Unix socket in
`/Library/Application Support/Oarbank/run` that forwards only `start`, `status` and the broker's fixed `docker`
argument shapes to its profile's socket. The agent's report then gains `helper: {user, state}` and a missing piece
`no_session` (no one logged in). The cost is that containers run only while someone is logged in and that the VM is
that person's; that is why it is the fallback, not the design.

## Verify on a real node after the release

On a Mac (system install, Colima and docker in `/opt/homebrew/bin`, Rosetta installed):

1. Before a container release: `oarbank node show <node>` shows `containers: colima absent`, no missing pieces;
   a Mac without Rosetta shows `missing rosetta`.
2. With a container module's release: the facts go `starting` then `ready` within ~10 minutes (first image download);
   `sudo -u _oarbank /Library/Oarbank/bin/oarbank-agent --home "/Library/Application Support/Oarbank/agent"
   containers doctor --probe` passes every check (run, mount, limits, no network, cleanup); `capacity_json.pools`
   shows `containers` only after `ready`.
3. `sudo ls "/Library/Application Support/Oarbank/agent/colima"` holds `oarbank/docker.sock`, `_lima/colima-oarbank`,
   `Library/Caches`; nothing appeared in `/Library/Application Support/Oarbank` itself or in any person's home.
4. An amd64 image runs (a job of a module with an amd64 image; or the probe with `--platform linux/amd64`), so Rosetta
   works in the daemon's VM.
5. Restart the agent (`sudo launchctl kickstart -k system/dev.codonic.oarbank.agent`): the VM keeps running and the
   report is `ready` again within seconds.
6. A Mac with krunkit: `containers.gpu` is `undetected` while `starting`, `virtio-gpu:venus` once `ready`;
   `containers doctor --probe --gpu` starts `oarbank-gpu` and passes `gpu_run` (this is the reverse-sshfs mount with a
   space in its path, and krunkit's Metal from a daemon).
7. If 2 or 6 fail with a VZ or Metal error, take the fallback above.

## Implementation status

- `rust/crates/oarbank-agent/src/colima.rs`: tool lookup, Colima's directories, socket-length check, missing pieces
  with fixes, the report and its JSON, the facts and GPU-API readers, `colima start` arguments, the helper PATH. Plain
  code, tested on every OS.
- `container_runtime.rs`: `ColimaRuntime` with a shared report, `pair`/`for_node_mac`, background bring-up
  (`recheck`), ready-only pool, GPU offered from the report, the environment above.
- `facts.rs`, `gpuapi.rs`: macOS reads the runtime's state file (or what is there now). `agent.rs`: makes the runtime
  with a published report and brings it up; removes a stale state file at start. `main.rs`: `containers doctor`
  overlays the live prerequisites.
- Tests: `colima::tests` (lookup and runnable vs present, directories and socket lengths, each missing piece's fix,
  the report's GPU rule, facts from the state file), `container_runtime::tests` (environment and start arguments,
  GPU device only from a ready runtime with krunkit, pool only when ready, a missing piece stops the bring-up and is
  published to the facts). Live (`--ignored`, `OARBANK_LIVE_COLIMA=1`): the existing tiny-container and Vulkan tests.
