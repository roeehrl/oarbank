# The coordinator on Windows

**Status (2026-10-04):** design for the third 2.5.0 gap: oarbankd, its console and the admin CLI run on Windows, as a
Windows service, so the core suite and the coordinator-backed end-to-end tests (`tests/rust`) run on Windows locally
and in CI. Decision **D40** in [PLAN.md](PLAN.md). Versions stay core 2.5.0 / SDK 1.5.0 (unreleased); no manifest key,
protocol field or schema changes. The SDK gains one helper (`portable.os_env`) and a corrected platform probe.

## The problem

The coordinator ran on macOS and Linux only. Its OS-touching code assumed POSIX in places that fail on Windows or,
worse, pass while doing something else:

- **Process groups.** Module processes started with `start_new_session` and died with `os.killpg`. Windows has
  neither, and a process tree outlives its parent unless something holds it.
- **The confinement check** asked the agent binary (`oarbank-agent sandbox-check PID`) whether a module process was
  confined. On Windows that reads the members of the shim's Job Object from the *checking* process's own job table,
  which is empty, so every module process was judged unconfined and refused. The coordinator never put the shim in a
  job at all.
- **The module environment** was `PATH=/usr/bin:/bin` and `HOME`. A Windows program needs `SystemRoot` to start, and
  `CreateProcess` for an AppContainer fails with error 203 without `LOCALAPPDATA`.
- **Owner-only files.** `chmod 0600`/`0700` does nothing useful on Windows (it toggles the read-only attribute). Keys,
  tokens and the database inherited whatever their parent allowed; the signing key check read `st_mode` and refused
  every key (`0o666`).
- **Read-only blobs.** `chmod 0444` set the read-only attribute, after which `os.replace` and `unlink` fail on
  Windows: stored agent builds, blobs and checkpoints could no longer be renewed or collected.
- **The local admin channel** is a Unix socket; CPython on Windows has no `AF_UNIX`.
- **Releases and move manifests** were built from the filesystem: modes read back with `stat` (Windows keeps none,
  so every release from a Windows coordinator would have lost its executable bits and changed its id) and relative
  paths written with `str()` (backslashes on Windows, so a move from Windows to macOS would have created files named
  `blobs\ab\ab12…`). Text files were read and written in the locale's code page with CRLF line ends.
- **Moves** replaced the database file under open connections (`os.replace`). Windows refuses to replace an open file;
  on POSIX the console kept reading the replaced inode until it restarted.
- **Service management** was launchd and systemd only; the coordinator could not be installed as a service.
- **Restart semantics** relied on the service manager reading the exit code (`os._exit(75)`: restart on the installed
  copy; `os._exit(0)`: a finalized coordinator stays down). The Windows service control manager treats any process
  that ends without reporting a stop as crashed, whatever the code.
- **Discovery** advertised through `dns-sd` or Avahi only.

## Decisions

1. **Windows is a coordinator platform**: `windows-amd64` and `windows-arm64`, Windows 10 1809 / Server 2019 or later
   (the agent's sandbox floor, D30). A module's `requires.coordinator_platforms` decides per module as before.

2. **One x64 interpreter on both architectures.** The coordinator's `cryptography` dependency publishes no Windows on
   Arm wheels, so the coordinator build and the test environments use x64 CPython, which Windows on Arm runs under its
   x64 emulation. The coordinator still reports the machine's platform: `oarbank_sdk.portable.host_platform` reads the
   native architecture (`IsWow64Process2`) rather than the interpreter's, so a Windows on Arm coordinator is
   `windows-arm64`, as its agent says. A module's coordinator side there installs x64 wheels (its interpreter's).

3. **Process containers** (`platform/procs.py`, used for every module process, the sandboxed dependency install and
   module CLIs). POSIX keeps its new session and process-group kill. On Windows a module process is born in a Job
   Object of its own: started suspended, assigned, then resumed (Toolhelp's thread list), with
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and without breakaway, and with no console at all (`DETACHED_PROCESS`), since a
   console, even a hidden one, puts a `conhost.exe` in the job outside the AppContainer. Only oarbankd holds the job's
   handle, so the tree also dies with oarbankd, however it ends. Closing a container waits for its processes to end
   (a running process holds its files and working directory open). This is the agent's container on Windows
   (`sys.rs` `new_group` and `contain`), in the coordinator.

4. **The module sandbox on a Windows coordinator** is the agent's AppContainer launcher, as Linux uses the agent's
   Landlock launcher (`bin/oarbank-sandbox` in a coordinator build, `sandboxexec.py`): a per-module AppContainer
   (`Oarbank.coordinator.<module id>`, never the node's `Oarbank.<module id>`: a container's named objects live in one
   directory per session, owned by the account that first started it, and on a coordinator that is also a node the
   agent's and the coordinator's services both run in session 0, so sharing a container would refuse whichever came
   second; module CLIs use `Oarbank.cli.<module id>`), started by the `sandbox-exec` shim inside the coordinator's Job
   Object. What it enforces for
   a coordinator process (policy `kind = "coordinator"`, `net = "none"`): files through ACL entries for the container's
   SID (read and execute on the bundle, the interpreter and the import roots; full access to
   `<home>\modules\data\<name>` and `<home>\tmp\modules\<name>`; anything else only where Windows grants every
   AppContainer, the system directories); no network (no `internetClient`, and loopback isolation keeps it off the
   admin and agent listeners); no named objects outside the container's namespace (pipes, sections, the admin pipe
   included); children inherit the container and cannot break away from the job. **The confinement check reads the job
   in oarbankd** (it holds the handle): the shim is the first member, and every other member must run with an
   AppContainer token (`TokenIsAppContainer`), and there must be one, checked after the handshake. The agent's
   `sandbox-check` subcommand, which could not see the job, is removed. Not enforced on Windows, and not needed by
   coordinator processes: `exec_writable_deny` (needs application control). A module CLI (`oarbank cli`) is limited to
   the admin API's loopback port through the elevated helper (`OarbankHelper`, which the agent's MSI installs); without
   it the CLI refuses to start, as Linux refuses without Landlock's network rules.

5. **The module environment comes from one SDK function**, `portable.os_env(home, tmp)`, the table in the SDK's
   spec/platforms.md ("Environment per OS"), which the conformance kit, the kit's service runner, the coordinator's
   module processes, the dependency install and module CLIs all use. An AppContainer start points `LOCALAPPDATA`,
   `TEMP` and `TMP` at the container's folder below the given `LOCALAPPDATA`, which Windows creates only under a
   profile's own (with a made-up `LOCALAPPDATA`, uv found no temporary directory). The first build kept the host
   account's `LOCALAPPDATA` for it; now the home's own is used everywhere and the module launcher creates the folder
   (module-sandbox.md, "A runner's home").

6. **Owner-only files** (`platform/files.py`). On Windows "owner-only" is a protected DACL (nothing inherited)
   granting full control to SYSTEM, Administrators and the writing account, and inside the coordinator's home also the
   two coordinator service accounts (decision 8), whoever writes it (an owner running a rescue in an elevated prompt
   writes files the service must read). Files are created with that descriptor (`CreateFileW` with security
   attributes), never given it after the fact; directories pass it on. `owner_only(path)` (every allow entry names a
   trusted account) replaces the `st_mode` checks: signing keys are refused unless owner-only, and `tighten_home`
   repairs the home and its secrets as it does on POSIX (a repaired file drops its own entries and inherits the home's).
   Administrators are trusted because an elevated administrator can take ownership of anything anyway, as root can
   read anything on POSIX; it is what lets the CLI in an elevated prompt read the admin token.

7. **Sealed files.** Stored blobs, agent and coordinator builds, module files and the hand-off marker are sealed with
   `files.seal`: `0444`/`0555` on POSIX; on Windows nothing, since the read-only attribute is no access control there
   (the home's DACL is) and would stop the file being replaced by a rename or deleted.

8. **A Windows service, run by its own virtual account** (`platform/service.py`). oarbankd and the console are two
   services, `dev.codonic.oarbank.oarbankd` and `dev.codonic.oarbank.console`, each run by its virtual account
   (`NT SERVICE\<name>`, as the agent's service is), started at boot (Automatic, Delayed Start) and restarted by the
   recovery actions 10 s after a crash or a failed exit (`sc failure … restart/10000/restart/10000/restart/60000`,
   `sc failureflag 1`), as launchd's `KeepAlive.SuccessfulExit = false` and systemd's `Restart=on-failure` do. They run
   `python.exe -I bin\oarbankd.py --service` (and `bin\oarbank-console.py --service`; two-line launchers, as the
   POSIX builds' `bin/oarbankd` is a shell script, since the compiled core cannot run as `python -m`): `--service`
   hands the process to the service control dispatcher (ctypes; no pywin32), reports running, turns stop and shutdown controls into
   uvicorn's graceful exit, sends the output to `<home>\logs\oarbankd.log` (`console.log`), and reports the exit code
   when the process ends. Every deliberate exit goes through `service.exit_now(code)`, which reports the code first:
   75 (a standby restarting on the copy a move installed) is a service-specific error the recovery actions answer with
   a restart; 0 (a finalized old coordinator) stays stopped. On macOS and Linux `exit_now` is `os._exit`.

9. **The coordinator's home on Windows is `%ProgramData%\Oarbank\coordinator`** (`paths.coordinator_home`), always:
   the coordinator is a system service there, and the CLI in an elevated prompt finds the same home. The installer
   creates it with a protected DACL for SYSTEM, Administrators and the two service accounts (named by SID: a virtual
   account's SID is S-1-5-80 and the SHA-1 of the upper-cased service name, known before the service exists). The
   programs live in `%ProgramFiles%\Oarbank\Coordinator\<version>-<sha12>`, writable only by administrators (a
   service cannot rewrite its own code), with `current` a directory junction to the running one.

10. **The coordinator build is the package on every OS.** `scripts/build-coordinator.ps1` builds
    `oarbank-coordinator-<v>-windows-<arch>.tar.gz` with the same layout and manifest as the POSIX builds (x64 CPython,
    the locked dependencies, the SDK, the core compiled with Nuitka into one `.pyd`, `bin\oarbank-sandbox.exe`,
    `bin\uv.exe` for module environments, and per program a launcher and a `.cmd` for people; the manifest's `exec`
    is `python/python.exe -I bin/oarbankd.py`, since a service needs a program). `deploy/oarbankd/install-oarbankd.ps1`
    installs it, as `install-oarbankd.sh` does on macOS and Linux: unpack, move `current`, (re)create the services with
    their environment (`OARBANKD_HOME`, `OARBANK_RELEASE_SIGNING`, a `PATH` with the build's `bin`), the home's DACL,
    and an inbound firewall rule for the agent port scoped to the oarbankd service; running it again with a newer
    build is the upgrade (the services stop, `current` moves, they start; modules' environments made on the previous
    build's interpreter are rebuilt at start, `modlife.runtimes_ok`). `-Uninstall` removes the services, the rule and
    the programs and keeps the home. Not an MSI: the coordinator is one machine the owner sets up, moves install the
    same archive, and one archive with one installer per OS family keeps a single format.

11. **The local admin channel on Windows is a named pipe** (`platform/localchannel.py`, `_winpipe.py`):
    `\\.\pipe\oarbank-admin-<sha256(home)[:12]>`, created with the owner-only descriptor (SYSTEM, Administrators,
    which an elevated prompt carries, and the coordinator's accounts), as the first instance
    (`FILE_FLAG_FIRST_PIPE_INSTANCE`: if anyone created the name first, oarbankd fails to serve it rather than talk to
    them), byte mode, `PIPE_REJECT_REMOTE_CLIENTS`. Without the right to create instances nobody else can add one to
    listen in. uvicorn serves it on asyncio's proactor (an instance waits for a client, each client gets its own duplex
    transport); the CLI reaches it through an httpx transport that opens the pipe. A non-elevated prompt cannot open
    it and the CLI falls back to the admin token over TCP, which it also cannot read: the same split as the coordinator's
    account and every other account on POSIX.

12. **Discovery** announces through `DnsServiceRegister` on Windows (`platform/dnssd.py`; Windows 10 1903 and later,
    the API the agent browses with; before that nothing is announced, and discovery is only a hint).

13. **Portable data.** Everything a coordinator writes for another machine is independent of the coordinator's OS:
    release archives carry the modes the release records, never modes read back from the filesystem, with `/`
    paths sorted as before (release ids stay the same); a checkout bundle carries git's recorded modes; move manifests
    and their file lists use `/`; text files are written as UTF-8 with LF line ends and read as UTF-8.

14. **A move installs the copy without replacing open files.** The standby puts each database's content in place with
    SQLite's backup API into its own file, which oarbankd and the console keep open; Windows cannot replace an open
    file, and elsewhere the console would have kept reading the replaced one. Files are still renamed into place.

15. **Moves to and from Windows.** From Windows: nothing new, the old side's endpoints serve the same manifest and
    snapshots. To Windows: the target is a standby installed by the owner, `install-oarbankd.ps1 -Pair <code> -From
    <url> -FromCa <pin>` (the runbook's path for a target that is not an enrolled node). An enrolled Windows node's
    agent runs under an unprivileged virtual account, which cannot create services, so its `install_coordinator`
    refuses with that instruction instead of installing something that would not survive a reboot; the elevated helper
    is not given a "install a service from this bundle" operation, which would let a compromised agent install code as
    a service. (The agent's `OARBANK_SERVICE_HOST=process` test host works on Windows, so the end-to-end move tests run
    there.)

16. **The secret store** on a Windows coordinator is DPAPI for the service's virtual account (its profile is under
    `C:\Windows\ServiceProfiles`). Like the Keychain, its keys never move: a move seals module secrets to the target's
    transport key and the target makes its own audit key (coordinator-move.md).

17. **SQLite** runs in WAL mode on Windows as elsewhere (its Windows VFS locks with `LockFileEx`); the coordinator's
    one-writer lock and the read-only connections are unchanged. Paths stay well under 260 characters in the default
    layout (the deepest, a module environment's extension modules, is about 140), so long paths are not required.

18. **The coordinator says where and how it runs** (`coordinator/hostinfo.py`): its platform, what its service
    manager reports about the coordinator's two services (launchd's `launchctl print`, systemd's `systemctl --user
    show`, the service control manager's status and configuration: installed, state, start type, account, process),
    whether this process is the one the manager runs, and its module sandbox; on Windows also the elevated helper's
    service and whether module CLIs' allowlists are enforced. oarbankd takes it at start and at every
    `GET /api/v1/coordinator` (no polling: nothing else changes it), keeps the last one in the setting
    `coordinator_host`, and `oarbank coordinator status` and the console's Coordinator page show it (the console, a
    read-only process, shows the time it was taken).

## Per OS, after this change

| | macOS | Linux | Windows |
|---|---|---|---|
| Service | LaunchAgents (`install-oarbankd.sh`) | systemd user units | two services, virtual accounts (`install-oarbankd.ps1`) |
| Home | `~/Library/Application Support/Oarbank/coordinator` | `~/.local/share/oarbank/coordinator` | `%ProgramData%\Oarbank\coordinator` |
| Owner-only | modes 0600/0700 | modes 0600/0700 | protected DACL: SYSTEM, Administrators, the coordinator's accounts |
| Module container | process group | process group | Job Object, kill-on-close, no breakaway |
| Module sandbox | Seatbelt | Landlock and seccomp (agent launcher) | AppContainer (agent launcher) |
| Confinement check | `sandbox_check` | `/proc/<pid>/status` no_new_privs and seccomp | job members' tokens |
| Local admin channel | Unix socket, owner-only directory | same | named pipe, owner-only descriptor |
| Secret store | Keychain | owner-only file | DPAPI (the service account) |
| Discovery | dns-sd | Avahi | DnsServiceRegister |
| Restart after exit 75 | launchd | systemd | recovery actions |

## Threat model (Windows)

| Threat | Defence |
|---|---|
| Another local account reads the database, keys or admin token | The home's protected DACL admits SYSTEM, Administrators and the two service accounts; `tighten_home` repairs it at every start; signing keys are refused unless owner-only. |
| Another account squats the admin pipe's name to collect requests | oarbankd creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` and fails if the name exists; only trusted accounts may create further instances. |
| A non-elevated process or a remote client uses the admin pipe | Its DACL admits Administrators only through an elevated token, and remote clients are refused. |
| A module process escapes its container or survives oarbankd | Born in a kill-on-close job without breakaway; any member outside an AppContainer fails the confinement check; the job dies with oarbankd's handle. |
| A module reaches the network or the admin API | No `internetClient`; loopback isolation. A module CLI reaches only the admin port, through the elevated helper. |
| A compromised agent on the target installs a service | Agents do not install coordinator services on Windows; the owner runs the installer. |
| The service rewrites its own programs | They live in Program Files, writable by administrators only. |
| The firewall rule opens more than the agent port | It names the port and the oarbankd service. |

Residual: an elevated administrator can read everything (as root can on POSIX); the x64 interpreter on Windows on
Arm runs under emulation, which is Microsoft's code path, not ours.

## Testing and CI

- The whole core suite (`pytest -m "not chaos"`), the chaos tests and `tests/rust` run on Windows: on the Windows 11
  arm64 VM, and in CI on `windows-2025` (x64) and `windows-11-arm`.
- CI: `coordinator` gains a matrix over `macos-26`, `windows-2025` and `windows-11-arm` (pytest-xdist splits the suite;
  the agent binary the suite confines module processes with comes from the Rust cache); the Windows jobs also install
  the elevated helper from the launcher they build (as the MSI does), so module CLIs and egress allowlists are tested
  enforced. A `windows-e2e` job runs `tests/rust` on both Windows runners, as the macOS `agent` job does. uv stays
  pinned at 0.12.22.
- Tests that cannot apply on Windows skip with a precise reason (the list is in "Implementation status").

## Acceptance tests

1. `uv run pytest -q -m "not chaos"`, `-m chaos` and `tests/rust` pass on the Windows VM and on both Windows runners.
2. Module processes on a Windows coordinator run in an AppContainer inside a kill-on-close job, and a process outside
   the container fails the check (`test_module_sandbox`, `test_windows_coordinator`).
3. Owner-only files, keys and the home's repair hold on Windows (`test_access`, `test_signing`, `test_secrets`).
4. The admin pipe serves the CLI without a token and refuses others (`tests/rust/test_local_admin`).
5. The service host reports running, stops on a stop control and reports exit codes (`test_windows_coordinator`,
   against the real service control manager on the runner).
6. The installer installs from a build, the services run, an agent enrolls and a module's jobs run, the coordinator
   survives a restart and an upgrade (manual on the VM; the installer's dry run is checked in CI).
7. A move from macOS or Linux to Windows and back (manual across the Mac and the VM; the move protocol itself is
   covered by `test_coordinator_move`, `tests/rust/test_agent_move` and `test_agent_coordinator_install`, which carries
   a module across, on every OS).
8. The coordinator reports its platform, its services' state and on Windows the helper's (`test_coordinator_host`,
   with the service control manager's answer for a real service on Windows).

## Open questions

- A native arm64 interpreter once `cryptography` ships Windows on Arm wheels (or the build compiles it).
- Whether the elevated helper should be part of the coordinator's install when no agent is installed beside it (today
  `oarbank cli` asks for the agent's MSI there).

## Implementation status

Built as designed, with these additions found on the way:

- **Role containers** (decision 4): the first build ran the coordinator's module processes in the node's
  `Oarbank.<module id>` container; on the VM, once the coordinator service had run a module, the agent beside it could
  no longer start that module (Access denied in session 0). The agent's `sandbox-exec` now names the container by role.
- **The build's own launcher**: a Windows build keeps `python.exe` in `python\`, not `python\bin\`; `sandboxexec.launcher`
  looks beside `python\` too (it found none and refused every module process of a standby's verification).
- **Launchers, not `python -m`**: Nuitka's compiled package has no code objects for `runpy`, so a build's programs run
  through two-line launchers (`bin\oarbankd.py`), as the POSIX builds run a shell script.
- **The machine's architecture**: x64 PowerShell under emulation reports AMD64 in `PROCESSOR_ARCHITECTURE` and .NET;
  the build script and the installer read the system's environment instead, and the SDK's `host_platform` asks
  `IsWow64Process2`.
- **A managed Python's real prefix**: uv names its interpreters through junctions, and copying a junction left a "copy"
  whose installs landed in the shared interpreter; the build copies `realpath(sys.base_prefix)` and refuses a link.
- **Environments the module sandbox reads are copies.** uv hard-links files from its cache by default, and a linked
  file keeps the cache's protected DACL, which the sandbox's inheritable grant on `site-packages` never reaches: a
  module process could not read the editable SDK's `.pth` and found no `oarbank_sdk`. The agent's checkout install
  (`uv sync`) and CI set `UV_LINK_MODE=copy` on Windows, as the coordinator's and the agent's dependency installs do.
  It showed only on the arm64 runner: the x64 runner's workspace is on another volume than uv's cache, so uv copied.
- **The admin pipe's client** opens it with `CreateFileW`: Python's `open()` goes through the C runtime, which reports
  a busy pipe (one instance being served, the next not made yet) as EINVAL, so a client could not wait for it and the
  CLI took a running coordinator for gone (seen on CI). Its server makes the next instance before it closes one whose
  client left, so the name always has one.
- **Releases and moves** were made OS-independent (decision 13); the move's database install uses the backup API
  (decision 14). A module environment rebuilt in place is deleted with `files.remove_tree`, which retries for up to a
  minute an executable Windows will not delete (nor its directory rename) while Defender scans it after it was written
  or run: a tenth of a second on an idle machine, 29 to 38 s with every core of a 4-core VM busy, with nothing to wait
  on. Before, the rebuild found half an environment and failed; it matters after a move, which writes the environment
  just before oarbankd rebuilds it.
- **Tests and the suite**: module hosts a test file opened end with it (their processes held files open on Windows);
  the simulator closes its module host before deleting its home; the e2e tests give their nodes no memory reserves
  (an 8 GB VM with an unknown presence reserved more than it had), build the agent versions they need in one target
  directory, stop a launcher's whole process tree, and read `current` links as pointer files on Windows; liveness
  checks never call `os.kill(pid, 0)`, which ends the process on Windows. The chaos test and the swarm harness that read a database
  right after terminating its coordinator wait for Windows to release that process's file locks (LockFileEx: "the
  time it takes depends upon available system resources"). CI splits the suite with pytest-xdist.

**Verified.**
- Windows 11 arm64 VM (x64 CPython under emulation): the core suite 646 passed, 8 skipped (below); `-m chaos` 6 passed;
  `tests/rust` 24 passed, 5 skipped (below); the Rust workspace's tests; the coordinator build (`scripts\build-coordinator.ps1`, 59 MB) built,
  installed with `install-oarbankd.ps1` as two services under their virtual accounts with the home's DACL, enrolled a
  Windows agent and a macOS agent, ran toy campaigns on each and on both, survived a service restart and two upgrades
  (2.5.0 to 2.5.1 to 2.5.2, side by side, `current` moved), and reported its services from the service account
  (`oarbank coordinator status`). A move from a macOS coordinator to the Windows service (installed with `-Pair`) and
  back to macOS committed at epochs 2 and 3, both agents following each time, with the campaigns' history intact.
  The signed move installed the real compiled Windows build through the agent's process host.
- macOS: the core suite 644 passed, 10 skipped; chaos 6 passed; `tests/rust` 27 passed, 2 skipped; the Rust workspace
  (clippy and tests); the SDK's suite 435 passed, 4 skipped.
- Linux (Lima, arm64): the core suite 629 passed, 12 skipped and chaos 6 passed (before the rebase on main); clippy
  and the Rust workspace's tests (323 passed, 16 ignored).

**Skipped on Windows, and why.**
- `test_packaging`: three tests of `install-oarbankd.sh` (Windows has `install-oarbankd.ps1`, tested by its own test)
  and the POSIX shebang relocation (the Windows launcher relocation runs in every Windows build).
- `test_sandboxexec`: Seatbelt (macOS's backend).
- `tests/rust/test_launcher_service`: launchd (two), systemd, and the launcher's POSIX signal handling.
- `tests/rust/test_agent_files`, the checkpoint moved by a protection pause: the agent counts every process in session
  0 (services, where ssh and CI runners start the suite) as no person's, so a rule never matches a process the test
  starts there; it runs in a person's session.
- Environment-dependent everywhere: accessibility with axe (`OARBANK_A11Y_NODE_MODULES`), a node.js test, a real
  coordinator build's inspection (`OARBANK_COORDINATOR_BUILD`).

**Not verified.** The GitHub Actions jobs themselves (`windows-2025` and `windows-11-arm`; the workflow passes
actionlint), x64 Windows (CI only), and Windows Server. An agent installed from the MSI beside the coordinator service
was not combined on the VM; the role containers cover it by construction, and the VM's test agent beside the service
showed the failure and the fix.

**Found on the way, outside this gap, and fixed before 2.5.0.**
- The elevated helper kept a job's loopback filters and exemption when the shim that asked for them was killed (on the
  VM: a killed job's filters stayed until the helper restarted, and the module's next job, with its own proxy port,
  reached nothing, since each opening's filter blocked every port but its own). An opening now lasts exactly as long as
  the process that asked for it: the helper waits on that process's handle, its filters are a block per container and a
  permit per port (several jobs of one module at once), persistent and owned by the helper's WFP provider, and a helper
  that starts keeps the openings whose owner still runs and removes the rest (helper_windows.rs; `helper-clear` on
  uninstall).
- `scripts/build-node-runtime.ps1` copies the interpreter's real prefix and refuses a link; the packaging gate
  (`scripts/check-package.py`) refuses a runtime with a reparse point or a path of the build machine (uv's
  `direct_url.json` named the checkout), and runs a copy of it from another directory.
- The Windows scripts take the architecture from the caller (`-Arch`) or from Windows (`scripts/windows-arch.ps1`,
  `IsWow64Process2`), build with an explicit Rust target and check the binaries' machine type.
- A runner's per-user locations, `LOCALAPPDATA` among them, stay in its work directory by design; the module launcher
  creates the AppContainer folder an AppContainer start points `LOCALAPPDATA`, `TEMP` and `TMP` at (module-sandbox.md,
  "A runner's home").
