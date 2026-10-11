#!/usr/bin/env python3
"""Pre-removal cleanup of per-user units, using the package's bundled Python (stdlib only).

Since 2.9 the coordinator is a system service (docs/design/coordinator-system-service.md),
which coordinator-preremove.sh removes first; this finds what a 2.8 or earlier helper left in
people's systemd user directories and a migration did not retire (one refused, or never
run), so no unit is left running a payload that is about to disappear. Those helpers used
the canonical unit names below and absolute executable paths under ROOT. For offline users with a custom XDG_CONFIG_HOME, write this
registry even if XDG_DATA_HOME is customized, using the account's NSS home:

  ~/.local/share/oarbank/coordinator-package.json
  {"format": 1, "root": "/opt/oarbank/coordinator", "unit_dir": "/absolute/systemd/user"}

Write the registry BEFORE enabling services, atomically and mode 0600. Default
paths and running managers are also discovered, supporting older installations.
The registry is only a discovery hint, never authority to delete arbitrary files.
We inspect package executable references and perform all user-file access after
dropping to that account. We retain coordinator data, keys, logs, and linger.

Unreachable active managers, inaccessible relevant paths, and failed stop/reload
abort removal. Custom offline paths without the registry and manually renamed
units cannot be discovered: the installed helper must honor this contract.
Offline accounts must be enumerable via NSS; active managers additionally use
UID lookups. NSS-unresolvable active managers block removal.
"""
import json
import os
import pwd
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = "/opt/oarbank/coordinator"
UNITS = ("dev.codonic.oarbank.oarbankd.service", "dev.codonic.oarbank.console.service")


def references_package(text: str) -> bool:
    # Match executable paths, not descriptions, data directories, or other builds.
    commands = re.findall(r"^\s*Exec(?:Start|StartPre|StartPost|Stop|StopPost)\s*=([^\n]*)", text.replace("\\\n", " "), re.M)
    return any(re.search(re.escape(ROOT) + r"/bin/(?:oarbankd|oarbank-console)(?=[\s\"';}]|$)", command)
               for command in commands)


def systemctl(*args: str) -> str:
    result = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=30)
    # Some systemd versions report a nonzero status for an unknown unit while
    # still returning its LoadState. Absence is normal for unrelated accounts.
    if result.returncode and "LoadState=not-found" not in result.stdout.splitlines():
        raise RuntimeError("systemctl " + " ".join(args) + ": " + result.stderr.strip())
    return result.stdout.strip()


def read_unit(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def cleanup_user(home: Path, runtime: Path) -> None:
    registry = home / ".local/share/oarbank/coordinator-package.json"
    directories = {home / ".config/systemd/user", home / ".local/share/systemd/user",
                   runtime / "systemd/user", runtime / "systemd/user.control",
                   home / ".config/systemd/user.control"}
    registered = False
    try:
        doc = json.loads(registry.read_text())
    except FileNotFoundError:
        doc = None
    if doc is not None and doc.get("root") == ROOT:
        path = doc.get("unit_dir")
        if doc.get("format") != 1 or not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError("invalid coordinator package registry: " + str(registry))
        directories.add(Path(path))
        registered = True

    # Query only an EXISTING user manager; plain --user never starts one.
    manager = (runtime / "systemd/private").exists()
    loaded = set()
    if manager:
        directories.update(Path(p) for p in shlex.split(systemctl("show", "--property=UnitPath", "--value")))
        for unit in UNITS:
            info = systemctl("show", unit, "--property=LoadState,ExecStart,FragmentPath,DropInPaths")
            if references_package(info):
                loaded.add(unit)
                fragment = re.search(r"^FragmentPath=(.+)$", info, re.M)
                if fragment:
                    directories.add(Path(fragment[1]).parent)

    files = set()
    enable_targets = set()
    selected = set(loaded)
    # Inspect before stopping, so an inaccessible unit/registry fails safely.
    for directory in directories:
        for unit in UNITS:
            path = directory / unit
            if references_package(read_unit(path)):
                files.add(path)
                selected.add(unit)
            dropins = directory / (unit + ".d")
            if dropins.exists():
                for path in dropins.glob("*.conf"):
                    if references_package(read_unit(path)):
                        files.add(path)
                        enable_targets.add(directory / unit)
                        selected.add(unit)
    if manager and loaded:
        # An explicit stop suppresses Restart=always/on-failure. Never kill the
        # whole user manager, which may supervise unrelated applications.
        systemctl("stop", *sorted(loaded))

    targets = {path.resolve() for path in files | enable_targets}
    # Remove enablement and aliases BEFORE deleting the files they resolve to.
    # pathlib traversal does not recurse into symlinked directories. All access
    # is as the account, so user-controlled links cannot grant root write access.
    for directory in directories:
        if not directory.exists():
            continue
        candidates = list(directory.iterdir())
        for child in list(candidates):
            if not child.is_symlink() and child.is_dir() and child.name.endswith((".wants", ".requires")):
                candidates.extend(child.iterdir())
        for path in candidates:
            if path.is_symlink() and path.resolve() in targets:
                path.unlink()
    for path in files:
        # A unit may itself be an alias removed in the preceding loop.
        path.unlink(missing_ok=True)
    if manager and selected:
        systemctl("daemon-reload")
        for unit in selected:
            if references_package(systemctl("show", unit, "--property=LoadState,ExecStart")):
                raise RuntimeError(unit + " still references the package after cleanup")
    if registered:
        registry.unlink()


def accounts_to_clean(runtime_root: Path = Path("/run/user")) -> list:
    # NSS backends may disable enumeration while still supporting UID lookup.
    # Include active/lingering managers even when getpwall omits their account.
    accounts = {(a.pw_uid, a.pw_dir): a for a in pwd.getpwall()}
    if runtime_root.exists():
        for runtime in runtime_root.iterdir():
            if runtime.name.isdigit() and (runtime / "systemd/private").exists():
                try:
                    account = pwd.getpwuid(int(runtime.name))
                except KeyError as exc:
                    raise RuntimeError("active user manager has no NSS account: UID " + runtime.name) from exc
                accounts[(account.pw_uid, account.pw_dir)] = account
    return list(accounts.values())


def main() -> int:
    if os.geteuid() != 0:
        print("coordinator-remove: package removal must run as root", file=sys.stderr)
        return 1
    failures = []
    try:
        accounts = accounts_to_clean()
    except (OSError, RuntimeError) as exc:
        print("Oarbank: removal blocked; " + str(exc), file=sys.stderr)
        return 1
    for account in accounts:
        home = Path(account.pw_dir)
        runtime = Path("/run/user") / str(account.pw_uid)
        # No assumed /home layout, UID floor, login shell, or root's $HOME.
        if not home.is_absolute():
            continue
        if not home.exists() and not runtime.exists():
            continue
        pid = os.fork()
        if pid == 0:
            try:
                os.initgroups(account.pw_name, account.pw_gid)
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
                os.environ.clear()
                os.environ.update(HOME=str(home), USER=account.pw_name, LOGNAME=account.pw_name,
                                  PATH="/usr/bin:/bin", XDG_RUNTIME_DIR=str(runtime),
                                  DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(runtime / "bus"))
                os.chdir("/")
                cleanup_user(home, runtime)
            except Exception as exc:
                print("coordinator-remove: " + account.pw_name + ": " + str(exc), file=sys.stderr, flush=True)
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        if status != 0:
            failures.append(account.pw_name)
    if failures:
        print("Oarbank: removal blocked; clean up services for " + ", ".join(failures)
              + " and retry. Package executables must remain installed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
