"""oarbankd configuration: paths, protocol constants and policy defaults."""
import os
import shutil
from pathlib import Path

from .. import paths

HOME = Path(os.environ.get("OARBANKD_HOME") or paths.coordinator_home())
DB_PATH = HOME / "oarbank.sqlite3"

# Release signing (D31; docs/release-signing.md), read once at process start: on unless OARBANK_RELEASE_SIGNING=0,
# developer mode.
RELEASE_SIGNING = os.environ.get("OARBANK_RELEASE_SIGNING", "1") != "0"
ATTEMPT_LOG_DIR = HOME / "attempt-logs"
RELEASE_DIR = HOME / "releases"

# oarbank-console (pages, SSE; the `tailscale serve` target) and oarbankd's admin API (JSON + operations),
# both loopback-only (D10). The console forwards /api/* to the admin API.
CONSOLE_BIND = os.environ.get("OARBANKD_CONSOLE_BIND", "127.0.0.1")
CONSOLE_PORT = int(os.environ.get("OARBANKD_CONSOLE_PORT", "7400"))
ADMIN_BIND = os.environ.get("OARBANKD_ADMIN_BIND", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("OARBANKD_ADMIN_PORT", "7401"))
CONSOLE_SECRET_PATH = HOME / "console.secret"      # per boot, 0600: authenticates the console's forwarded identity
# the agent listener's interface: one the nodes reach (loopback by default, for development)
AGENT_BIND = os.environ.get("OARBANKD_AGENT_BIND", "127.0.0.1")
AGENT_PORT = int(os.environ.get("OARBANKD_AGENT_PORT", "7443"))              # TLS, agents authenticated by client certificate

LEASE_TTL = 60.0
ARTIFACT_MAX_BYTES = 2 * 1024 ** 3     # one stage output file (typically a few MB)
HEARTBEAT_S = 10
OFFLINE_ALERT_AFTER = 600.0      # node_offline alerts after 10 min: sleep and wake noise stays below (alerting.py)
OFFLINE_AFTER = 30.0
REAPER_EVERY = 5.0
MAX_GOLDEN_FAILURES = 3        # a node stops certifying a module after this many golden failures (a job's own retries: stages[].retry)
BREAKER_K = 3                  # consecutive host-attributable failures -> back to doctor
RECERT_EVERY = 6 * 3600.0
SAMPLE_EVERY = 30.0            # store a node sample at most this often

# the Tailscale CLI of this machine's tailscaled (discovery hints and whois)
TAILSCALE = os.environ.get("OARBANKD_TAILSCALE") or shutil.which("tailscale") or next(
    (p for p in ("/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale",
                 "/Applications/Tailscale.app/Contents/MacOS/Tailscale") if os.path.exists(p)), "tailscale")
TAILSCALE_SOCKET = os.environ.get("OARBANKD_TAILSCALE_SOCKET", "")

DEFAULT_POLICY = {
    "os_reserve_gb": 4, "user_reserve_gb": 8, "max_slots": None, "threads_per_job": 1, "job_mem_gb": 1.5,
    "user_present_slots": 2, "user_idle_s": 300, "run_on_battery": False, "nice": 10,
    # a remote Screen Sharing session (macOS) counts as someone using the machine even without input
    "screen_sharing_present": True,
    # jobs get at most the memory available now (less the memory guard's floor and 1 GB); off: the reserves alone decide
    "mem_in_use_bound": True,
    # jobs' reservations become hard limits where the OS has them (Linux cgroups, Windows Job Objects): going over
    # the memory reservation is then the job's fault (oom). Off: reservations steer admission only.
    "hard_limits": False,
    # services this node must not run, as "<module>/<service>" (e.g. a VM kept to the coordinator's machine)
    "disabled_services": [],
    # per-module node settings, handed to the module's services (e.g. a VM size)
    "module_settings": {},
    # owner-set protection (D3; schema 1): new nodes are "moderate" with no rules
    "protection": {"schema": 1, "node": {"mode": "moderate"}, "rule": []},
}

LIMIT_KEYS = ("cpu_cores", "mem_gb", "jobs", "vm_mem_gb", "vm_cpus", "disk_gb", "staging_mbps", "schedule")


def is_coordinator_host(facts: dict) -> bool:
    import socket
    short = lambda h: (h or "").split(".")[0].lower()
    return bool(facts.get("hostname")) and short(facts.get("hostname")) == short(socket.gethostname())


def policy_defaults(facts: dict, default_worker_disabled: list | None = None) -> dict:
    """Per-node defaults from detected hardware, each with why it is the default: {key: (value, reason)} where reason
    is None when the value is the same on every node. Workers get the fleet's default disabled services (setting
    `default_worker_disabled_services`); the coordinator's own machine runs everything."""
    import copy
    out = {k: (copy.deepcopy(v), None) for k, v in DEFAULT_POLICY.items()}
    if is_coordinator_host(facts):
        out["disabled_services"] = ([], "the coordinator's own machine runs every service")
    else:
        off = list(default_worker_disabled or [])
        out["disabled_services"] = (off, "the fleet's default for workers" if off else None)
    from .platforms import memory_gb
    ram = memory_gb(facts)
    if ram:
        out["os_reserve_gb"] = (4 if ram <= 32 else (8 if ram >= 96 else 6), f"{ram:g} GB RAM")
    else:
        out["os_reserve_gb"] = (6, "RAM not reported")
    return out


def policy_for(facts: dict, default_worker_disabled: list | None = None) -> dict:
    """Per-node defaults from detected hardware (`policy_defaults` without the reasons); the owner edits them in the
    console, which shows each default and why next to the setting."""
    return {k: v for k, (v, _) in policy_defaults(facts, default_worker_disabled).items()}
