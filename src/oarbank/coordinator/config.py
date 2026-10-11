"""oarbankd configuration: paths and protocol constants (owner settings and their defaults: settings/registry.py)."""
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


def is_coordinator_host(facts: dict) -> bool:
    """Is this the coordinator's own machine (the built-in "Coordinator host" group: it runs every service)?"""
    import socket
    short = lambda h: (h or "").split(".")[0].lower()
    return bool(facts.get("hostname")) and short(facts.get("hostname")) == short(socket.gethostname())
