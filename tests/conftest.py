import os
import sys
import tempfile
from pathlib import Path

import pytest

# never touch the real coordinator's state (~/Library/Application Support/Oarbank/coordinator): releases and the module store go to a scratch home
os.environ["OARBANKD_HOME"] = tempfile.mkdtemp(prefix="oarbank-test-home-")

from hypothesis import HealthCheck, settings

sys.path.insert(0, str(Path(__file__).parent))
settings.register_profile("thorough", max_examples=1000, stateful_step_count=100, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
if os.environ.get("OARBANK_THOROUGH"):
    settings.load_profile("thorough")


# the suite's agents are synthetic hello bodies (module-scoped fixtures run before any function fixture); the claim
# gate on the agent's module_sandbox feature has its own test, which turns it back on
from oarbank.coordinator import modsandbox as _modsandbox  # noqa: E402
_modsandbox.REQUIRE_SANDBOXED_AGENTS = False

# the test client's Host header ("testserver") is not a loopback name; real listeners are checked in test_access.py
from oarbank.coordinator import access as _access  # noqa: E402
_access.TEST_HOSTS.add("testserver")

# signing is on by default in production; the suite runs in developer mode, and the signing tests turn it on
from oarbank.coordinator import config as _config  # noqa: E402
_config.RELEASE_SIGNING = False

# secrets go to owner-only files in the scratch home, never into the developer's login Keychain (plan §9.7)
os.environ["OARBANK_SECRET_STORE"] = "file"


def pytest_configure(config):
    """Module processes always run confined (modsandbox.py). macOS confines them with Seatbelt; Linux and Windows with
    the agent's `sandbox-exec`, which the suite builds from rust/ unless OARBANK_SANDBOX_EXEC names a binary. No
    backend is a configuration error, never a skip (docs/verification.md, "Running it")."""
    if sys.platform == "darwin":
        return
    import agentbin
    from oarbank.coordinator import sandboxexec
    if not os.environ.get("OARBANK_SANDBOX_EXEC"):
        try:
            os.environ["OARBANK_SANDBOX_EXEC"] = str(agentbin.build())
        except agentbin.BuildError as e:
            raise pytest.UsageError(f"the module sandbox on {sys.platform} needs the agent binary: {e}") from None
    exe = os.environ["OARBANK_SANDBOX_EXEC"]
    if sandboxexec.backend() is None:
        raise pytest.UsageError(f"no module sandbox backend on {sys.platform}: OARBANK_SANDBOX_EXEC={exe} is missing or "
                                f"`{exe} sandbox-status` reports no backend (build it with `cargo build -p oarbank-agent` "
                                "in rust/; Linux needs Landlock and seccomp)")


@pytest.fixture(scope="module", autouse=True)
def _module_processes_end_with_their_test_module():
    """Module hosts a test file made stop when the file is done, rather than when their database is collected: their
    processes would otherwise pile up over the session (on Windows each holds its files open)."""
    from oarbank.coordinator import modcalls
    before = len(modcalls._all_hosts)
    yield
    for ref in modcalls._all_hosts[before:]:
        h = ref()
        if h is not None:
            h.close()
