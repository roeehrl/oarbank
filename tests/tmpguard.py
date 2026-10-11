"""No temp file outlives the test run that made it.

Imported first by conftest.py. The run points TMPDIR (and TEMP and TMP, which Windows tools read) at a directory of its
own inside the real temp directory, so every temp file a test, the code under test or a process it starts makes lands
there: xdist workers and subprocesses inherit it. When the session ends, anything left in that directory is a leak (a
source that does not clean up after itself): the session fails naming each entry and a few files inside it, and the
directory is removed either way. The suite's own scratch (suite_dir(): the test coordinator home, the session's bundles)
lives there too and is not a leak.

Entries with our prefixes that appear in the real temp directory during the run are reported as well (something that
ignores TMPDIR made them), without failing the run: another process may have made them. pytest's tmp_path stays in the
real temp directory (PYTEST_DEBUG_TEMPROOT), where pytest keeps only its last three runs. A run killed outright leaves
its directory behind; the next run removes every such directory whose process is gone.
"""
import atexit
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

PREFIX = "oarbank-test-"                       # oarbank-test-<pid>-<random>: one run's temp directory
ENV = "OARBANK_TEST_TMP"                       # that directory, for the run's workers and subprocesses
OURS = ("oarbank", "bundle", "conform", "TemporaryDirectory.")   # what our code and tools name their temp files
SUITE = "_suite-"                              # suite_dir()s: the suite's own scratch, not a leak
# tools' persistent caches, kept by design wherever TMPDIR points (removed with the run's directory)
KEPT_BY_TOOLS = re.compile(r"^(uv-[0-9a-f]+\.lock|xcrun_db.*)$")


def _ours(tmp: str) -> set[str]:
    try:
        return {n for n in os.listdir(tmp) if n.startswith(OURS) and not n.startswith(PREFIX)}
    except OSError:
        return set()


def _gone(pid: int) -> bool:
    if os.name != "posix":
        return False                           # os.kill(pid, 0) is not a probe on Windows: never sweep there
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def _sweep(tmp: str):
    """Remove the directories of runs that were killed outright (their process is gone)."""
    for n in os.listdir(tmp):
        m = re.match(rf"{re.escape(PREFIX)}(\d+)-", n)
        if m and _gone(int(m[1])):
            shutil.rmtree(Path(tmp, n), ignore_errors=True)


CONTROLLER = not os.path.isdir(os.environ.get(ENV, ""))     # the process that runs the session (an xdist controller)
if CONTROLLER:
    REAL = tempfile.gettempdir()
    _sweep(REAL)
    os.environ[ENV] = tempfile.mkdtemp(prefix=f"{PREFIX}{os.getpid()}-")
    os.environ.setdefault("PYTEST_DEBUG_TEMPROOT", REAL)
    BEFORE = _ours(REAL)
    atexit.register(shutil.rmtree, os.environ[ENV], True)  # a session that never finishes (a usage error) leaves nothing
RUN = os.environ[ENV]
for _var in ("TMPDIR", "TEMP", "TMP"):
    os.environ[_var] = RUN
tempfile.tempdir = RUN


def suite_dir() -> Path:
    """This process's scratch for the suite itself, removed with the run's directory and never reported."""
    d = Path(RUN, f"{SUITE}{os.environ.get('PYTEST_XDIST_WORKER', 'main')}-{os.getpid()}")
    d.mkdir(exist_ok=True)
    return d


def _peek(p: Path) -> str:
    if not p.is_dir() or p.is_symlink():
        return ""
    inside = sorted(str(f.relative_to(p)) for f in p.rglob("*"))[:4]
    return f" ({', '.join(inside)})" if inside else " (empty)"


REPORT: list[str] = []
LEAKED: list[str] = []


@pytest.hookimpl(trylast=True)                 # after xdist's own sessionfinish: every worker has exited
def pytest_sessionfinish(session):
    if not CONTROLLER:
        return
    left = sorted(n for n in os.listdir(RUN) if not n.startswith(SUITE) and not KEPT_BY_TOOLS.match(n))
    LEAKED.extend(left)
    REPORT.extend(f"left in the run's temp directory: {n}{_peek(Path(RUN, n))}" for n in left)
    REPORT.extend(f"appeared in {REAL} during the run (not failing: another process may have made it): {n}"
                  f"{_peek(Path(REAL, n))}" for n in sorted(_ours(REAL) - BEFORE))
    shutil.rmtree(RUN, ignore_errors=True)
    if left and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter):
    if REPORT:
        terminalreporter.section("temp files left behind", red=bool(LEAKED), yellow=not LEAKED)
        for line in REPORT:
            terminalreporter.write_line(line)
        if LEAKED:
            terminalreporter.write_line(f"temp entries that outlived the run: {len(LEAKED)}. Remove each where it is made "
                                        "(tmp_path, a context manager, try/finally); see tests/tmpguard.py")
