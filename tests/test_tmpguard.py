"""The run's temp-file guard (tmpguard.py): a temp directory a test leaves fails the run, by name, and goes anyway; a
clean run passes and leaves nothing; with xdist the workers' leftovers count too."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import tmpguard

HERE = Path(__file__).parent


def run_suite(tmp_path: Path, body: str, *args: str) -> tuple[subprocess.CompletedProcess, Path]:
    """pytest on a one-file suite guarded as this one is, in a temp directory of its own: (the run, that directory)."""
    suite, real = tmp_path / "suite", tmp_path / "tmp"
    suite.mkdir()
    real.mkdir()
    (suite / "tmpguard.py").write_text((HERE / "tmpguard.py").read_text(encoding="utf-8"), encoding="utf-8")
    (suite / "conftest.py").write_text("import tmpguard  # noqa: F401\n"
                                       "from tmpguard import pytest_sessionfinish, pytest_terminal_summary  # noqa: F401\n",
                                       encoding="utf-8")
    (suite / "test_it.py").write_text(body, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in (tmpguard.ENV, "PYTEST_DEBUG_TEMPROOT", "PYTEST_XDIST_WORKER")}
    env.update(TMPDIR=str(real), TEMP=str(real), TMP=str(real), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args, "test_it.py"],
                       cwd=suite, env=env, capture_output=True, text=True, timeout=300)
    return r, real


def ours(real: Path) -> list[str]:
    return sorted(p.name for p in real.iterdir() if p.name.startswith(tmpguard.OURS))


LEAKY = """import tempfile
def test_leaks():
    tempfile.mkdtemp(prefix="bundle-")
def test_cleans(tmp_path):
    with tempfile.TemporaryDirectory(prefix="conform-"):
        pass
"""


def test_a_temp_directory_left_behind_fails_the_run_and_still_goes(tmp_path):
    r, real = run_suite(tmp_path, LEAKY)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "2 passed" in r.stdout and "left in the run's temp directory: bundle-" in r.stdout, r.stdout
    assert ours(real) == []


def test_a_clean_run_passes_and_leaves_nothing(tmp_path):
    r, real = run_suite(tmp_path, LEAKY.replace('tempfile.mkdtemp(prefix="bundle-")', "pass"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "temp files left behind" not in r.stdout
    assert ours(real) == []


def test_xdist_workers_leftovers_count_too(tmp_path):
    pytest.importorskip("xdist")
    r, real = run_suite(tmp_path, LEAKY, "-n", "2")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "left in the run's temp directory: bundle-" in r.stdout, r.stdout
    assert ours(real) == []
