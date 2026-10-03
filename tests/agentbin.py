"""The `oarbank-agent` debug build the suites run against: the end-to-end tests drive it, and on Linux and Windows the
coordinator suite confines module processes with its `sandbox-exec` (the launcher a coordinator build ships as
`bin/oarbank-sandbox`; sandboxexec.py)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXE = ".exe" if sys.platform == "win32" else ""
CARGO = next((c for c in (shutil.which("cargo"), "/opt/homebrew/opt/rustup/bin/cargo", str(Path.home() / ".cargo" / "bin" / f"cargo{EXE}"))
              if c and Path(c).is_file()), None)
AGENT_BIN = REPO / "rust" / "target" / "debug" / f"oarbank-agent{EXE}"


class BuildError(RuntimeError):
    pass


def cargo_env() -> dict:
    return {**os.environ, "PATH": f"{Path(CARGO).parent}{os.pathsep}{os.environ.get('PATH', '')}"} if CARGO else dict(os.environ)


def build() -> Path:
    """`cargo build -p oarbank-agent` (incremental) and the binary's path."""
    if not CARGO:
        raise BuildError("no Rust toolchain (cargo) found: install rustup, or build the agent elsewhere with "
                         "`cargo build -p oarbank-agent` in rust/ and point OARBANK_SANDBOX_EXEC at the binary")
    r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-agent"], cwd=REPO / "rust", env=cargo_env(),
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise BuildError(f"`cargo build -p oarbank-agent` failed in rust/:\n{r.stderr[-3000:]}")
    return AGENT_BIN
