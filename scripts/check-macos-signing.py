#!/usr/bin/env python3
"""Check the macOS code signatures of the Python interpreters a build ships, which run module code: the node runtime
(scripts/package-macos.sh) and the coordinator build (scripts/build-coordinator.sh, scripts/package-coordinator-macos.sh).
Stdlib only; macOS only (codesign).

- Every interpreter (a Mach-O file named python, python3 or python3.N, not a link) carries exactly the entitlements of
  deploy/macos/python.entitlements: com.apple.security.cs.disable-library-validation, so a hardened interpreter can
  load the third-party wheels modules install, and nothing broader. Every other Mach-O executable carries none.
  At least one interpreter must be found.
- With --developer-id, the interpreters are signed with the hardened runtime by a team (a Developer ID), as a release
  is. An ad hoc signature never enforces library validation, so only this mode shows what a Mac will do with the build.
- With --canary, each interpreter loads a native wheel from PyPI that it did not ship (WHEEL, whose extension module is
  signed ad hoc, not by the build's team): a virtual environment made by the build's own uv (bin/uv in the tree, or
  --uv), the wheel installed into it, its extension module imported by the shipped interpreter, and a ctypes callback
  called (the hardened runtime's executable-memory rules). Under a Developer ID signature without the entitlement the
  import fails with "mapping process and mapped file (non-platform) have different Team IDs". The environment lives in
  a temporary directory (or --work); nothing in the tree may change, which the check verifies.

  scripts/check-macos-signing.py [--developer-id] [--canary [--uv UV] [--work DIR]] TREE...
"""
from __future__ import annotations

import argparse
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENTITLEMENTS = REPO / "deploy" / "macos" / "python.entitlements"
INTERPRETER = re.compile(r"python(3(\.\d+)?)?")
# a tiny wheel with one C extension, published for cp312 on both Mac architectures; its module is imported by name,
# since markupsafe itself falls back to pure Python when the extension does not load
WHEEL = "markupsafe==3.0.4"
EXTENSION = "markupsafe._speedups"

MH_MAGIC = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">", b"\xce\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xce": ">"}
FAT_MAGIC = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
MH_EXECUTE = 2


def macho_type(path: Path) -> int | None:
    """The Mach-O file type (MH_EXECUTE, MH_DYLIB, MH_BUNDLE, ...) of a thin file or a universal file's first slice;
    None for anything else."""
    try:
        with open(path, "rb") as f:
            head = f.read(32)
            if head[:4] in FAT_MAGIC and len(head) >= 16:
                wide = head[:4] == b"\xca\xfe\xba\xbf"
                offset = struct.unpack(">Q", head[16:24])[0] if wide else struct.unpack(">I", head[16:20])[0]
                f.seek(offset)
                head = f.read(32)
    except OSError:
        return None
    order = MH_MAGIC.get(head[:4])
    if order is None or len(head) < 16:
        return None
    return struct.unpack(order + "I", head[12:16])[0]


def executables(root: Path):
    """Every Mach-O executable under `root` (or `root` itself), never through a link."""
    paths = [root] if root.is_file() else (Path(d) / n for d, _, ns in os.walk(root) for n in ns)
    for p in paths:
        if not p.is_symlink() and p.is_file() and macho_type(p) == MH_EXECUTE:
            yield p


def entitlements(path: Path) -> dict:
    out = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", str(path)], capture_output=True)
    if out.returncode != 0:
        raise SystemExit(f"{path}: not signed: {out.stderr.decode(errors='replace').strip()}")
    return plistlib.loads(out.stdout) if out.stdout.strip() else {}


def signature(path: Path) -> dict[str, str]:
    out = subprocess.run(["codesign", "-dvv", str(path)], capture_output=True, text=True)
    info: dict[str, str] = {}
    for line in out.stderr.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info.setdefault(key, value)
    return info


def check_tree(root: Path, expected: dict, developer_id: bool) -> tuple[list[Path], list[str]]:
    found, problems = [], []
    for exe in executables(root):
        got = entitlements(exe)
        if INTERPRETER.fullmatch(exe.name):
            found.append(exe)
            if got != expected:
                problems.append(f"{exe}: entitlements {sorted(got) or 'none'}, expected exactly {sorted(expected)} "
                                f"({ENTITLEMENTS.relative_to(REPO)})")
            if developer_id:
                info = signature(exe)
                if "runtime" not in info.get("CodeDirectory v", "") or info.get("TeamIdentifier", "not set") == "not set":
                    problems.append(f"{exe}: not signed with the hardened runtime by a Developer ID "
                                    f"(flags {info.get('CodeDirectory v', '?')}, team {info.get('TeamIdentifier', '?')})")
        elif got:
            problems.append(f"{exe}: entitlements {sorted(got)}; only the interpreters carry any")
    if not found:
        problems.append(f"{root}: no Python interpreter found")
    return found, problems


def snapshot(prefix: Path) -> dict[str, tuple[int, int]]:
    return {str(p): (p.lstat().st_size, p.lstat().st_mtime_ns)
            for p in (Path(d) / n for d, ds, ns in os.walk(prefix) for n in ds + ns)}


def canary(python: Path, uv: str, work: Path) -> list[str]:
    """A fresh environment on `python`, WHEEL from PyPI in it, its extension imported by `python`."""
    prefix = Path(subprocess.run([str(python), "-I", "-B", "-c", "import sys; print(sys.base_prefix)"],
                                 capture_output=True, text=True, check=True).stdout.strip())
    before = snapshot(prefix)
    venv = work / f"canary-{python.name}"
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work), "TMPDIR": str(work),
           "UV_CACHE_DIR": str(work / "uv-cache"), "UV_NO_CONFIG": "1", "UV_PYTHON_DOWNLOADS": "never",
           "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"}
    shutil.rmtree(venv, ignore_errors=True)
    steps = [[uv, "venv", "--quiet", "--no-config", "--python", str(python), str(venv)],
             [uv, "pip", "install", "--quiet", "--no-config", "--python", str(venv / "bin" / "python"),
              "--only-binary", ":all:", WHEEL]]
    for argv in steps:
        out = subprocess.run(argv, env=env, capture_output=True, text=True)
        if out.returncode != 0:
            return [f"{python}: canary: {' '.join(argv[:3])} failed: {out.stderr.strip()[-800:]}"]
    probe = (
        "import ctypes, importlib, sys\n"
        f"m = importlib.import_module({EXTENSION!r})\n"
        "assert m.__file__.startswith(sys.prefix + '/'), (m.__file__, sys.prefix)\n"
        "cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda x: x * 2)\n"
        "assert cb(21) == 42\n"
        "print(m.__file__)\n"
    )
    out = subprocess.run([str(venv / "bin" / "python"), "-I", "-B", "-c", probe], env=env, capture_output=True, text=True)
    problems = []
    if out.returncode != 0:
        problems.append(f"{python}: cannot load a third-party native wheel ({WHEEL}): {out.stderr.strip()[-1200:]}")
    else:
        so = Path(out.stdout.strip().splitlines()[-1])
        mine, theirs = signature(python).get("TeamIdentifier"), signature(so).get("TeamIdentifier", "not set")
        print(f"canary: {python} (team {mine}) loaded {so.name} (team {theirs}) and called a ctypes callback")
        if mine not in (None, "not set") and theirs == mine:
            problems.append(f"{so}: signed by the build's own team, so the canary proves nothing")
    if snapshot(prefix) != before:
        problems.append(f"{prefix}: the canary changed the shipped tree")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--developer-id", action="store_true", help="require the hardened runtime and a team")
    ap.add_argument("--canary", action="store_true", help="load a third-party native wheel under each interpreter")
    ap.add_argument("--uv", help="the uv that makes the canary's environment (default: bin/uv in the tree, else PATH)")
    ap.add_argument("--work", type=Path, help="where the canary's environment goes (default: a temporary directory)")
    ap.add_argument("trees", nargs="+", type=Path)
    args = ap.parse_args(argv)
    if sys.platform != "darwin":
        print("check-macos-signing.py: macOS only", file=sys.stderr)
        return 2
    with open(ENTITLEMENTS, "rb") as f:
        expected = plistlib.load(f)
    problems: list[str] = []
    interpreters: list[tuple[Path, Path]] = []
    for root in args.trees:
        found, bad = check_tree(root.resolve(), expected, args.developer_id)
        problems += bad
        interpreters += [(root.resolve(), p) for p in found]
    if args.canary and interpreters:
        with tempfile.TemporaryDirectory(prefix="oarbank-canary-") as tmp:
            work = (args.work or Path(tmp)).resolve()
            work.mkdir(parents=True, exist_ok=True)
            for root, python in interpreters:
                uv = args.uv or next((str(u) for u in (root / "bin" / "uv",) if u.is_file()), None) or shutil.which("uv")
                if not uv:
                    problems.append(f"{root}: no uv for the canary (--uv)")
                    continue
                problems += canary(python, uv, work)
    for p in problems:
        print(p, file=sys.stderr)
    if not problems:
        names = ", ".join(str(p) for _, p in interpreters)
        print(f"macOS signing: {names} {'carries' if len(interpreters) == 1 else 'carry'} {', '.join(sorted(expected))}"
              + (" with the hardened runtime" if args.developer_id else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
