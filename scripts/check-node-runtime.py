#!/usr/bin/env python3
"""Check a Windows node runtime (scripts/build-node-runtime.ps1) before it is packaged; scripts/package-windows.ps1 runs
it. Stdlib only.

- No link of any kind: a reparse point (junction, symbolic link, mount point) would be packaged as whatever the MSI
  makes of it, or reach into the build machine (uv names its managed Pythons through junctions).
- No path of the build: the runtime names none of the directories it was built from (the checkout, the interpreter it
  was copied from, the output directory itself) in its metadata and configuration files.
- It runs from its own location: a copy elsewhere starts, imports the SDK, and finds its prefix and every import path
  inside itself.

  scripts/check-node-runtime.py RUNTIME [BUILD_PATH ...]"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# the files a runtime keeps paths in: package metadata, path files, configuration
TEXT = {".pth", ".json", ".cfg", ".txt", ".toml", ".ini"}
TEXT_NAMES = {"RECORD", "INSTALLER", "METADATA", "pyvenv.cfg"}


def links(root: Path) -> list[Path]:
    """Every reparse point under `root` (a symbolic link where the OS has no reparse points), never followed."""
    out, todo = [], [root]
    while todo:
        with os.scandir(todo.pop()) as it:
            for e in it:
                st = e.stat(follow_symlinks=False)
                if getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT or e.is_symlink():
                    out.append(Path(e.path))
                elif e.is_dir(follow_symlinks=False):
                    todo.append(Path(e.path))
    return sorted(out)


def spellings(p: str) -> set[str]:
    """How a path may be written in a file: as it is, with forward slashes (a file URL), case-folded on Windows."""
    forms = {p, p.replace("\\", "/"), p.replace("\\", "\\\\")}
    return {f.lower() for f in forms} if os.name == "nt" else forms


def references(root: Path, paths: list[str]) -> list[tuple[Path, str]]:
    """(file, path) for each of `paths` a metadata or configuration file under `root` names."""
    needles = set().union(*(spellings(str(Path(p))) for p in paths)) if paths else set()
    out = []
    for f in root.rglob("*"):
        if not f.is_file() or f.is_symlink() or (f.suffix.lower() not in TEXT and f.name not in TEXT_NAMES):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        text = text.lower() if os.name == "nt" else text
        out += [(f, n) for n in sorted(needles) if n in text]
    return out


def runs_elsewhere(root: Path) -> str | None:
    """None when a copy of the runtime in another directory starts, imports the SDK and keeps every import path inside
    itself; else what went wrong."""
    probe = ("import json, sys, oarbank_sdk, pydantic\n"
             "print(json.dumps({'prefix': sys.prefix, 'sdk': oarbank_sdk.__file__, 'path': [p for p in sys.path if p]}))")
    with tempfile.TemporaryDirectory(prefix="oarbank-runtime-check-") as td:
        copy = Path(td) / "moved"
        shutil.copytree(root, copy, symlinks=True)
        py = copy / ("python.exe" if os.name == "nt" else "bin/python3")
        r = subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True, cwd=td)
        if r.returncode:
            return f"the moved runtime does not start: {r.stderr.strip()[-500:]}"
        seen = json.loads(r.stdout)
        real = copy.resolve()
        outside = [p for p in [seen["prefix"], seen["sdk"], *seen["path"]] if not Path(p).resolve().is_relative_to(real)]
        return f"the moved runtime reaches outside itself: {outside}" if outside else None


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.rsplit("\n\n", 1)[-1].strip(), file=sys.stderr)
        return 2
    root = Path(argv[0]).resolve()
    bad = [f"{p}: a link (reparse point)" for p in links(root)]
    bad += [f"{f}: names the build path {n}" for f, n in references(root, [str(root), *argv[1:]])]
    if not bad:
        why = runs_elsewhere(root)
        bad += [why] if why else []
    for b in bad:
        print(f"check-node-runtime: {b}", file=sys.stderr)
    if not bad:
        print(f"check-node-runtime: {root} has no links, names no build path and runs from elsewhere")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
