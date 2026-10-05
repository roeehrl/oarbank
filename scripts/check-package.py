#!/usr/bin/env python3
"""Check what a package ships before it is packaged: the node runtime and the agent's binaries (scripts/package-*.sh,
scripts/package-windows.ps1) and the coordinator build (scripts/build-coordinator.*). Stdlib only.

- No link that leaves the tree. On Windows no link at all: a reparse point (junction, symbolic link, mount point) is
  packaged as whatever the MSI makes of it, or reaches into the build machine (uv names its managed Pythons through
  junctions). Elsewhere a symbolic link must be relative and stay inside its tree (bin/python3 -> python3.12).
- No path of the build: no file names the checkout, the build's work directories or the interpreter's install
  directory, in any encoding a program stores it in: package metadata (uv's direct_url.json names the directory it
  installed from), path files, scripts, bytecode and binaries. Nor may any file but a native binary inside a tree name
  the build account's home or CARGO_HOME, and a binary given as its own argument (the build's own: the agent, the
  launcher) not even those (rustc embeds the source paths of the crates a binary is built from). The native binaries
  inside the trees come built from elsewhere (wheels, uv, python-build-standalone), often on CI machines whose account
  is the build's own (GitHub's runneradmin), so their copies of those paths are not this build's.
- With --run DIR=PYTHON, it runs from its own location: a copy of DIR in another directory starts PYTHON (relative to
  DIR), imports the --imports modules, and finds its prefix, those modules and every import path inside itself.

  scripts/check-package.py [--run DIR=PYTHON] [--imports a,b] [--build-path PATH]... TREE_OR_FILE..."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

WINDOWS = os.name == "nt"
REPO = Path(__file__).resolve().parents[1]


def files(root: Path):
    """Every entry under `root` (or `root` itself, a file), never following a link."""
    if not root.is_dir() or root.is_symlink():
        yield root
        return
    todo = [root]
    while todo:
        with os.scandir(todo.pop()) as it:
            for e in it:
                yield Path(e.path)
                if e.is_dir(follow_symlinks=False) and not reparse(e.stat(follow_symlinks=False)):
                    todo.append(Path(e.path))


def reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def bad_links(root: Path) -> list[str]:
    """The links under `root` a package must not hold: on Windows every reparse point; elsewhere a symbolic link that is
    absolute or resolves outside `root`."""
    out, top = [], root.resolve()
    for p in files(root):
        st = p.lstat()
        if WINDOWS and reparse(st):
            out.append(f"{p}: a link (reparse point)")
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(p)
            if os.path.isabs(target) or not (p.parent / target).resolve().is_relative_to(top):
                out.append(f"{p}: a link to {target}, outside the package")
    return out


def needles(paths: list[str]) -> dict[bytes, str]:
    """The byte strings a file may hold one of `paths` as: UTF-8 with either separator, as a JSON or C string (doubled
    backslashes), and UTF-16 (Windows resources), case-folded on Windows."""
    out = {}
    for p in paths:
        p = str(Path(p))
        for form in {p, p.replace("\\", "/"), p.replace("\\", "\\\\")}:
            form = form.lower() if WINDOWS else form
            out[form.encode()] = p
            if WINDOWS:
                out[form.encode("utf-16-le")] = p
    return out


def own_paths(root: Path, given: list[str]) -> list[str]:
    """This build's paths: the tree itself, the checkout, and the ones given (work directories, the interpreter's
    install directory)."""
    return usable({str(root), str(root.resolve()), str(REPO), *given})


def account_paths() -> list[str]:
    """The build account's: its home and CARGO_HOME."""
    home = Path.home()
    return usable({str(home), os.environ.get("CARGO_HOME") or str(home / ".cargo")})


def usable(paths: set[str]) -> list[str]:
    return sorted(p for p in paths if p and len(p) > 3)       # never a drive or the filesystem root


# PE, ELF, and Mach-O (thin and universal, either byte order)
NATIVE = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def references(root: Path, own: list[str], account: list[str]) -> list[tuple[Path, str]]:
    """(file, path) for each path a file under `root` must not hold: `own` in any file; `account` in any but a native
    binary inside a tree (a file given itself is checked for both)."""
    mine, theirs = needles(own), needles(account)
    out = []
    for f in files(root):
        if not f.is_file() or f.is_symlink():
            continue
        data = f.read_bytes()
        found = mine if f != root and data.startswith(NATIVE) else {**mine, **theirs}
        data = data.lower() if WINDOWS else data
        out += [(f, p) for n, p in found.items() if n in data]
    return sorted(set(out))


def runs_elsewhere(root: Path, python: str, imports: list[str]) -> str | None:
    """None when a copy of `root` in another directory starts `python` (relative to `root`), imports `imports` and
    keeps its prefix, those modules and every import path inside itself; else what went wrong."""
    probe = (f"import json, sys\nmods = [__import__(m) for m in {imports!r}]\n"
             "print(json.dumps({'prefix': sys.prefix, 'modules': [getattr(m, '__file__', None) or '' for m in mods],"
             " 'path': [p for p in sys.path if p]}))")
    td = tempfile.mkdtemp(prefix="oarbank-package-check-")
    try:
        copy = Path(td) / "moved"
        shutil.copytree(root, copy, symlinks=True)
        r = subprocess.run([str(copy / python), "-I", "-c", probe], capture_output=True, text=True, cwd=td)
        if r.returncode:
            return f"the moved copy of {root} does not start: {r.stderr.strip()[-500:]}"
        seen = json.loads(r.stdout)
        real = copy.resolve()
        outside = [p for p in [seen["prefix"], *seen["modules"], *seen["path"]] if p and not Path(p).resolve().is_relative_to(real)]
        return f"the moved copy of {root} reaches outside itself: {outside}" if outside else None
    finally:
        remove_tree(Path(td))


def remove_tree(p: Path, within: float = 60.0):
    """Delete the copy. Windows refuses to delete an executable while the antivirus scanner holds it after it was written
    or run, with nothing to wait on (src/oarbank/platform/files.py `remove_tree`): each refused entry is retried until
    `within` seconds have passed."""
    end = time.monotonic() + within

    def again(fn, path, exc):
        while isinstance(exc, PermissionError) and time.monotonic() < end:
            time.sleep(0.05)
            try:
                return fn(path)
            except PermissionError as e:
                exc = e
        raise exc
    shutil.rmtree(p, onexc=again)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="check-package.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("trees", nargs="+", type=Path)
    ap.add_argument("--run", action="append", default=[], metavar="DIR=PYTHON")
    ap.add_argument("--imports", default="oarbank_sdk,pydantic")
    ap.add_argument("--build-path", action="append", default=[])
    a = ap.parse_args(argv)
    bad = []
    for t in a.trees:
        bad += bad_links(t)
        bad += [f"{f}: names the build path {p}" for f, p in references(t, own_paths(t, a.build_path), account_paths())]
    if not bad:
        for r in a.run:
            d, py = r.split("=", 1)
            why = runs_elsewhere(Path(d), py, a.imports.split(","))
            bad += [why] if why else []
    for b in bad:
        print(f"check-package: {b}", file=sys.stderr)
    if not bad:
        print(f"check-package: {', '.join(map(str, a.trees))}: no link out, no build path"
              + (", runs from elsewhere" if a.run else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
