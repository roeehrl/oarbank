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
- Every native file is for the package's platforms: each Mach-O (thin or universal), ELF and PE file, and each object
  of a static or import library, carries code for every platform --platform declares for where it sits
  (spec/platforms.md tokens; DIR=PLATFORMS for the files under DIR, the longest DIR that holds a file deciding). Code
  for more platforms is fine (a universal2 wheel runs on either Mac); missing code for one is not. The one exception is
  pip's and setuptools' launcher templates, which they copy out for whatever machine a script is installed for.
- With --run DIR=PYTHON, it runs from its own location: a copy of DIR in another directory starts PYTHON (relative to
  DIR), imports the --imports modules and every extension module on its import path, and finds its prefix, those
  modules and every import path inside itself. Run on the build machine, it runs the package's platform: natively, or
  under Rosetta 2 or Windows on Arm's emulation for x64.

  scripts/check-package.py --platform [DIR=]PLATFORM[,PLATFORM]... [--run DIR=PYTHON] [--imports a,b]
                           [--build-path PATH]... TREE_OR_FILE..."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import struct
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


MACHO_CPU = {0x0100000C: "arm64", 0x01000007: "amd64"}          # CPU_TYPE_ARM64, CPU_TYPE_X86_64
ELF_MACHINE = {0xB7: "arm64", 0x3E: "amd64"}                    # EM_AARCH64, EM_X86_64
# IMAGE_FILE_MACHINE_ARM64, _AMD64, and in objects _ARM64EC and _ARM64X (Arm64EC code runs only on Windows on Arm)
PE_MACHINE = {0xAA64: "arm64", 0x8664: "amd64", 0xA641: "arm64", 0xA64E: "arm64"}
COFF_MACHINES = (*PE_MACHINE, 0x14C, 0x1C4)                     # and I386, ARMNT: an object's first field
# pip's and setuptools' launchers, which they copy out for the machine a console script is installed for
TEMPLATES = re.compile(r"(^|/)(pip/_vendor/distlib/[tw](32|64|64-arm)|setuptools/(cli|gui)(-32|-64|-arm64)?)\.exe$")


def platforms_of(data: bytes) -> set[str] | None:
    """The platforms (spec/platforms.md tokens) whose code a file carries, from its headers: None for a file that is
    not native code; an architecture no platform has comes back under a token of its own (linux-machine-0x3, ...)."""
    def macho(cpu: int) -> str:
        return f"darwin-{MACHO_CPU.get(cpu, f'cpu-{cpu:#x}')}"
    head = data[:4]
    if head == b"\xcf\xfa\xed\xfe" and len(data) >= 8:                     # 64-bit Mach-O, little-endian
        return {macho(struct.unpack_from("<I", data, 4)[0])}
    if head in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return {"darwin-32-bit-or-big-endian"}
    # universal; a Java class file has the same magic, and its version (45 or more) where the count is
    if head in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        n, step = struct.unpack_from(">I", data, 4)[0], 20 if head[3] == 0xBE else 32
        if 0 < n <= 20 and len(data) >= 8 + n * step:
            return {macho(struct.unpack_from(">I", data, 8 + i * step)[0]) for i in range(n)}
        return None
    if head == b"\x7fELF" and len(data) >= 20:
        if data[4] != 2 or data[5] != 1:                                    # ELF64, little-endian
            return {"linux-32-bit-or-big-endian"}
        mach = struct.unpack_from("<H", data, 18)[0]
        return {f"linux-{ELF_MACHINE.get(mach, f'machine-{mach:#x}')}"}
    if data[:2] == b"MZ" and len(data) >= 64:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[off:off + 4] == b"PE\0\0" and len(data) >= off + 24:
            machine = struct.unpack_from("<H", data, off + 4)[0]
            # an x64 header over Arm64EC code (hybrid metadata), as Microsoft's Arm64 runtime libraries ship some
            return {"windows-arm64" if machine == 0x8664 and hybrid(data, off) else coff(machine)}
        return None
    if data[:8] == b"!<arch>\n":                                             # a static or import library
        found = set()
        for member in archive_members(data):
            plats = platforms_of(member)
            if plats is None and len(member) >= 8 and member[:4] == b"\0\0\xff\xff":    # a short import entry
                plats = {coff(struct.unpack_from("<H", member, 6)[0])}
            elif plats is None and len(member) >= 20 and struct.unpack_from("<H", member)[0] in COFF_MACHINES:
                plats = {coff(struct.unpack_from("<H", member)[0])}            # a COFF object
            found |= plats or set()
        return found or None
    return None


def coff(machine: int) -> str:
    return f"windows-{PE_MACHINE.get(machine, f'machine-{machine:#x}')}"


def hybrid(data: bytes, pe: int) -> bool:
    """Whether a PE32+ image carries Arm64EC code: its load configuration points at CHPE metadata."""
    nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B or opt_size < 112 + 8 * 11:
        return False
    rva = struct.unpack_from("<I", data, opt + 112 + 8 * 10)[0]        # data directory 10: the load configuration
    for i in range(nsec):
        _, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)
        if rva and va <= rva < va + max(vsize, rsize):
            at = raw + rva - va
            size = struct.unpack_from("<I", data, at)[0]
            return size >= 0xD0 and struct.unpack_from("<Q", data, at + 0xC8)[0] != 0    # CHPEMetadataPointer
    return False


def archive_members(data: bytes):
    """The members of an ar archive (System V, GNU and BSD names), but its symbol and name tables."""
    pos = 8
    while pos + 60 <= len(data):
        name, size = data[pos:pos + 16].rstrip(), int(data[pos + 48:pos + 58].strip() or 0)
        body = data[pos + 60:pos + 60 + size]
        if name.startswith(b"#1/"):                                         # BSD: the name leads the body
            n = int(name[3:])
            name, body = body[:n].rstrip(b"\0"), body[n:]
        if name not in (b"/", b"//", b"/SYM64/") and not name.startswith(b"__.SYMDEF"):
            yield body
        pos += 60 + size + (size & 1)


def wrong_platforms(root: Path, rules: dict[str, set[str]]) -> list[str]:
    """The native files under `root` without code for every platform `rules` declares for where they sit
    ({DIR: platforms}, "" for the rest)."""
    dirs = sorted(rules, key=len, reverse=True)
    out = []
    for f in files(root):
        if not f.is_file() or f.is_symlink() or TEMPLATES.search(f.as_posix()):
            continue
        with open(f, "rb") as fh:
            data = fh.read(65536)
            if data.startswith((b"!<arch>\n", b"MZ")):                     # members, a load configuration: anywhere
                data += fh.read()
        found = platforms_of(data)
        if found is None:
            continue
        here = os.path.abspath(f)
        want = rules[next(d for d in dirs if not d or Path(here).is_relative_to(d))]
        if not want <= found:
            out.append(f"{f}: code for {', '.join(sorted(found))}, not {', '.join(sorted(want))}")
    return out


def platform_rules(given: list[str]) -> dict[str, set[str]]:
    """--platform values as {absolute DIR or "": platforms}."""
    rules = {}
    for g in given:
        d, _, plats = g.rpartition("=")
        rules[os.path.abspath(d) if d else ""] = set(plats.split(","))
    if "" not in rules:
        raise SystemExit("check-package: --platform PLATFORM (without DIR=) names the package's platforms")
    return rules


def runs_elsewhere(root: Path, python: str, imports: list[str]) -> tuple[str | None, int]:
    """(None, how many extension modules it loaded) when a copy of `root` in another directory starts `python`
    (relative to `root`), imports `imports` and every extension module on its import path, and keeps its prefix, those
    modules and every import path inside itself; else (what went wrong, 0)."""
    probe = PROBE.replace("IMPORTS", repr(imports))
    td = tempfile.mkdtemp(prefix="oarbank-package-check-")
    try:
        copy = Path(td) / "moved"
        shutil.copytree(root, copy, symlinks=True)
        r = subprocess.run([str(copy / python), "-I", "-c", probe], capture_output=True, text=True, cwd=td)
        if r.returncode:
            return f"the moved copy of {root} does not start: {r.stderr.strip()[-500:]}", 0
        seen = json.loads(r.stdout)
        if seen["failed"]:
            return f"the moved copy of {root} does not import {seen['failed']}", 0
        real = copy.resolve()
        outside = [p for p in [seen["prefix"], *seen["modules"], *seen["path"]] if p and not Path(p).resolve().is_relative_to(real)]
        if outside:
            return f"the moved copy of {root} reaches outside itself: {outside}", 0
        return None, len(seen["loaded"])
    finally:
        remove_tree(Path(td))


# what --run runs in the moved copy: the modules named, then every extension module in a package or at the top of an
# import path (lib-dynload, DLLs, site-packages), so each native file it loads was loaded once
PROBE = """\
import importlib, importlib.machinery, json, os, sys
mods = [importlib.import_module(m) for m in IMPORTS]
loaded, failed = [], {}

def walk(d, prefix):
    for e in sorted(os.scandir(d), key=lambda e: e.name):
        if e.is_dir() and e.name.isidentifier() and os.path.exists(os.path.join(e.path, "__init__.py")):
            walk(e.path, prefix + e.name + ".")
        elif e.is_file():
            for suffix in importlib.machinery.EXTENSION_SUFFIXES:
                if e.name.endswith(suffix) and e.name[:-len(suffix)].isidentifier():
                    name = prefix + e.name[:-len(suffix)]
                    try:
                        importlib.import_module(name)
                        loaded.append(name)
                    except Exception as exc:
                        failed[name] = f"{type(exc).__name__}: {exc}"
                    break

for p in [p for p in sys.path if p and os.path.isdir(p)]:
    walk(p, "")
print(json.dumps({"prefix": sys.prefix, "modules": [getattr(m, "__file__", None) or "" for m in mods],
                  "path": [p for p in sys.path if p], "loaded": loaded, "failed": failed}))
"""


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
    ap.add_argument("--platform", action="append", required=True, metavar="[DIR=]PLATFORM[,PLATFORM]")
    a = ap.parse_args(argv)
    rules = platform_rules(a.platform)
    bad = []
    for t in a.trees:
        bad += bad_links(t)
        bad += [f"{f}: names the build path {p}" for f, p in references(t, own_paths(t, a.build_path), account_paths())]
        bad += wrong_platforms(t, rules)
    loaded = []
    if not bad:
        for r in a.run:
            d, py = r.split("=", 1)
            why, n = runs_elsewhere(Path(d), py, a.imports.split(","))
            bad += [why] if why else []
            loaded.append(n)
    for b in bad:
        print(f"check-package: {b}", file=sys.stderr)
    if not bad:
        print(f"check-package: {', '.join(map(str, a.trees))}: no link out, no build path, native code for "
              + "; ".join(f"{d or 'the package'}: {','.join(sorted(p))}" for d, p in rules.items())
              + (f", runs from elsewhere (extension modules loaded: {', '.join(map(str, loaded))})" * bool(a.run)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
