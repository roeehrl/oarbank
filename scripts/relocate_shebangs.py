#!/usr/bin/env python3
"""Make a bundled interpreter's console scripts relocatable. pip and uv write each script's interpreter as the absolute
path of the interpreter they installed for, which in a build is a temporary directory, so `oarbank-sdk` and the
dependencies' scripts would not run where the build is unpacked.

- A POSIX script's shebang becomes a header that runs the python beside the script, wherever that is.
- A Windows launcher (`Scripts\\*.exe`) that uv wrote is a trampoline: a PE whose RCDATA resources hold the interpreter
  path (UV_PYTHON_PATH) and the script, a zip whose `__main__.py` starts with a `#!` line naming it (UV_SCRIPT_DATA).
  uv resolves a relative interpreter path from the launcher's directory, so both become relative (`..\\python.exe`).
- A launcher pip (distlib) wrote is a PE stub followed by a `#!` line and a zip. Its stub resolves no relative path, so
  it is not rewritten: the check fails on it.

  scripts/relocate_shebangs.py BIN_DIR [ROOT]    # rewrite BIN_DIR's scripts, then fail if any script or launcher under
                                                 # ROOT (default BIN_DIR) still names an interpreter by absolute path

Stdlib only; build-coordinator.sh, build-node-runtime.sh and build-node-runtime.ps1 run it with the bundled
interpreter."""
from __future__ import annotations

import io
import os
import re
import struct
import sys
import zipfile
from pathlib import Path

# the header written instead: the one python-build-standalone gives its own scripts (sh runs the python beside the
# script, which reads the rest as Python)
POLYGLOT = "#!/bin/sh\n'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")/{python}\" \"$0\" \"$@\"\n' '''\n"
# shebangs that name no build path
PORTABLE = ("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env ")
RT_RCDATA = 10
PYTHON_PATH, SCRIPT_DATA = "UV_PYTHON_PATH", "UV_SCRIPT_DATA"


def _interpreter(text: str) -> tuple[str, int] | None:
    """The interpreter a script's header names and the number of header lines, or None for other files. pip, uv and
    distlib write `#!/abs/python`, or for a long path or one with spaces an sh/python polyglot naming it."""
    lines = text.split("\n", 3)
    if lines[0].startswith("#!/") and not lines[0].startswith(PORTABLE):
        return lines[0][2:].strip(), 1
    if lines[0] == "#!/bin/sh" and len(lines) > 2 and lines[1].startswith("'''exec' ") and lines[2] == "' '''":
        rest = lines[1][len("'''exec' "):]
        if rest[:1] in ("'", '"'):  # a quoted path (distlib quotes one with spaces)
            end = rest.find(rest[0], 1)
            return rest[1:end if end > 0 else None], 3
        return rest.split(" ", 1)[0], 3
    return None


def _read(path: Path) -> str | None:
    try:
        head = path.read_bytes()
    except OSError:
        return None
    if not head.startswith(b"#!") or b"\0" in head[:1024]:
        return None
    return head.decode("utf-8", "surrogateescape")


def _absolute(path: str) -> bool:
    """A POSIX absolute path, or a Windows one (drive, UNC or root-relative)."""
    return path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", path) is not None


# ---------------------------------------------------------------------------------------------- Windows launchers

def _rcdata(pe: bytes) -> dict[str, tuple[int, int, int]]:
    """A PE's named RCDATA resources: name -> (offset of its IMAGE_RESOURCE_DATA_ENTRY, offset of the data, size).
    Empty for anything else."""
    try:
        if pe[:2] != b"MZ":
            return {}
        nt = struct.unpack_from("<I", pe, 0x3C)[0]
        if pe[nt:nt + 4] != b"PE\0\0":
            return {}
        sections, opt_size = struct.unpack_from("<H", pe, nt + 6)[0], struct.unpack_from("<H", pe, nt + 20)[0]
        opt = nt + 24
        dirs = opt + (96 if struct.unpack_from("<H", pe, opt)[0] == 0x10B else 112)
        rsrc_rva = struct.unpack_from("<I", pe, dirs + 2 * 8)[0]  # data directory 2: resources
        table = [struct.unpack_from("<8xIIII", pe, opt + opt_size + 40 * i) for i in range(sections)]

        def offset(rva: int) -> int:
            for vsize, va, raw_size, raw in table:
                if va <= rva < va + max(vsize, raw_size):
                    return raw + rva - va
            raise ValueError(rva)

        base = offset(rsrc_rva) if rsrc_rva else None
        if base is None:
            return {}

        def entries(at: int):
            named, ids = struct.unpack_from("<12xHH", pe, base + at)
            for i in range(named + ids):
                yield struct.unpack_from("<II", pe, base + at + 16 + 8 * i)

        out = {}
        for kind, sub in entries(0):
            if kind != RT_RCDATA or not sub & 0x8000_0000:
                continue
            for name, sub2 in entries(sub & 0x7FFF_FFFF):
                if not name & 0x8000_0000 or not sub2 & 0x8000_0000:
                    continue
                at = base + (name & 0x7FFF_FFFF)
                length = struct.unpack_from("<H", pe, at)[0]
                label = pe[at + 2:at + 2 + 2 * length].decode("utf-16-le")
                for _lang, leaf in entries(sub2 & 0x7FFF_FFFF):
                    if not leaf & 0x8000_0000:  # the first language's data entry
                        entry = base + leaf
                        rva, size = struct.unpack_from("<II", pe, entry)
                        out[label] = (entry, offset(rva), size)
                        break
        return out
    except (struct.error, ValueError, UnicodeDecodeError):
        return {}


def _main_shebang(script_zip: bytes) -> str | None:
    """The `#!` line of a trampoline script's `__main__.py`, without the `#!`."""
    try:
        with zipfile.ZipFile(io.BytesIO(script_zip)) as z:
            first = z.read("__main__.py").split(b"\n", 1)[0]
    except (zipfile.BadZipFile, KeyError):
        return None
    return first[2:].decode("utf-8", "surrogateescape").strip() if first.startswith(b"#!") else None


def _distlib_shebang(pe: bytes) -> str | None:
    """The interpreter of a pip (distlib) launcher: the `#!` line between the PE stub and the zip appended to it."""
    eocd = pe.rfind(b"PK\x05\x06", max(0, len(pe) - 65557))
    if eocd < 0 or pe[:2] != b"MZ":
        return None
    cd_size, cd_offset = struct.unpack_from("<II", pe, eocd + 12)
    start = eocd - cd_size - cd_offset
    bang = pe.rfind(b"#!", max(0, start - 4096), start)
    if bang < 0:
        return None
    line = pe[bang + 2:start].decode("utf-8", "surrogateescape").strip()
    if line.startswith('"'):
        return line[1:].split('"', 1)[0]
    return line.split(" ", 1)[0]


def launcher_interpreters(pe: bytes) -> list[str]:
    """Every interpreter path a Windows launcher names (none for any other file)."""
    res = _rcdata(pe)
    if PYTHON_PATH in res:
        _, at, size = res[PYTHON_PATH]
        found = [pe[at:at + size].decode("utf-8", "surrogateescape")]
        if SCRIPT_DATA in res:
            _, at, size = res[SCRIPT_DATA]
            found += [s for s in [_main_shebang(pe[at:at + size])] if s]
        return found
    return [s for s in [_distlib_shebang(pe)] if s]


def _put(pe: bytearray, res: dict[str, tuple[int, int, int]], name: str, data: bytes) -> None:
    """Replace a resource's data in place (never longer), zero the rest and set its size."""
    entry, at, size = res[name]
    if len(data) > size:
        raise ValueError(f"{name}: {len(data)} bytes do not fit in {size}")
    pe[at:at + size] = data + bytes(size - len(data))
    struct.pack_into("<I", pe, entry + 4, len(data))


def _relocate_trampoline(path: Path, bin_dir: Path) -> bool:
    """Point a uv trampoline at its interpreter relative to bin_dir, when that interpreter is the bundled one (in
    bin_dir or its parent). True when rewritten."""
    pe = bytearray(path.read_bytes())
    res = _rcdata(pe)
    if PYTHON_PATH not in res:
        return False
    _, at, size = res[PYTHON_PATH]
    python = pe[at:at + size].decode("utf-8", "surrogateescape")
    if not _absolute(python):  # already relative
        return False
    home = os.path.normcase(os.path.realpath(os.path.dirname(python)))
    if not os.path.basename(python).lower().startswith("python") or home not in {
            os.path.normcase(os.path.realpath(bin_dir)), os.path.normcase(os.path.realpath(bin_dir.parent))}:
        return False
    rel = os.path.relpath(os.path.realpath(python), os.path.realpath(bin_dir))
    _put(pe, res, PYTHON_PATH, rel.encode())
    if SCRIPT_DATA in res:
        _, at, size = res[SCRIPT_DATA]
        old = zipfile.ZipFile(io.BytesIO(bytes(pe[at:at + size])))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as new:
            for info in old.infolist():
                body = old.read(info)
                if info.filename == "__main__.py" and body.startswith(b"#!"):
                    body = b"#!" + rel.encode() + b"\n" + body.split(b"\n", 1)[1]
                new.writestr(info, body)
        _put(pe, res, SCRIPT_DATA, buf.getvalue())
    path.write_bytes(pe)
    return True


# ---------------------------------------------------------------------------------------------- both

def relocate(bin_dir: Path) -> list[str]:
    """Rewrite every script and uv launcher in bin_dir whose interpreter is the bundled python (in bin_dir, or for a
    Windows launcher also its parent); returns the names rewritten."""
    real = bin_dir.resolve()
    done = []
    for path in sorted(bin_dir.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() == ".exe":
            if _relocate_trampoline(path, bin_dir):
                done.append(path.name)
            continue
        if (text := _read(path)) is None or not (found := _interpreter(text)):
            continue
        python, n = found
        target = Path(python)
        if not target.name.startswith("python") or Path(os.path.realpath(target.parent)) != real:
            continue
        body = text.split("\n", n)[n] if text.count("\n") >= n else ""
        mode = path.stat().st_mode
        path.write_text(POLYGLOT.format(python=target.name) + body, encoding="utf-8", errors="surrogateescape")
        path.chmod(mode)
        done.append(path.name)
    return done


def problems(root: Path) -> list[str]:
    """Scripts (in a bin or Scripts directory) and Windows launchers (any .exe) under root that name an interpreter
    by absolute path (a build path, or the build host's)."""
    out = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() == ".exe":
            out += [f"{rel}: {p}" for p in dict.fromkeys(launcher_interpreters(path.read_bytes())) if _absolute(p)]
        elif path.parent.name in ("bin", "Scripts") and (text := _read(path)) is not None \
                and (found := _interpreter(text)) and _absolute(found[0]):
            out.append(f"{rel}: {found[0]}")
    return out


def main(argv: list[str]) -> int:
    bin_dir = Path(argv[0])
    relocate(bin_dir)
    bad = problems(Path(argv[1]) if len(argv) > 1 else bin_dir)
    for line in bad:
        print(f"relocate_shebangs: not relocatable: {line}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) if sys.argv[1:] else "usage: relocate_shebangs.py BIN_DIR [ROOT]")
