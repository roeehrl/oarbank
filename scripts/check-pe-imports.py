#!/usr/bin/env python3
"""Fail if a Windows executable imports a DLL that a clean Windows install does not have (the Visual C++ runtime).
scripts/package-windows.ps1 runs it on the agent and launcher (scripts/check-package.py checks their architecture).
Stdlib only: reads the PE headers and import directory.

  scripts/check-pe-imports.py EXE..."""
import struct
import sys

# present on every Windows 10/11 install; the dynamic C runtime (VCRUNTIME140*, MSVCP140*, ucrtbased) is not, and
# api-ms-win-crt-* would only resolve where the Universal CRT happens to be present, so static CRT avoids both
FORBIDDEN = ("vcruntime", "msvcp", "ucrtbased", "api-ms-win-crt-", "concrt", "vccorlib")


def imports(path: str) -> list[str]:
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"{path}: not a PE file")
    nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (112 if magic == 0x20B else 96)            # PE32+ or PE32
    imp_rva = struct.unpack_from("<I", data, dirs + 8)[0]  # data directory 1: imports
    secs = [struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i) for i in range(nsec)]

    def off(rva: int) -> int:
        for _, vsize, va, rsize, raw in secs:
            if va <= rva < va + max(vsize, rsize):
                return raw + rva - va
        raise ValueError(f"{path}: rva {rva:#x} outside every section")

    names, d = [], off(imp_rva) if imp_rva else None
    while d is not None:
        name_rva = struct.unpack_from("<I", data, d + 12)[0]
        if not name_rva:
            break
        o = off(name_rva)
        names.append(data[o:data.index(b"\0", o)].decode("ascii"))
        d += 20
    return names


def main(args: list[str]) -> int:
    bad = 0
    for p in args:
        dlls = imports(p)
        hits = [n for n in dlls if n.lower().startswith(FORBIDDEN)]
        print(f"{p}: {', '.join(dlls)}")
        if hits:
            print(f"{p}: imports {', '.join(hits)}, which a clean Windows install does not have", file=sys.stderr)
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) if sys.argv[1:] else "usage: check-pe-imports.py <exe>...")
