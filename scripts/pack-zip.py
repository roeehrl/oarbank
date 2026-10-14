#!/usr/bin/env python3
"""Write a .zip of the files NAMES under ROOT whose bytes depend only on those files' contents: the entries in the order
given, '/' in their names, a fixed time (2000-01-01 00:00), the same attributes (a regular file, 0644, made on Unix),
no extra fields, and stored, not compressed (a deflater's output can differ between builds of zlib; the two Windows
jobs each build the Group Policy template's zip, and its one published copy must match both architectures' sums
files). scripts/package-windows.ps1 zips the Group Policy template with it. Stdlib only.

  scripts/pack-zip.py OUT.zip ROOT NAME..."""
import sys
import zipfile
from pathlib import Path

WHEN = (2000, 1, 1, 0, 0, 0)


def entry(name: str) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name, WHEN)
    zi.create_system = 3                        # Unix: ZipInfo says 0 on Windows, 3 elsewhere
    zi.create_version = zi.extract_version = 20
    zi.external_attr = 0o100644 << 16
    zi.compress_type = zipfile.ZIP_STORED
    return zi


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.rsplit("\n\n", 1)[-1].strip(), file=sys.stderr)
        return 2
    out, root, names = Path(argv[0]), Path(argv[1]), [n.replace("\\", "/") for n in argv[2:]]
    for n in names:
        if not (root / n).is_file():
            print(f"pack-zip: {root / n} is not a file", file=sys.stderr)
            return 1
    tmp = out.with_name(out.name + ".tmp")
    with zipfile.ZipFile(tmp, "w") as z:
        for n in names:
            z.writestr(entry(n), (root / n).read_bytes())
    tmp.replace(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
