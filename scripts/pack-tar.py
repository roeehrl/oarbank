#!/usr/bin/env python3
"""Write a .tar.gz of NAMES under ROOT that says nothing about the machine that built it: every entry owned by uid and
gid 0 with no user or group name (tar writes the build account's otherwise), symbolic links kept as links, and no
AppleDouble files. scripts/build-coordinator.sh and scripts/build-coordinator.ps1 archive the coordinator build with
it. Stdlib only.

  scripts/pack-tar.py OUT.tar.gz ROOT NAME..."""
import sys
import tarfile
from pathlib import Path


def anonymous(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.rsplit("\n\n", 1)[-1].strip(), file=sys.stderr)
        return 2
    out, root, names = Path(argv[0]), Path(argv[1]), argv[2:]
    with tarfile.open(out, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for n in names:
            tf.add(root / n, arcname=n, filter=anonymous)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
