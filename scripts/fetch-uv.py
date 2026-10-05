#!/usr/bin/env python3
"""Fetch the uv a package ships for a platform: its release asset from GitHub, checked against the pin below, and the
one executable from it written to DEST. The node runtimes (scripts/build-node-runtime.*) and the Windows coordinator
build (scripts/build-coordinator.ps1) ship it; the package is for the platform named, whatever the build machine's own
uv is. The version is the one CI installs (setup-uv in .github/workflows/ci.yml). Stdlib only.

  scripts/fetch-uv.py PLATFORM DEST        # PLATFORM: darwin-arm64, linux-amd64, ... (spec/platforms.md)"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "0.12.22"
# the release's target per platform, and the SHA-256 of its asset (the release's own .sha256 files)
ASSETS = {
    "darwin-arm64": ("aarch64-apple-darwin", "5d714de09501a59393ceca78f4bc232a50478729640d251907160299b2a93ddd"),
    "darwin-amd64": ("x86_64-apple-darwin", "1b8a5b316883df2daf20fb9a446e5b230e01d947d57aba2694977c5ac5a7e98c"),
    "linux-arm64": ("aarch64-unknown-linux-gnu", "6f66a14e8239871fb477f9746c941fedfa77e8fe28a8bc7c07e1dc7f53a66712"),
    "linux-amd64": ("x86_64-unknown-linux-gnu", "b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b"),
    "windows-arm64": ("aarch64-pc-windows-msvc", "6a42b919c2bb7135f07b4d1bb8e489f0eaab0bae039020573cc522d831e2d32e"),
    "windows-amd64": ("x86_64-pc-windows-msvc", "ea1397797a0ca15f63516dd0f49c2dde9776db9be5861cab152ebe8ad199894d"),
}


def fetch(platform: str, dest: Path) -> None:
    target, sha = ASSETS[platform]
    windows = platform.startswith("windows-")
    asset = f"uv-{target}.{'zip' if windows else 'tar.gz'}"
    url = f"https://github.com/astral-sh/uv/releases/download/{VERSION}/{asset}"
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != sha:
        raise SystemExit(f"fetch-uv: {asset} {VERSION} does not match its pin")
    if windows:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            exe = z.read("uv.exe")
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            exe = t.extractfile(f"uv-{target}/uv").read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp")
    tmp.write_bytes(exe)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dest)
    print(f"fetch-uv: uv {VERSION} for {platform} -> {dest}")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ASSETS:
        print(f"usage: fetch-uv.py {{{','.join(ASSETS)}}} DEST", file=sys.stderr)
        return 2
    fetch(argv[0], Path(argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
