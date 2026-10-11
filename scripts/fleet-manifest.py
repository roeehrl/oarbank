#!/usr/bin/env python3
"""Write a version's fleet release manifest, oarbank-fleet-<version>.json, from the release assets in a directory
(PLAN D56; docs/design/fleet-updates.md, "The fleet release manifest"). CI runs it on the release's dist/; the owner
signs the result (`oarbank update sign <version>`) and the vendor lists it as a TUF target (scripts/tuf_vendor.py add).

    scripts/fleet-manifest.py <version> <dist-dir> [--seq N] [--agent-min V] [--stops V,...] [--out PATH]
                              [--released-at ISO|EPOCH] [--expires ISO] [--notes URL]

Each asset is classified by its name, as the packaging scripts write them:

    oarbank-agent-<v>-macos-<arm64|x86_64>.pkg           node         darwin-<arm64|amd64>   pkg     package-macos.sh
    oarbank-agent_<v>_<amd64|arm64>.deb                  node         linux-<arch>           deb     package-linux.sh (nfpm)
    oarbank-agent-<v>-<release>.<x86_64|aarch64>.rpm     node         linux-<arch>           rpm     package-linux.sh (nfpm)
    oarbank-agent-<v>-linux-<amd64|arm64>.tar.gz         node         linux-<arch>           tar     package-linux.sh
    oarbank-agent-<v>-windows-<x64|arm64>.msi            node         windows-<amd64|arm64>  msi     package-windows.ps1
    oarbank-agent-<v>-<darwin|linux>-<amd64|arm64>       agent        <os>-<arch>            binary  package-macos/linux
    oarbank-agent-<v>-windows-<x64|arm64>.exe            agent        windows-<amd64|arm64>  binary  package-windows.ps1
    oarbank-coordinator-<v>-<os>-<amd64|arm64>.tar.gz    coordinator  <os>-<arch>            tar     build-coordinator.*

Everything else (SHA256SUMS-*, the one-line installers, install-oarbankd.*, the ADMX zip, other versions' files, and the
coordinator's native packages, which an administrator installs and the coordinator's self-update never does: D58
installs the build archive side by side) is not an artifact of the fleet release. A pre-release's deb and rpm carry
nFPM's `~` form of the version (2.10.0~rc.1).

The manifest is canonical JSON, and its bytes are what both signatures sign: `json.dumps(manifest, sort_keys=True,
separators=(",", ":"))` with ASCII escapes (Python's ensure_ascii), encoded as ASCII, no trailing newline, no byte
order mark. Nobody re-serializes it: the coordinator stores and serves this exact text, and every party hashes those
bytes (`manifest_sha256`). `seq` is major*10000 + minor*100 + patch unless --seq gives it (a minor or patch above 99
must give it); `agent_min` defaults to the previous minor's .0; `stops` to none.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

FORMAT = 1
NOTES = "https://github.com/roeehrl/oarbank/releases/tag/v{version}"
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]+)?$")

ARCH = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64", "x64": "amd64"}
OS = {"macos": "darwin", "darwin": "darwin", "linux": "linux", "windows": "windows"}


def parse_version(v: str) -> tuple[int, int, int]:
    m = VERSION_RE.match(v)
    if not m:
        raise ValueError(f"not a version: {v!r} (major.minor.patch[-pre])")
    return int(m[1]), int(m[2]), int(m[3])


def default_seq(version: str) -> int:
    major, minor, patch = parse_version(version)
    if minor > 99 or patch > 99:
        raise ValueError(f"{version}: minor and patch above 99 overlap the next version's seq: give --seq")
    return major * 10000 + minor * 100 + patch


def default_agent_min(version: str) -> str:
    major, minor, _ = parse_version(version)
    return f"{major}.{minor - 1}.0" if minor else f"{major}.0.0"


def patterns(version: str) -> list[tuple[re.Pattern, str, str]]:
    """(name pattern, role, format); the pattern's `os` and `arch` groups give the platform."""
    v = re.escape(version)
    # nFPM writes a pre-release's deb and rpm with `~` (sorts before the release in dpkg and rpm)
    vt = re.escape(version.replace("-", "~", 1))
    alt = f"(?:{v}|{vt})" if vt != v else v
    return [
        (re.compile(rf"^oarbank-agent-{v}-(?P<os>macos)-(?P<arch>arm64|x86_64)\.pkg$"), "node", "pkg"),
        (re.compile(rf"^oarbank-agent_{alt}_(?P<arch>amd64|arm64)\.deb$"), "node", "deb"),
        (re.compile(rf"^oarbank-agent-{alt}-\d+\.(?P<arch>x86_64|aarch64)\.rpm$"), "node", "rpm"),
        (re.compile(rf"^oarbank-agent-{v}-(?P<os>linux)-(?P<arch>amd64|arm64)\.tar\.gz$"), "node", "tar"),
        (re.compile(rf"^oarbank-agent-{v}-(?P<os>windows)-(?P<arch>x64|arm64)\.msi$"), "node", "msi"),
        (re.compile(rf"^oarbank-agent-{v}-(?P<os>darwin|linux)-(?P<arch>amd64|arm64)$"), "agent", "binary"),
        (re.compile(rf"^oarbank-agent-{v}-(?P<os>windows)-(?P<arch>x64|arm64)\.exe$"), "agent", "binary"),
        (re.compile(rf"^oarbank-coordinator-{v}-(?P<os>darwin|linux|windows)-(?P<arch>amd64|arm64)\.tar\.gz$"),
         "coordinator", "tar"),
    ]


def classify(name: str, version: str) -> dict | None:
    """{role, platform, format} for a release asset's file name, or None when it is no artifact of the fleet release."""
    for pat, role, fmt in patterns(version):
        m = pat.match(name)
        if m:
            os_ = OS[m.groupdict().get("os") or "linux"]           # deb and rpm are Linux's
            return {"role": role, "platform": f"{os_}-{ARCH[m['arch']]}", "format": fmt}
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def artifacts(version: str, dist: Path) -> list[dict]:
    out, seen = [], {}
    for p in sorted(dist.iterdir(), key=lambda p: p.name):
        if not p.is_file() or p.is_symlink():
            continue
        c = classify(p.name, version)
        if c is None:
            continue
        key = (c["role"], c["platform"], c["format"])
        if key in seen:
            raise ValueError(f"{p.name} and {seen[key]} are both the {c['format']} {c['role']} for {c['platform']}")
        seen[key] = p.name
        a = {"name": p.name, **c, "sha256": sha256_file(p), "size": p.stat().st_size}
        if c["role"] in ("node", "agent"):
            a["agent_version"] = version
        out.append(a)
    if not out:
        raise ValueError(f"no artifact of {version} in {dist}")
    return sorted(out, key=lambda a: (a["role"], a["platform"], a["format"], a["name"]))


def timestamp(value: str | None) -> str:
    """ISO 8601 UTC seconds: the value (an ISO time or epoch seconds), else SOURCE_DATE_EPOCH, else now."""
    if value is None:
        value = os.environ.get("SOURCE_DATE_EPOCH") or None
    if value is None:
        t = dt.datetime.now(dt.timezone.utc)
    elif re.fullmatch(r"\d+", value):
        t = dt.datetime.fromtimestamp(int(value), dt.timezone.utc)
    else:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t.tzinfo is None:
            raise ValueError(f"{value}: give a time zone (Z)")
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest(version: str, dist: Path, *, seq: int | None = None, agent_min: str | None = None,
             stops: list[str] | None = None, released_at: str | None = None, expires: str | None = None,
             notes: str | None = None) -> dict:
    parse_version(version)
    stops = sorted(set(stops or []), key=parse_version)
    for s in stops:
        if parse_version(s) >= parse_version(version):
            raise ValueError(f"stop {s} is not older than {version}")
    agent_min = agent_min or default_agent_min(version)
    parse_version(agent_min)
    return {
        "type": "oarbank-fleet-release", "format": FORMAT,
        "version": version, "seq": default_seq(version) if seq is None else seq,
        "released_at": timestamp(released_at), "expires": timestamp(expires) if expires else None,
        "notes": notes or NOTES.format(version=version),
        "agent_min": agent_min, "stops": stops,
        "artifacts": artifacts(version, dist),
    }


def canonical(m: dict) -> bytes:
    """The manifest's exact bytes (what is signed and hashed): sorted keys, no whitespace, ASCII, no newline."""
    return json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version")
    ap.add_argument("dist", type=Path)
    ap.add_argument("--seq", type=int)
    ap.add_argument("--agent-min")
    ap.add_argument("--stops", default="", help="comma-separated versions a node older than them must pass through")
    ap.add_argument("--out", type=Path, help="default: <dist>/oarbank-fleet-<version>.json")
    ap.add_argument("--released-at", help="ISO time or epoch seconds (default: SOURCE_DATE_EPOCH, else now)")
    ap.add_argument("--expires", help="ISO time after which the release is uninstallable (freeze protection)")
    ap.add_argument("--notes", help="the release notes' URL (default: the project's GitHub release)")
    a = ap.parse_args(argv)
    version = a.version.removeprefix("v")
    try:
        if a.seq is not None and a.seq < 0:
            raise ValueError("--seq must not be negative")
        m = manifest(version, a.dist, seq=a.seq, agent_min=a.agent_min,
                     stops=[s.strip().removeprefix("v") for s in a.stops.split(",") if s.strip()],
                     released_at=a.released_at, expires=a.expires, notes=a.notes)
    except (ValueError, OSError) as e:
        print(f"fleet-manifest: {e}", file=sys.stderr)
        return 2
    out = a.out or a.dist / f"oarbank-fleet-{version}.json"
    data = canonical(m)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, out)
    print(f"{out} seq={m['seq']} artifacts={len(m['artifacts'])} sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
