#!/usr/bin/env python3
"""Validate and stage a copy of a format-1 move archive for nFPM; stdlib only.

No archive executable is run, allowing cross-packaging. The archive and manifest
are unchanged; only the package copy gains install-oarbankd.sh at its build root.
"""
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath


def stage(repo: Path, archive: Path, version: str, work: Path) -> None:
    root = work / "coordinator"
    root.mkdir(mode=0o755)
    with tarfile.open(archive, "r:gz") as tf:
        members = {}
        for member in tf.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or any(c in member.name for c in "\n\r\0"):
                raise ValueError("unsafe archive path: " + member.name)
            name = str(path)
            if name in members or not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError("duplicate or unsupported archive member: " + name)
            if member.issym():
                target = PurePosixPath(member.linkname)
                normalized = os.path.normpath(str(path.parent / target))
                if target.is_absolute() or normalized == ".." or normalized.startswith("../"):
                    raise ValueError("symlink escapes archive: " + name)
            members[name] = member
        # No extraction through a symlink (even an internal one) or other file.
        for name in members:
            for parent in PurePosixPath(name).parents:
                if str(parent) in members and not members[str(parent)].isdir():
                    raise ValueError("archive member beneath a non-directory: " + name)
        manifest = members.get("oarbank-coordinator.json")
        if not manifest or not manifest.isfile() or manifest.size > 65536:
            raise ValueError("archive needs a regular format-1 manifest at its root")
        doc = json.load(tf.extractfile(manifest))
        if not isinstance(doc, dict) or type(doc.get("format")) is not int or doc.get("format") != 1 \
                or doc.get("version") != version or doc.get("platform") not in ("linux-amd64", "linux-arm64"):
            raise ValueError("archive format, version or Linux platform does not match")
        for field, default in (("exec", ["bin/oarbankd"]), ("console", ["bin/oarbank-console"])):
            if doc.get(field, default) != default:
                raise ValueError("unsupported coordinator manifest " + field)
        for name, member in members.items():
            dst = root / name
            dst.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            if member.isdir():
                dst.mkdir(exist_ok=True, mode=0o755)
            elif member.isfile():
                with tf.extractfile(member) as src, dst.open("wb") as out:
                    shutil.copyfileobj(src, out)
                dst.chmod(0o755 if member.mode & 0o111 else 0o644)
        for name, member in members.items():
            if member.issym():
                (root / name).symlink_to(member.linkname)
        for path in root.rglob("*"):
            if path.is_symlink():
                # Check chains, loops and dangling links too; all payload links
                # must work after relocation without a build-host dependency.
                target = path.resolve(strict=True)
                if root.resolve() not in target.parents and target != root.resolve():
                    raise ValueError("symlink chain escapes archive: " + str(path))
    for name in ("bin/oarbank-setup", "bin/oarbankd", "bin/oarbank-console", "bin/oarbank", "bin/uv",
                 "bin/oarbank-sandbox", "python/bin/python3"):
        path = root / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("archive needs executable " + name)
    helper = root / "install-oarbankd.sh"
    if helper.is_file() or helper.is_symlink():
        helper.unlink()
    shutil.copyfile(repo / "deploy/oarbankd/install-oarbankd.sh", helper)
    helper.chmod(0o755)
    deploy = repo / "deploy/linux"
    values = {"ARCH": doc["platform"].removeprefix("linux-"), "VERSION": version,
              "ROOT": str(root), "TRAY": str(deploy / "coordinator-tray.py"), "AUTOSTART": str(deploy / "coordinator-autostart.py"), "ICON": str(repo / "docs/assets/logo.svg"), "DESKTOP": str(deploy / "coordinator-desktop.desktop"),
              "REMOVE": str(deploy / "coordinator-remove.py"), "PREREMOVE": str(deploy / "coordinator-preremove.sh")}
    template = (deploy / "coordinator-nfpm.yaml").read_text()
    config = re.sub(r"\$\{(\w+)\}", lambda match: json.dumps(values[match[1]]), template)
    (work / "nfpm.yaml").write_text(config)
    (work / "arch").write_text(values["ARCH"] + "\n")


if __name__ == "__main__":
    try:
        stage(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as exc:
        sys.exit("package-coordinator-linux: " + str(exc))
