#!/usr/bin/env python3
"""The vendor's TUF repository for agent builds (PLAN D31; the agent's client is rust/crates/oarbank-agent/src/tuf.rs).
The owner runs this on the machine that holds the keys; CI holds none.

  scripts/tuf_vendor.py init KEYS REPO               # four ed25519 keys (root, targets, snapshot, timestamp) and root v1
  scripts/tuf_vendor.py add KEYS REPO NAME FILE      # list FILE as target NAME (e.g. oarbank-agent-1.0.0-darwin-arm64)
  scripts/tuf_vendor.py timestamp KEYS REPO          # re-sign snapshot and timestamp (before they expire)
  scripts/tuf_vendor.py rotate-root KEYS REPO ROLE   # a new key for ROLE, root N+1 signed by the old and new root keys

Build release agents with `OARBANK_TUF_ROOT=REPO/root.json` (the agent pins that root and follows rotations), then
mirror REPO's metadata on each coordinator: `oarbank vendor-metadata upload REPO`.

Metadata follows the TUF specification 1.0: OLPC canonical JSON signed with ed25519, key ids the sha256 of the hex
public key, no delegations, no consistent snapshots. Keep the root key offline; the timestamp key is the one that
signs most often.
"""
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLES = ("root", "targets", "snapshot", "timestamp")
EXPIRES_DAYS = {"root": 365, "targets": 180, "snapshot": 30, "timestamp": 7}
SPEC = "1.0.31"


def canonical(v) -> bytes:
    """OLPC canonical JSON (as securesystemslib signs): sorted keys, no whitespace, only \\ and " escaped."""
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if v is None:
        return b"null"
    if isinstance(v, int):
        return str(v).encode()
    if isinstance(v, float):
        raise ValueError("no floats in TUF metadata")
    if isinstance(v, str):
        return b'"' + v.replace("\\", "\\\\").replace('"', '\\"').encode() + b'"'
    if isinstance(v, list):
        return b"[" + b",".join(canonical(x) for x in v) + b"]"
    if isinstance(v, dict):
        return b"{" + b",".join(canonical(k) + b":" + canonical(v[k]) for k in sorted(v)) + b"}"
    raise TypeError(type(v))


def expires(days: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_key(keys: Path, role: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key((keys / f"{role}.pem").read_bytes(), password=None)


def public(k: Ed25519PrivateKey) -> dict:
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": pub}}


def keyid(k: Ed25519PrivateKey) -> str:
    return hashlib.sha256(public(k)["keyval"]["public"].encode()).hexdigest()


def sign(signed: dict, *keys: Ed25519PrivateKey) -> dict:
    msg = canonical(signed)
    return {"signed": signed, "signatures": [{"keyid": keyid(k), "sig": k.sign(msg).hex()} for k in keys]}


def write(repo: Path, name: str, doc: dict) -> bytes:
    data = json.dumps(doc, indent=1, sort_keys=True).encode()
    (repo / name).write_bytes(data)
    return data


def read(repo: Path, name: str) -> dict:
    return json.loads((repo / name).read_text())


def new_key(keys: Path, role: str) -> Ed25519PrivateKey:
    k = Ed25519PrivateKey.generate()
    p = keys / f"{role}.pem"
    p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(p, 0o600)
    return k


def root_doc(version: int, keys: dict) -> dict:
    return {"_type": "root", "spec_version": SPEC, "version": version, "expires": expires(EXPIRES_DAYS["root"]),
            "consistent_snapshot": False, "keys": {keyid(k): public(k) for k in keys.values()},
            "roles": {r: {"keyids": [keyid(keys[r])], "threshold": 1} for r in ROLES}}


def init(keys: Path, repo: Path):
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(keys, 0o700)
    repo.mkdir(parents=True, exist_ok=True)
    ks = {r: new_key(keys, r) for r in ROLES}
    root = sign(root_doc(1, ks), ks["root"])
    write(repo, "root.json", root)
    write(repo, "1.root.json", root)
    write(repo, "targets.json", sign({"_type": "targets", "spec_version": SPEC, "version": 1,
                                      "expires": expires(EXPIRES_DAYS["targets"]), "targets": {}}, ks["targets"]))
    timestamp(keys, repo)


def timestamp(keys: Path, repo: Path):
    """snapshot (naming targets.json) and timestamp (naming snapshot.json), each one version up."""
    tb = (repo / "targets.json").read_bytes()
    tv = json.loads(tb)["signed"]["version"]
    old_s = json.loads((repo / "snapshot.json").read_text())["signed"]["version"] if (repo / "snapshot.json").exists() else 0
    snap = sign({"_type": "snapshot", "spec_version": SPEC, "version": old_s + 1, "expires": expires(EXPIRES_DAYS["snapshot"]),
                 "meta": {"targets.json": {"version": tv, "hashes": {"sha256": hashlib.sha256(tb).hexdigest()}}}},
                load_key(keys, "snapshot"))
    sb = write(repo, "snapshot.json", snap)
    old_t = json.loads((repo / "timestamp.json").read_text())["signed"]["version"] if (repo / "timestamp.json").exists() else 0
    write(repo, "timestamp.json", sign({"_type": "timestamp", "spec_version": SPEC, "version": old_t + 1,
                                        "expires": expires(EXPIRES_DAYS["timestamp"]),
                                        "meta": {"snapshot.json": {"version": old_s + 1, "length": len(sb),
                                                                   "hashes": {"sha256": hashlib.sha256(sb).hexdigest()}}}},
                                       load_key(keys, "timestamp")))


def add(keys: Path, repo: Path, name: str, file: Path):
    data = file.read_bytes()
    t = read(repo, "targets.json")["signed"]
    t["targets"][name] = {"length": len(data), "hashes": {"sha256": hashlib.sha256(data).hexdigest()}}
    t["version"] += 1
    t["expires"] = expires(EXPIRES_DAYS["targets"])
    write(repo, "targets.json", sign(t, load_key(keys, "targets")))
    timestamp(keys, repo)


def rotate_root(keys: Path, repo: Path, role: str):
    old_root_key = load_key(keys, "root")
    cur = read(repo, "root.json")["signed"]
    ks = {r: load_key(keys, r) for r in ROLES}
    ks[role] = new_key(keys, role)
    doc = root_doc(cur["version"] + 1, ks)
    signers = [old_root_key] + ([ks["root"]] if role == "root" else [])
    root = sign(doc, *signers)
    write(repo, "root.json", root)
    write(repo, f"{doc['version']}.root.json", root)
    if role == "targets":
        t = read(repo, "targets.json")["signed"]
        t["version"] += 1
        write(repo, "targets.json", sign(t, ks["targets"]))
    timestamp(keys, repo)


def main(argv: list[str]):
    if len(argv) < 3:
        sys.exit(__doc__)
    cmd, keys, repo = argv[0], Path(argv[1]), Path(argv[2])
    if cmd == "init":
        init(keys, repo)
    elif cmd == "add" and len(argv) == 5:
        add(keys, repo, argv[3], Path(argv[4]))
    elif cmd == "timestamp":
        timestamp(keys, repo)
    elif cmd == "rotate-root" and len(argv) == 4 and argv[3] in ROLES:
        rotate_root(keys, repo, argv[3])
    else:
        sys.exit(__doc__)
    print(f"{repo}: " + ", ".join(sorted(p.name for p in repo.glob("*.json"))))


if __name__ == "__main__":
    main(sys.argv[1:])
