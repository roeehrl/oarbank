"""Rescue moves (docs/design/coordinator-move.md, "If something goes wrong"): in signing mode, a fresh coordinator takes
over a fleet whose coordinator is compromised or lost, from a copy of the old coordinator's home.

1. On the new machine, with OARBANKD_HOME naming a new home:
       python -m oarbank.coordinator.rescue adopt <copy of the old home> --url https://<this machine>:7443
   copies the fleet's data, gives this coordinator its own identity key, audit key and TLS CA, keeps the old CA only
   to verify the client certificates the nodes hold (each node renews under the new CA at its first hello), stays a
   standby (it serves no agent), and writes <home>/rescue-request.json.
2. Where the owner keys are: `oarbank owner rescue-move --request rescue-request.json --out move.json`.
3. On the new machine: `python -m oarbank.coordinator.rescue sign move.json` checks the move against the adopted fleet,
   adds this coordinator's signature, records the move and makes this coordinator active at the move's epoch.
4. Start oarbankd and publish move.json at a rescue location of the owner key set. An agent reads it there once its
   coordinator has been unreachable for 30 minutes (and every 6 hours in any case), verifies it like any move (the
   next epoch, from the key it trusts, signed by this coordinator and an owner key) and follows it to this one.
"""
import argparse
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from . import config as C
from . import audit, identity, owner, tlsca
from .db import DB

# what a rescue never takes from the old home: its identity and secrets, its move and process state, its TLS (the
# old CA's certificate is read separately), machine-specific module runtimes, and its own backups and logs
NOT_ADOPTED = {"oarbank.sqlite3", "oarbank.sqlite3-wal", "oarbank.sqlite3-shm", "coordinator_key", identity.MARKER,
               "FINALIZED", "move", "tls", "run", "keys", "console.secret", "admin.token", "backups", "logs",
               "rescue-request.json"}
REQUEST = "rescue-request.json"


class RescueError(Exception):
    pass


def adopt(old: Path, url: str, home: Path | None = None) -> dict:
    """Take the fleet's data from `old` into the new `home`; returns the request the owner signs a move for."""
    home, old = Path(home or C.HOME), Path(old)
    if not (old / "oarbank.sqlite3").is_file() or not (old / "tls" / "ca.pem").is_file():
        raise RescueError(f"{old} is not a coordinator home (oarbank.sqlite3 and tls/ca.pem)")
    if (home / "oarbank.sqlite3").exists() and DB(home / "oarbank.sqlite3").one("SELECT COUNT(*) n FROM nodes")["n"]:
        raise RescueError(f"{home} already holds a fleet")
    from ..platform import files
    files.private_dir(home)
    for side in ("", "-wal", "-shm"):
        (home / f"oarbank.sqlite3{side}").unlink(missing_ok=True)
    src = sqlite3.connect(f"file:{old / 'oarbank.sqlite3'}?mode=ro", uri=True)
    dst = sqlite3.connect(home / "oarbank.sqlite3")
    try:
        src.backup(dst)                        # a consistent copy, whatever the old WAL holds
    finally:
        src.close()
        dst.close()
    for p in sorted(old.rglob("*")):
        rel = p.relative_to(old)
        if rel.parts[0] in NOT_ADOPTED or ".venv" in rel.parts or not p.is_file():
            continue
        (home / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, home / rel)
    db = DB(home / "oarbank.sqlite3")
    if not (C.RELEASE_SIGNING and owner.anchors(db)):
        raise RescueError("a rescue needs signing mode and an owner key set: agents follow no other move from a lost coordinator")
    old_cik = db.get_state("coordinator_cik")
    fid = identity.fleet_id(db)
    tlsca.ensure_ca(home, fid)
    tlsca.trust_adopted_ca(home, (old / "tls" / "ca.pem").read_text(encoding="utf-8"))
    with db.tx():
        identity.set_role(db, "standby")
        for k in ("move_phase", "move_commit_decided", "move_rules_plan", "move_blockers", "move_postflight_pending"):
            db.set_state(k, None)
        db.x("UPDATE coordinator_plans SET state='done' WHERE state NOT IN ('done','cancelled')")
        db.x("UPDATE nodes SET client_cert_not_after=0")      # every node renews under this CA at its first hello
        req = {"fleet_id": fid, "epoch": identity.epoch(db) + 1, "from_cik": old_cik,
               "to": {"url": url.rstrip("/"), "cik": identity.key(home).public_b64, "audit_pubkey": audit.Signer().public_b64}}
        db.set_state("rescue_request", req)
        db.event("coordinator_rescue_adopted", reason=f"fleet {fid} from {old}, epoch {req['epoch']} pending")
    files.write_private(home / REQUEST, json.dumps(req, indent=1) + "\n")
    return req


def sign(path: Path, home: Path | None = None) -> dict:
    """Check the owner-signed move against the adopted fleet, add this coordinator's signature and take the fleet over."""
    home = Path(home or C.HOME)
    db = DB(home / "oarbank.sqlite3")
    req = db.get_state("rescue_request")
    if not req:
        raise RescueError("nothing to sign: adopt a fleet first (python -m oarbank.coordinator.rescue adopt)")
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    mv = d["coordinator_move"]
    stmt = json.loads(mv["statement"])
    k = identity.key(home)
    want = {"type": identity.MOVE_TYPE, "rescue": True, "fleet_id": req["fleet_id"], "epoch": req["epoch"]}
    if {f: stmt.get(f) for f in want} != want or stmt["from"]["cik"] != req["from_cik"] or stmt["to"] != {
            **req["to"], "ts_stable_node_id": stmt["to"].get("ts_stable_node_id"), "required_tag": None}:
        raise RescueError(f"this move is not the rescue this coordinator ({k.fingerprint[:16]}) asked for: {REQUEST}")
    if not owner.verify_any(db, mv["statement"], mv["signatures"].get("owner")):
        raise RescueError("the move is not signed by a key of the fleet's owner key set")
    mv["signatures"]["to"] = k.sign(mv["statement"])
    Path(path).write_text(json.dumps(d, indent=1) + "\n", encoding="utf-8", newline="\n")
    last = db.one("SELECT MAX(last_event_id) m FROM audit_digests")["m"]
    with db.tx():
        db.set_state("coordinator_epoch", int(stmt["epoch"]))
        identity.set_role(db, "active")
        db.set_state("coordinator_url", stmt["to"]["url"])
        db.set_state("coordinator_cik", k.public_b64)
        db.set_state("move_phase", "idle")
        db.set_state("reaper_grace_until", time.time() + C.LEASE_TTL + 120)
        db.set_state("audit_rescue", {"after": last, "statement": mv["statement"], "owner_sig": mv["signatures"]["owner"]})
        db.set_state("rescue_request", None)
        db.x("INSERT INTO coordinator_moves(move_id,plan_id,epoch,statement,sig_from,sig_to,sig_owner,state,created_at,"
             "not_before,ended_at,actor,reason) VALUES(?,NULL,?,?,NULL,?,?,'committed',?,?,?,'owner','rescue')",
             (stmt["move_id"], stmt["epoch"], mv["statement"], mv["signatures"]["to"], mv["signatures"]["owner"],
              time.time(), stmt["not_before"], time.time()))
        audit.append(db, actor="owner", source="cli", operation="coordinator.rescue", category="modify",
                     target_type="coordinator", target_id=stmt["to"]["url"], outcome="ok", request_id=audit.request_id(),
                     reason=f"rescue move {stmt['move_id']} to epoch {stmt['epoch']}", after={"statement": mv["statement"]})
        db.event("coordinator_rescued", reason=f"epoch {stmt['epoch']}: {stmt['move_id']}")
    from . import modlife
    modlife.runtimes_ok(db)                   # module runtimes were not adopted
    return {"signed": str(path), "move_id": stmt["move_id"], "epoch": stmt["epoch"], "to": stmt["to"]["url"]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m oarbank.coordinator.rescue", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("adopt", help="take a fleet's data from a copy of its lost coordinator's home")
    a.add_argument("old_home")
    a.add_argument("--url", required=True, help="this coordinator's agent URL as agents will reach it")
    s = sub.add_parser("sign", help="sign the owner's rescue move and take the fleet over")
    s.add_argument("move")
    args = ap.parse_args(argv)
    try:
        out = adopt(Path(args.old_home), args.url) if args.cmd == "adopt" else sign(Path(args.move))
    except RescueError as e:
        sys.exit(f"rescue: {e}")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
