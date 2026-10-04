"""Moving the coordinator to another machine: the old coordinator's side (docs/design/coordinator-move.md).

A move is a trust-anchor rotation that carries the data with it:

1. `coordinator.prepare` (T3) names the target, either an enrolled node, bootstrapped through its own agent, or
   a host the owner installs once. It returns a single-use pairing code.
2. The target runs oarbankd in standby. It pairs with this coordinator over the tailnet: code, plus its tailnet
   StableID when known. From then on it pulls the blobs and a seed snapshot of the database (movepull.py).
3. `coordinator.move` (T3) writes the move statement, signed by this coordinator's key and by the target's.
   The epoch is exactly current + 1, and `not_before` is the time lock (24 h default, at least 15 min). Agents
   receive it as pending, so the console banner and ntfy announce it. `coordinator.cancel` (T1) withdraws it
   before the cutover.
4. At `not_before` the driver runs the cutover:
   - **draining:** no new leases; live leases are extended;
   - **frozen:** agent mutations get 503; the background loops and the console's writes stop; module hosts
     stop; the handoff audit record and a handover digest are written; then the final `VACUUM INTO`
     snapshot of every database, with invariants;
   - **final_ready:** the target pulls the final copy and verifies it against those invariants;
   - **promoting:** this coordinator tells the target to install it. The target asks back for the commit
     decision, which is taken here, atomically: the HANDED_OFF marker is written, then the target goes
     active at the new epoch;
   - **handed_off:** every agent call is answered 410 with the signed statement.
5. Agents verify the statement, probe the target's identity (tailnet StableID, a signed nonce from the new
   key), sign in, and commit. This coordinator stays redirect-only through probation; `coordinator.finalize`
   (T2) retires it afterwards.

Until the commit decision, any failure thaws this coordinator at the same epoch and loses nothing. After it,
going back is a reverse move (epoch + 2).
"""
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from . import clock
from . import config as C
from . import identity
from .db import DB, jl

DEFAULT_TIMELOCK_S = 86400
MIN_TIMELOCK_S = int(os.environ.get("OARBANKD_MOVE_MIN_TIMELOCK_S", "900"))     # tests lower it; 15 min in production
PAIR_TTL_S = 1800
COMMIT_TIMEOUT_S = 600
LEASE_CARRY_S = 1800
PROBATION_S = 72 * 3600
STATEMENT_VALID_S = 7 * 86400
FROZEN_PHASES = ("frozen", "final_ready", "promoting")
EXCLUDE_TOP = {"coordinator_key", "oarbank.sqlite3", "oarbank.sqlite3-wal", "oarbank.sqlite3-shm", identity.MARKER, "logs",
               "backups", "move", "console.secret", "FINALIZED", "tmp", "run"}
TAILNET_PREFIXES = ("100.", "fd7a:115c:a1e0:")


class MoveError(Exception):
    pass


def now() -> float:
    return clock.now()


def home(db: DB) -> Path:
    return Path(db.path).parent


def phase(db: DB) -> str:
    return db.get_setting("move_phase", "idle") or "idle"


def set_phase(db: DB, p: str, **detail):
    db.set_setting("move_phase", p)
    db.event("coordinator_move_phase", reason=p, **detail)


def serving(db: DB) -> bool:
    """Whether this coordinator may hand out work and run its background writes."""
    return identity.role(db) == "active" and phase(db) not in FROZEN_PHASES


def accepting_leases(db: DB) -> bool:
    return serving(db) and phase(db) != "draining"


_SHA_CACHE: dict[str, tuple[int, float, str]] = {}


def _sha_cached(p: Path) -> str:
    """Hash a file once per (size, mtime): the manifest is re-read for every seed refresh."""
    st = p.stat()
    c = _SHA_CACHE.get(str(p))
    if c and c[0] == st.st_size and c[1] == st.st_mtime:
        return c[2]
    h = _sha(p)
    _SHA_CACHE[str(p)] = (st.st_size, st.st_mtime, h)
    return h


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ plan and pairing

def prepare(db: DB, target: str, actor: str) -> dict:
    """A move plan for `target`: an enrolled node (hostname or node id: its agent installs the standby
    coordinator) or a URL `https://host:port` of a standby the owner starts by hand. One plan at a time."""
    if identity.role(db) != "active":
        raise MoveError(f"this coordinator is {identity.role(db)}, not active")
    busy = db.one("SELECT plan_id FROM coordinator_plans WHERE state IN ('prepared','paired','moving')")
    if busy:
        raise MoveError(f"plan {busy['plan_id']} is in progress; cancel it first")
    node = db.one("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (target, target))
    if node:
        if not node["ts_ip"]:
            raise MoveError(f"{node['hostname']} has no tailnet address on record")
        url, stable, nid = f"https://{node['ts_ip']}:{C.AGENT_PORT}", node["ts_node_id"], node["node_id"]
        from . import platforms
        plat = platforms.node_platform(dict(node))
    elif target.startswith(("http://", "https://")):
        url, nid, plat = target.rstrip("/"), None, None
        from . import core
        host = url.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0].strip("[]")
        who = core.tailscale_whois(host)
        stable = who["ts_node_id"] if who else None
    else:
        raise MoveError(f"unknown target {target!r}: give an enrolled node or https://host:port")
    code = "-".join(secrets.token_hex(3) for _ in range(3))
    pid = "mvp_" + secrets.token_hex(5)
    db.x("INSERT INTO coordinator_plans(plan_id,target_url,target_stable_id,target_node_id,code_sha,expires_at,state,"
         "created_at,actor,target_platform) VALUES(?,?,?,?,?,?,'prepared',?,?,?)",
         (pid, url, stable, nid, hashlib.sha256(code.encode()).hexdigest(), now() + PAIR_TTL_S, now(), actor, plat))
    db.event("coordinator_move_prepared", actor=actor, reason=f"{pid} -> {url}")
    from_url = db.get_setting("coordinator_url") or f"https://{C.AGENT_BIND}:{C.AGENT_PORT}"
    from . import tlsca
    from_ca = tlsca.pins(home(db))["ca_spki_sha256"] if (home(db) / "tls" / "ca.pem").exists() else None
    from . import modlife
    out = {"plan_id": pid, "target_url": url, "target_stable_id": stable, "target_node": nid, "target_platform": plat,
           "blocking_modules": modlife.platform_blockers(db, plat), "pair_code": code,
           "expires_at": now() + PAIR_TTL_S, "from_url": from_url, "from_ca": from_ca,
           "install_command": f"oarbankd --standby --pair {code} --from {from_url}" + (f" --from-ca {from_ca}" if from_ca else "")}
    if nid:
        from . import coordbuilds
        try:
            bundle = coordbuilds.directive_bundle(db, plat)
        except coordbuilds.BuildError as e:
            db.x("UPDATE coordinator_plans SET state='cancelled' WHERE plan_id=?", (pid,))
            raise MoveError(str(e))
        db.x("UPDATE nodes SET install_coordinator_json=? WHERE node_id=?",
             (json.dumps({"plan_id": pid, "pair_code": code, "from_url": from_url, "from_ca": from_ca, "bind": node["ts_ip"],
                          "agent_port": C.AGENT_PORT, "url": url, **bundle}), nid))
        out["via"] = f"the agent on {node['hostname']} installs the standby coordinator"
    return out


def plan(db: DB, plan_id: str | None = None) -> dict | None:
    if plan_id:
        return db.one("SELECT * FROM coordinator_plans WHERE plan_id=?", (plan_id,))
    return db.one("SELECT * FROM coordinator_plans WHERE state IN ('prepared','paired','moving') ORDER BY created_at DESC LIMIT 1")


def pair(db: DB, body: dict, peer_ip: str) -> dict:
    """The standby target presents the pairing code; we check its tailnet identity and exchange keys."""
    p = plan(db, body.get("plan_id")) or plan(db)
    code = body.get("code") or ""
    if not p or p["state"] != "prepared" or p["expires_at"] < now() or \
            hashlib.sha256(code.encode()).hexdigest() != p["code_sha"]:
        raise MoveError("no prepared move plan matches that pairing code (it is single-use and expires in 30 min)")
    _check_peer(p, peer_ip)
    for k in ("b_url", "b_cik", "b_audit_pub", "b_platform", "b_secrets_pub"):
        if not body.get(k):
            raise MoveError(f"pairing needs {k}")
    from oarbank_sdk import portable
    if not portable.is_platform_token(body["b_platform"]):
        raise MoveError(f"b_platform {body['b_platform']!r} is not a platform token (<os>-<arch>)")
    tok = secrets.token_urlsafe(32)
    db.x("UPDATE coordinator_plans SET state='paired', b_url=?, b_cik=?, b_audit_pub=?, b_secrets_pub=?, move_token_sha=?, paired_at=?,"
         " code_sha=NULL, b_tls_ca=?, target_platform=? WHERE plan_id=?",
         (body["b_url"].rstrip("/"), body["b_cik"], body["b_audit_pub"], body["b_secrets_pub"],
          hashlib.sha256(tok.encode()).hexdigest(), now(),
          body.get("b_tls_ca"), body["b_platform"], p["plan_id"]))
    db.event("coordinator_move_paired", reason=f"{p['plan_id']} {body['b_url']} key {identity.fingerprint(body['b_cik'])[:16]}")
    return {"plan_id": p["plan_id"], "move_token": tok, "a_cik": identity.key(home(db)).public_b64,
            "fleet_id": identity.fleet_id(db), "epoch": identity.epoch(db)}


def _check_peer(p: dict, peer_ip: str):
    """The caller must be the planned target: its tailnet StableID when we know it, else its address."""
    if p["target_stable_id"] and peer_ip.startswith(TAILNET_PREFIXES):
        from . import core
        who = core.tailscale_whois(peer_ip)
        if not who or who["ts_node_id"] != p["target_stable_id"]:
            raise MoveError("the caller is not the planned target machine (tailnet identity mismatch)")
        return
    host = p["target_url"].split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0].strip("[]")
    if peer_ip and host not in (peer_ip, "localhost") and not (host == "127.0.0.1" and peer_ip in ("127.0.0.1", "::1")):
        raise MoveError(f"the caller {peer_ip} is not the planned target {host}")


def auth_move(db: DB, token: str | None, peer_ip: str) -> dict:
    p = plan(db)
    if not p or not token or p.get("move_token_sha") != hashlib.sha256(token.encode()).hexdigest():
        raise MoveError("unknown move session")
    _check_peer(p, peer_ip)
    return p


# ------------------------------------------------------------------ what moves: files and databases

def manifest(db: DB) -> dict:
    """Every file under the coordinator's home that moves (blobs, module store, agent builds, releases, logs of
    attempts, other databases), with sizes and hashes. Databases are listed separately: they are copied only
    as snapshots."""
    root = home(db)
    files, dbs = [], []
    # blobs that module move rules rebuild or drop (and nothing else names) stay behind
    skip = set((db.get_setting("move_rules_plan") or {}).get("skip_blobs") or [])
    skip_paths = {str(db.abs(b["path"]).resolve()) for b in db.q("SELECT digest, path FROM blobs WHERE path IS NOT NULL")
                  if b["digest"] in skip}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if rel.parts[0] in EXCLUDE_TOP or p.is_dir() or p.is_symlink() or ".bak" in p.name or p.name.endswith(".tmp"):
            continue
        if ".venv" in rel.parts or "__pycache__" in rel.parts:      # machine-specific: the target rebuilds runtimes
            continue
        if skip_paths and str(p.resolve()) in skip_paths:
            continue
        if p.suffix in (".sqlite3", ".db") or p.name.endswith((".sqlite3-wal", ".sqlite3-shm", ".db-wal", ".db-shm")):
            if p.suffix in (".sqlite3", ".db"):
                dbs.append(rel.as_posix())
            continue
        files.append({"path": rel.as_posix(), "size": p.stat().st_size, "sha256": _sha_cached(p)})
    # blobs the database references outside the home (datasets registered from files on this machine, e.g. a
    # module's archive and tools): they move too, as external/<digest>, and the target rewrites their paths
    inside = os.path.join(str(root.resolve()), "")
    for b in db.q("SELECT digest, path, size FROM blobs WHERE path IS NOT NULL"):
        if b["digest"] in skip:
            continue
        bp = db.abs(b["path"])
        if not str(bp.resolve()).startswith(inside) and bp.is_file():
            files.append({"path": f"external/{b['digest']}", "size": b["size"] or bp.stat().st_size,
                          "sha256": b["digest"]})
    return {"files": files, "databases": dbs}


def safe_path(db: DB, rel: str) -> Path:
    if rel.startswith("external/"):
        b = db.one("SELECT path FROM blobs WHERE digest=?", (rel.split("/", 1)[1],))
        if not b or not b["path"] or not db.abs(b["path"]).is_file():
            raise MoveError(f"no blob {rel}")
        return db.abs(b["path"])
    root = home(db).resolve()
    p = (root / rel).resolve()
    if root not in p.parents or Path(rel).parts[0] in EXCLUDE_TOP:
        raise MoveError(f"not a movable file: {rel}")
    return p


def _counts(conn) -> dict:
    tabs = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    return {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in sorted(tabs)}


def snapshot(db: DB, final: bool) -> dict:
    """VACUUM INTO a consistent copy of the main database (and of every other SQLite file in the home), with the
    invariants the target must reproduce: per-table counts, the audit head, the schema version, the hash."""
    d = home(db) / "move" / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    sid = ("final_" if final else "seed_") + secrets.token_hex(4)
    out = {"snapshot_id": sid, "final": final, "taken_at": now(), "databases": {}}
    targets = [("oarbank.sqlite3", db.path)] + [(rel, home(db) / rel) for rel in manifest(db)["databases"]]
    for rel, src in targets:
        dst = d / f"{sid}--{rel.replace('/', '__')}"
        dst.unlink(missing_ok=True)
        if rel == "oarbank.sqlite3":
            if final:
                db.x("PRAGMA wal_checkpoint(TRUNCATE)")
            db.x("VACUUM INTO ?", (str(dst),))
            p = plan(db)                 # module secrets travel sealed to the target's transport key, never as they are here
            if p and p.get("b_secrets_pub"):
                from . import modsecrets
                modsecrets.seal_snapshot(db, dst, p["b_secrets_pub"])
        else:
            c = sqlite3.connect(str(src), timeout=30)
            try:
                c.execute("VACUUM INTO ?", (str(dst),))
            finally:
                c.close()
        out["databases"][rel] = invariants(dst)
        out["databases"][rel]["file"] = dst.name
    db.set_setting("move_snapshot", out)
    return out


def invariants(path: Path) -> dict:
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        inv = {"integrity": c.execute("PRAGMA integrity_check").fetchone()[0], "counts": _counts(c),
               "user_version": c.execute("PRAGMA user_version").fetchone()[0]}
        try:
            h = c.execute("SELECT event_id, hash FROM audit ORDER BY event_id DESC LIMIT 1").fetchone()
            inv["audit_head"] = list(h) if h else None
        except sqlite3.Error:
            pass
    finally:
        c.close()
    inv["sha256"], inv["size"] = _sha(path), path.stat().st_size
    return inv


def snapshot_file(db: DB, name: str) -> Path:
    p = (home(db) / "move" / "snapshots" / name).resolve()
    if p.parent != (home(db) / "move" / "snapshots").resolve() or not p.exists():
        raise MoveError(f"no snapshot {name}")
    return p


# ------------------------------------------------------------------ the statement

def _signed_post(p: dict, path: str, body: dict, db: DB, timeout: float = 60) -> dict:
    """A request from this coordinator to the paired target, signed with our key (the target pinned it at pairing)."""
    import httpx
    payload = identity.canonical({**body, "ts": int(now()), "plan_id": p["plan_id"]})
    verify = True
    if p["b_url"].startswith("https://"):
        from . import tlsca
        if not p.get("b_tls_ca"):
            raise MoveError("the target's TLS CA was not exchanged at pairing")
        from cryptography import x509
        ca = p["b_tls_ca"]
        verify = tlsca.client_context(ca, [tlsca.spki_sha256(x509.load_pem_x509_certificate(ca.encode()))])
    try:
        r = httpx.post(p["b_url"] + path, content=payload, timeout=timeout, verify=verify,
                       headers={"content-type": "application/json", "x-oarbank-move-sig": identity.key(home(db)).sign(payload)})
    except httpx.TransportError as e:
        raise MoveError(f"the target {p['b_url']} is not reachable ({e}); is the standby running?")
    if r.status_code >= 400:
        raise MoveError(f"target {path}: {r.status_code} {r.text[:300]}")
    return r.json()


def request_move(db: DB, actor: str, reason: str | None, timelock_s: int | None = None, canary: list | None = None,
                 sign_b=None, owner_sig: str | None = None, force: bool = False) -> dict:
    """Write the move statement (signed by us and by the target) and announce it as pending."""
    p = plan(db)
    if not p or p["state"] != "paired":
        raise MoveError("no paired move plan (coordinator.prepare, then start the standby target)")
    if db.one("SELECT move_id FROM coordinator_moves WHERE state IN ('pending','cutover','awaiting_owner')"):
        raise MoveError("a move is already pending")
    tl = DEFAULT_TIMELOCK_S if timelock_s is None else int(timelock_s)
    if tl < MIN_TIMELOCK_S:
        raise MoveError(f"the time lock is at least {MIN_TIMELOCK_S} s")
    if tl < DEFAULT_TIMELOCK_S and not reason:
        raise MoveError("a time lock below 24 h needs a reason")
    from . import modlife
    blocked = modlife.platform_blockers(db, p["target_platform"])
    if blocked and not force:
        raise MoveError(f"modules whose coordinator side does not run on {p['target_platform']}: "
                        + "; ".join(f"{n} ({why})" for n, why in blocked.items())
                        + ". Disable them, or force the move: they start disabled on the target")
    prev = db.one("SELECT statement FROM coordinator_moves WHERE state='committed' ORDER BY epoch DESC LIMIT 1")
    k = identity.key(home(db))
    t = now()
    mid = "mv_" + secrets.token_hex(6)
    stmt = identity.canonical({
        "type": identity.MOVE_TYPE, "fleet_id": identity.fleet_id(db), "move_id": mid, "epoch": identity.epoch(db) + 1,
        "from": {"url": db.get_setting("coordinator_url") or f"http://{C.AGENT_BIND}:{C.AGENT_PORT}", "cik": k.public_b64},
        "to": {"url": p["b_url"], "cik": p["b_cik"], "ts_stable_node_id": p["target_stable_id"], "required_tag": None},
        "issued_at": int(t), "not_before": int(t + tl), "expires": int(t + tl + STATEMENT_VALID_S),
        "canary": canary or [], "prev": hashlib.sha256(prev["statement"].encode()).hexdigest() if prev else None})
    sig_to = sign_b(stmt) if sign_b else _signed_post(p, "/v1/move/sign-statement", {"statement": stmt}, db)["sig"]
    if not identity.verify(p["b_cik"], stmt, sig_to):
        raise MoveError("the target's signature over the statement does not verify")
    from . import owner
    # signing mode: agents that pinned the owner keys need the owner's signature too; until it arrives
    # (coordinator.sign_move) the statement waits and is not announced
    state = "awaiting_owner" if owner.required(db) else "pending"
    pre = modlife.preflight(db, mid, p["b_url"], t + tl, "planned", p["target_platform"])     # shown in the review; effects ignored
    mods = {"planned": pre, "rules": modlife.move_plan(db)["items"]}
    db.x("INSERT INTO coordinator_moves(move_id,plan_id,epoch,statement,sig_from,sig_to,sig_owner,state,created_at,not_before,"
         "actor,reason,modules_json,force) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (mid, p["plan_id"], identity.epoch(db) + 1, stmt, k.sign(stmt), sig_to, None, state, t, t + tl, actor, reason,
          json.dumps(mods), int(bool(force))))
    db.x("UPDATE coordinator_plans SET state='moving' WHERE plan_id=?", (p["plan_id"],))
    if state == "awaiting_owner":
        if owner_sig:
            return sign_move(db, owner_sig, actor)
        db.event("coordinator_move_awaiting_owner", actor=actor, reason=mid)
        return move(db, mid)
    db.event("coordinator_move_requested", actor=actor, reason=f"{mid} -> {p['b_url']} at {time.strftime('%Y-%m-%d %H:%M', time.localtime(t + tl))}")
    _notify(db, f"Coordinator move requested: to {p['b_url']} at {time.strftime('%a %H:%M', time.localtime(t + tl))}. "
                f"Cancel it in the console if you did not ask for this.", priority="high")
    return move(db, mid)


def sign_move(db: DB, owner_sig: str, actor: str) -> dict:
    """Attach the owner's signature (signing mode) and announce the move."""
    from . import owner
    r = db.one("SELECT * FROM coordinator_moves WHERE state='awaiting_owner' ORDER BY created_at DESC LIMIT 1")
    if not r:
        raise MoveError("no move is waiting for the owner's signature")
    if not owner.verify_any(db, r["statement"], owner_sig):
        raise MoveError("the signature is not from an owner key")
    db.x("UPDATE coordinator_moves SET sig_owner=?, state='pending' WHERE move_id=?", (owner_sig, r["move_id"]))
    d = json.loads(r["statement"])
    db.event("coordinator_move_requested", actor=actor, reason=f"{r['move_id']} -> {d['to']['url']} (owner-signed)")
    _notify(db, f"Coordinator move requested (owner-signed): to {d['to']['url']} at "
                f"{time.strftime('%a %H:%M', time.localtime(d['not_before']))}.", priority="high")
    return move(db, r["move_id"])


def move(db: DB, move_id: str | None = None) -> dict | None:
    r = db.one("SELECT * FROM coordinator_moves WHERE move_id=?", (move_id,)) if move_id else \
        db.one("SELECT * FROM coordinator_moves ORDER BY created_at DESC LIMIT 1")
    if r:
        r["statement_doc"] = json.loads(r["statement"])
        r["report"] = jl(r.get("report_json"))
        r["modules"] = jl(r.get("modules_json"), {}) or {}
    return r


def signed(r: dict) -> dict:
    return {"statement": r["statement"], "signatures": {"from": r["sig_from"], "to": r["sig_to"], "owner": r["sig_owner"]}}


def cancel(db: DB, actor: str, reason: str | None = None) -> dict:
    """Withdraw a pending move (or abort a cutover before the commit decision): this coordinator thaws at the
    same epoch, and agents holding the statement drop it on a cancel signed by our key."""
    r = db.one("SELECT * FROM coordinator_moves WHERE state IN ('pending','cutover','awaiting_owner') ORDER BY created_at DESC LIMIT 1")
    if not r:
        raise MoveError("no pending move")
    if r["state"] == "cutover" and phase(db) == "promoting" and db.get_setting("move_commit_decided"):
        raise MoveError("the commit decision was taken: going back is a reverse move")
    payload = identity.canonical({"type": identity.CANCEL_TYPE, "fleet_id": identity.fleet_id(db), "move_id": r["move_id"],
                                  "epoch": r["epoch"], "issued_at": int(now())})
    with db.tx():
        db.x("UPDATE coordinator_moves SET state='cancelled', cancel_payload=?, cancel_sig=?, ended_at=? WHERE move_id=?",
             (payload, identity.key(home(db)).sign(payload), now(), r["move_id"]))
        db.x("UPDATE coordinator_plans SET state='cancelled' WHERE plan_id=?", (r["plan_id"],))
        _thaw(db)
    db.event("coordinator_move_cancelled", actor=actor, reason=f"{r['move_id']}: {reason or ''}")
    _notify(db, f"Coordinator move {r['move_id']} cancelled ({reason or 'by ' + actor}).")
    try:
        from . import modlife
        modlife.cancelled(db, r["move_id"], reason or f"cancelled by {actor}")      # modules resume what they paused
    except Exception as e:
        db.event("background_error", reason=f"move.cancelled: {e!r}"[:300])
    return move(db, r["move_id"])


def _thaw(db: DB):
    db.set_setting("move_phase", "idle")
    db.set_setting("move_commit_decided", None)
    for k in ("move_blockers", "move_preflight_at", "move_draining_at", "move_rules_plan"):
        db.set_setting(k, None)


# ------------------------------------------------------------------ the cutover (driven by the background loop)

def driver_tick(db: DB):
    """Advance a pending move whose time lock has passed. Safe to call every few seconds and after a restart:
    every phase is persisted, and a frozen coordinator stays frozen until the move commits or aborts."""
    r = db.one("SELECT * FROM coordinator_moves WHERE state IN ('pending','cutover') ORDER BY created_at DESC LIMIT 1")
    if not r or identity.role(db) != "active":
        return
    p = plan(db, r["plan_id"])
    ph = phase(db)
    if r["state"] == "pending":
        if now() < r["not_before"]:
            return
        db.x("UPDATE coordinator_moves SET state='cutover' WHERE move_id=?", (r["move_id"],))
        ph = "idle"
    try:
        if ph == "idle":
            set_phase(db, "draining", move_id=r["move_id"])
            db.set_setting("move_draining_at", now())
            n = db.x("UPDATE attempts SET expires_at=MAX(expires_at, ?) WHERE state='live'", (now() + LEASE_CARRY_S,))
            db.event("leases_extended", reason=f"carried across the coordinator move ({n} live)")
            _notify(db, f"Coordinator move {r['move_id']}: cutover started (dispatch paused, running work continues).")
            _module_preflight(db, r, p)
        elif ph == "draining":
            if not _module_preflight(db, r, p):
                return                                   # a module still blocks (or the wait expired: aborted)
            from . import modlife
            set_phase(db, "frozen", move_id=r["move_id"])
            db.set_setting("move_rules_plan", modlife.move_plan(db))      # what modules rebuild or drop (travels in the copy)
            src = modlife.check_all(db, "move_source", move_id=r["move_id"], actor="oarbankd")
            bad = [n for n, c in src.items() if not c["ok"]]
            if bad and not r["force"]:
                raise MoveError(f"module integrity check failed on this coordinator: {', '.join(bad)}")
            _stop_module_hosts(db)
            _write_handoff_records(db, r, p)
            snap = snapshot(db, final=True)
            snap["modules"] = {n: {"ok": c["ok"], "fingerprint": c["fingerprint"]} for n, c in src.items()}
            db.x("UPDATE coordinator_moves SET final_snapshot_json=? WHERE move_id=?", (json.dumps(snap), r["move_id"]))
            set_phase(db, "final_ready", move_id=r["move_id"], snapshot=snap["snapshot_id"])
            db.set_setting("move_phase_at", now())
        elif ph == "final_ready":
            if now() - (db.get_setting("move_phase_at") or now()) > COMMIT_TIMEOUT_S:
                abort(db, "the target did not verify the final copy in time")
        elif ph == "promoting":
            if not db.get_setting("move_commit_decided") and now() - (db.get_setting("move_phase_at") or now()) > COMMIT_TIMEOUT_S:
                abort(db, "the target did not ask for the commit decision in time")
    except MoveError as e:
        abort(db, str(e))


def _module_preflight(db: DB, r: dict, p: dict) -> bool:
    """While draining: ask modules every few seconds; True when none blocks (or the operator forced the move). After
    modlife.BLOCKER_WAIT_S of blockers the move aborts and this coordinator thaws."""
    from . import modlife
    if now() - (db.get_setting("move_preflight_at") or 0) < modlife.PREFLIGHT_EVERY_S and db.get_setting("move_blockers") is not None:
        blocked = db.get_setting("move_blockers") or []
    else:
        pre = modlife.preflight(db, r["move_id"], p["b_url"], r["not_before"], "draining", p["target_platform"])
        blocked = modlife.blockers(pre)
        db.set_setting("move_preflight_at", now())
        db.set_setting("move_blockers", blocked)
        mods = jl(r.get("modules_json"), {}) or {}
        mods["draining"] = pre
        db.x("UPDATE coordinator_moves SET modules_json=? WHERE move_id=?", (json.dumps(mods), r["move_id"]))
    if not blocked or r["force"]:
        return True
    if now() - (db.get_setting("move_draining_at") or now()) > modlife.BLOCKER_WAIT_S:
        raise MoveError("modules still block the move: " + "; ".join(blocked)[:300])
    return False


def abort(db: DB, why: str):
    """Before the commit decision: thaw at the same epoch; agents drop the pending statement on our cancel."""
    if db.get_setting("move_commit_decided"):
        db.event("coordinator_move_stuck", reason=f"after the commit decision: {why}")
        return
    r = db.one("SELECT * FROM coordinator_moves WHERE state IN ('pending','cutover') ORDER BY created_at DESC LIMIT 1")
    if r:
        cancel(db, "oarbankd", reason=f"aborted: {why}")
        db.x("UPDATE coordinator_moves SET state='aborted' WHERE move_id=?", (r["move_id"],))
        _notify(db, f"Coordinator move aborted: {why}. Nothing was lost; this coordinator kept running.", priority="high")


def ready(db: DB, body: dict, p: dict) -> dict:
    """The target verified the final copy: compare its invariants with ours, then tell it to install."""
    r = db.one("SELECT * FROM coordinator_moves WHERE state='cutover' AND plan_id=?", (p["plan_id"],))
    if not r or phase(db) != "final_ready":
        raise MoveError("no cutover waiting for the target")
    ours = json.loads(r["final_snapshot_json"])
    theirs = body.get("databases") or {}
    bad = [rel for rel, inv in ours["databases"].items()
           if {k: inv[k] for k in ("sha256", "counts", "audit_head", "user_version") if k in inv} !=
           {k: (theirs.get(rel) or {}).get(k) for k in ("sha256", "counts", "audit_head", "user_version") if k in inv}]
    want = {f["path"]: f["sha256"] for f in manifest(db)["files"]}
    got = body.get("files") or {}
    missing = [f for f, h in want.items() if got.get(f) != h]
    mods_a, mods_b = ours.get("modules") or {}, body.get("modules") or {}
    from . import modlife
    disabled_there = set(modlife.platform_blockers(db, p["target_platform"])) if r["force"] else set()
    mod_bad = [n for n in mods_a if n not in disabled_there and (not (mods_b.get(n) or {}).get("ok") and not r["force"]
               or (mods_b.get(n) or {}).get("fingerprint") != mods_a[n].get("fingerprint"))]
    if mod_bad:
        abort(db, f"module state differs or fails its check on the target: {', '.join(mod_bad)}")
        raise MoveError("module verification failed; the move was aborted and this coordinator thawed")
    if bad or missing or any((theirs.get(rel) or {}).get("integrity") != "ok" for rel in ours["databases"]):
        abort(db, f"the target's copy differs (databases {bad[:3]}, files {missing[:3]})")
        raise MoveError("verification failed; the move was aborted and this coordinator thawed")
    report = {"databases": {rel: {"a": ours["databases"][rel], "b": theirs.get(rel)} for rel in ours["databases"]},
              "files": len(want), "modules": {n: {"a": mods_a[n], "b": mods_b.get(n)} for n in mods_a}, "verified_at": now()}
    db.x("UPDATE coordinator_moves SET report_json=? WHERE move_id=?", (json.dumps(report), r["move_id"]))
    set_phase(db, "promoting", move_id=r["move_id"])
    db.set_setting("move_phase_at", now())
    _signed_post(p, "/v1/move/promote", {"move_id": r["move_id"], **signed(r)}, db)
    return {"ok": True}


def commit(db: DB, body: dict, p: dict) -> dict:
    """The commit decision, taken here and only here: the target installed the copy and asks whether to go
    active. Yes means we write the HANDED_OFF marker first, so two coordinators are never active."""
    r = db.one("SELECT * FROM coordinator_moves WHERE move_id=?", (body.get("move_id"),))
    if not r or r["plan_id"] != p["plan_id"]:
        raise MoveError("unknown move")
    if r["state"] in ("cancelled", "aborted") or (phase(db) != "promoting" and identity.role(db) != "handed_off"):
        return _decision(db, r, False)
    if identity.role(db) != "handed_off":
        db.set_setting("move_commit_decided", now())
        identity.set_role(db, "handed_off")
        db.x("UPDATE coordinator_moves SET state='committed', ended_at=? WHERE move_id=?", (now(), r["move_id"]))
        db.x("UPDATE coordinator_plans SET state='done' WHERE plan_id=?", (p["plan_id"],))
        db.set_setting("move_phase", "handed_off")
        db.event("coordinator_handed_off", reason=f"{r['move_id']} -> {p['b_url']} epoch {r['epoch']}")
        _notify(db, f"Coordinator moved to {p['b_url']} (epoch {r['epoch']}). This machine now only redirects agents.")
    return _decision(db, r, True)


def _decision(db: DB, r: dict, ok: bool) -> dict:
    payload = identity.canonical({"move_id": r["move_id"], "commit": ok, "epoch": r["epoch"], "ts": int(now())})
    return {"payload": payload, "sig": identity.key(home(db)).sign(payload)}


def _write_handoff_records(db: DB, r: dict, p: dict):
    """The audit chain crosses machines: a coordinator_move record, and a digest naming the target's audit key, so
    the verifier accepts the new key only from this point (an attacker cannot fork the chain with a fresh key)."""
    from . import audit
    audit.append(db, actor="oarbankd", source="system", operation="coordinator.handoff", category="modify",
                 target_type="coordinator", target_id=r["move_id"], outcome="ok", request_id=audit.request_id(),
                 after={"epoch": r["epoch"], "to": p["b_url"], "to_cik": p["b_cik"], "next_audit_pubkey": p["b_audit_pub"],
                        "statement_sha256": hashlib.sha256(r["statement"].encode()).hexdigest()})
    try:
        audit.write_digest(db, audit.Signer(), next_pubkey=p["b_audit_pub"])
    except Exception as e:                       # no Keychain (tests): the chain record above still links them
        db.event("audit_digest_skipped", reason=f"handover digest: {e}")


def _stop_module_hosts(db: DB):
    """Module coordinators may write their own databases: stop them before the snapshot.
    The campaign loop does not restart them while frozen."""
    try:
        from . import modcalls
        h = modcalls._hosts.get(db)
        for name in list(getattr(h, "_procs", {}) or {}):
            h.stop(name)
    except Exception as e:
        db.event("background_error", reason=f"stopping module hosts for the move: {e!r}"[:300])


# ------------------------------------------------------------------ what agents see

def directives(db: DB) -> dict:
    """In every hello and heartbeat reply: a pending or committed move (agents verify it themselves), and recent
    cancellations (agents holding that statement drop it)."""
    out = {}
    r = db.one("SELECT * FROM coordinator_moves WHERE state IN ('pending','cutover','committed') ORDER BY created_at DESC LIMIT 1")
    if r and (r["state"] != "committed" or identity.role(db) == "handed_off"):
        out["coordinator_move"] = signed(r)
    c = db.one("SELECT move_id, cancel_payload, cancel_sig FROM coordinator_moves WHERE state IN ('cancelled','aborted') "
               "AND ended_at>? ORDER BY ended_at DESC LIMIT 1", (now() - 7 * 86400,))
    if c and c["cancel_payload"]:
        out["coordinator_move_cancel"] = {"payload": c["cancel_payload"], "sig": c["cancel_sig"]}
    return out


def redirect_body(db: DB) -> dict:
    r = db.one("SELECT * FROM coordinator_moves WHERE state='committed' ORDER BY epoch DESC LIMIT 1")
    return {"coordinator_move": signed(r), "chain": "/v1/coordinator/moves?since_epoch=<n>", "now": clock.now()} if r else {}


def chain(db: DB, since_epoch: int) -> list:
    """Committed statements above an epoch, oldest first: an agent offline across several moves walks them."""
    return [signed(r) for r in db.q("SELECT * FROM coordinator_moves WHERE state='committed' AND epoch>? ORDER BY epoch",
                                    (since_epoch,))]


def finalize(db: DB, actor: str) -> dict:
    """After probation on the old machine: stop serving redirects. The data stays where it is (archive it
    yourself); oarbankd exits and refuses to start here again (FINALIZED marker)."""
    if identity.role(db) != "handed_off":
        raise MoveError("only a handed-off coordinator can be finalized")
    m = db.one("SELECT * FROM coordinator_moves WHERE state='committed' ORDER BY epoch DESC LIMIT 1")
    if m and now() - (m["ended_at"] or 0) < PROBATION_S and not os.environ.get("OARBANKD_MOVE_SKIP_PROBATION"):
        left = PROBATION_S - (now() - (m["ended_at"] or 0))
        raise MoveError(f"probation has {left / 3600:.1f} h left (stragglers may still need the redirect)")
    (home(db) / "FINALIZED").write_text(json.dumps({"at": now(), "by": actor}) + "\n", encoding="utf-8", newline="\n")
    db.event("coordinator_finalized", actor=actor)
    return {"finalized": True, "home": str(home(db)), "note": "oarbankd stops now and will not start here again"}


def _notify(db: DB, message: str, priority: str = "default"):
    try:
        from . import notify
        notify.send(db, title="Oarbank: coordinator move", message=message, priority=priority)
    except Exception:
        pass


def status(db: DB) -> dict:
    """For the console, oarbank and the API: the plan, the move, the phase, which agents followed, and where and how
    this coordinator runs (hostinfo.py, taken now)."""
    from . import hostinfo
    p = plan(db) or db.one("SELECT * FROM coordinator_plans ORDER BY created_at DESC LIMIT 1")
    m = move(db)
    nodes = db.q("SELECT hostname, node_id, json_extract(agent_update_json,'$.state') u, coordinator_move_json, last_heartbeat_at "
                 "FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    return {"role": identity.role(db), "epoch": identity.epoch(db), "phase": phase(db), "fleet_id": identity.fleet_id(db),
            "cik_fingerprint": identity.key(home(db)).fingerprint,
            "plan": {k: v for k, v in (p or {}).items() if k not in ("code_sha", "move_token_sha")} or None,
            "move": {k: v for k, v in (m or {}).items() if k not in ("statement",)} if m else None,
            "agents": [{"hostname": n["hostname"], "node_id": n["node_id"], "move": jl(n["coordinator_move_json"]),
                        "last_heartbeat_at": n["last_heartbeat_at"]} for n in nodes],
            "min_timelock_s": MIN_TIMELOCK_S, "default_timelock_s": DEFAULT_TIMELOCK_S, "host": hostinfo.refresh(db)}
