"""Moving the coordinator: the target's side (docs/design/coordinator-move.md; the old side is coordmove.py).

A standby oarbankd (`oarbankd --standby --pair <code> --from <old url>`) keeps its move state in `<home>/move/state.json`
(not in the database, which the move replaces). It:

1. pairs with the old coordinator: the code, its own identity key, its audit key. It pins the old key;
2. seeds: copies every file in the old manifest, verified by hash, and a seed snapshot of each database, into
   `<home>/move/staging` (never opened read-write);
3. when the old coordinator froze and took the final snapshot: copies it and the changed files, verifies
   integrity and the invariants, and reports ready;
4. on the old coordinator's signed promote: asks it for the commit decision (taken there, atomically). On yes, it
   installs the staging copy in place and restarts (exit 75: the service manager starts it again). The new process
   finishes the install, raises the epoch, and serves as the active coordinator.

It also signs the move statement when the old coordinator asks, after checking that it names this machine's key,
the paired old key and the next epoch.
"""
import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path

from . import config as C
from . import identity, modsecrets
from .db import DB

RESTART_EXIT = 75


class PullError(Exception):
    pass


def state_path(home: Path) -> Path:
    return home / "move" / "state.json"


def load(home: Path) -> dict:
    p = state_path(home)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def save(home: Path, st: dict):
    p = state_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    from ..platform import files
    files.write_private(p, json.dumps(st, indent=1))


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Puller:
    """The standby's background work. `http` is an httpx-like client factory (tests inject one)."""

    def __init__(self, db: DB, home: Path, from_url: str | None = None, code: str | None = None, my_url: str | None = None,
                 client=None, from_ca: str | None = None):
        import httpx
        self.db, self.home = db, Path(home)
        self.st = load(self.home)
        if from_url:
            self.st.setdefault("from_url", from_url.rstrip("/"))
        if code and not self.st.get("move_token"):
            self.st["code"] = code
        if my_url:
            self.st["my_url"] = my_url.rstrip("/")
        if from_ca:
            self.st.setdefault("from_ca", from_ca.lower())
        self.http = client or self._client()
        self.stop = threading.Event()

    def _client(self):
        """To the old coordinator over TLS: only its CA, pinned by the hash the operator was given (prepare's
        `--from-ca`, or the install_coordinator directive)."""
        import httpx
        url = self.st.get("from_url") or ""
        if not url.startswith("https://"):
            return httpx.Client(timeout=120)
        from . import tlsca
        pin = self.st.get("from_ca")
        if not pin:
            raise PullError("the old coordinator is on TLS: start the standby with --from-ca <its CA pin> (coordinator.prepare prints it)")
        return httpx.Client(timeout=120, verify=tlsca.client_context(tlsca.fetch_ca(url, pin), [pin]))

    # -- calls to the old coordinator
    def _get(self, path: str, stream_to: Path | None = None):
        h = {"x-oarbank-move": self.st["move_token"]}
        if stream_to is None:
            r = self.http.get(self.st["from_url"] + path, headers=h)
            if r.status_code >= 400:
                raise PullError(f"{path}: {r.status_code} {r.text[:200]}")
            return r.json()
        tmp = stream_to.with_name(stream_to.name + ".partial")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with self.http.stream("GET", self.st["from_url"] + path, headers=h) as r:
            if r.status_code >= 400:
                raise PullError(f"{path}: {r.status_code}")
            with open(tmp, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
        tmp.replace(stream_to)
        return stream_to

    def _post(self, path: str, body: dict) -> dict:
        r = self.http.post(self.st["from_url"] + path, json=body, headers={"x-oarbank-move": self.st.get("move_token", "")})
        if r.status_code >= 400:
            raise PullError(f"{path}: {r.status_code} {r.text[:300]}")
        return r.json()

    # -- steps
    def pair(self):
        from . import audit
        k = identity.key(self.home)
        try:
            audit_pub = audit.Signer().public_b64
        except Exception:                        # no Keychain (tests): a file key stands in
            audit_pub = identity.Key(self.home / "move" / "audit_key").public_b64
        from oarbank_sdk import portable
        r = self.http.post(self.st["from_url"] + "/v1/move/pair",
                           json={"code": self.st.pop("code"), "b_url": self.st["my_url"], "b_cik": k.public_b64,
                                 "b_audit_pub": audit_pub, "b_platform": portable.host_platform(),
                                 "b_secrets_pub": modsecrets.transport_public(self.home),
                                 "b_tls_ca": (self.home / "tls" / "ca.pem").read_text(encoding="utf-8")
                                 if (self.home / "tls" / "ca.pem").exists() else None})
        if r.status_code >= 400:
            raise PullError(f"pairing refused: {r.status_code} {r.text[:300]}")
        d = r.json()
        self.st.update(move_token=d["move_token"], a_cik=d["a_cik"], fleet_id=d["fleet_id"], a_epoch=d["epoch"],
                       plan_id=d["plan_id"], phase="paired", paired_at=time.time())
        save(self.home, self.st)
        # the same fleet: a standby presents the fleet's id (agents probing it early must not see a stranger)
        self.db.set_state("fleet_id", d["fleet_id"])
        self.db.event("coordinator_standby_paired", reason=f"{self.st['from_url']} key {identity.fingerprint(d['a_cik'])[:16]}")

    def staging(self) -> Path:
        return self.home / "move" / "staging"

    def sync_files(self) -> dict:
        """Copy every manifest file whose hash we do not already hold; returns {path: sha256} as held. Files
        verified before are not re-hashed while their size and mtime are unchanged (the archive can be large)."""
        m = self._get("/v1/move/manifest")
        held = {}
        vf = self.home / "move" / "verified.json"
        verified = json.loads(vf.read_text(encoding="utf-8")) if vf.exists() else {}
        for f in m["files"]:
            dst = (self.staging() / "files" / f["path"]).resolve()
            if (self.staging() / "files").resolve() not in dst.parents:
                raise PullError(f"unsafe path {f['path']}")
            v = verified.get(f["path"])
            ok = dst.exists() and dst.stat().st_size == f["size"] and (
                (v and v[0] == f["sha256"] and v[1] == dst.stat().st_mtime) or _sha(dst) == f["sha256"])
            if not ok:
                self._get("/v1/move/file?path=" + _q(f["path"]), dst)
                if _sha(dst) != f["sha256"]:
                    dst.unlink(missing_ok=True)
                    raise PullError(f"{f['path']}: hash mismatch after transfer")
            verified[f["path"]] = [f["sha256"], dst.stat().st_mtime]
            held[f["path"]] = f["sha256"]
        vf.write_text(json.dumps(verified), encoding="utf-8", newline="\n")
        # files no longer in the manifest (deleted on the old side) leave the staging copy
        for p in list((self.staging() / "files").rglob("*")) if (self.staging() / "files").exists() else []:
            rel = p.relative_to(self.staging() / "files").as_posix()
            if p.is_file() and rel not in held:
                p.unlink()
        return held

    def pull_snapshot(self, snap: dict) -> dict:
        out = {}
        for rel, inv in snap["databases"].items():
            dst = self.staging() / "databases" / rel
            self._get("/v1/move/snapshot-file/" + _q(inv["file"]), dst)
            from .coordmove import invariants
            out[rel] = invariants(dst)
        return out

    def seed(self):
        self.st["phase"] = "seeding"
        save(self.home, self.st)
        self.sync_files()
        snap = self._post("/v1/move/snapshot", {})
        self.pull_snapshot(snap)
        self.st.update(phase="seeded", seeded_at=time.time())
        save(self.home, self.st)

    def final(self, status: dict):
        """The old coordinator froze: take its final copy, verify, report."""
        snap = status["snapshot"]
        files = self.sync_files()
        dbs = self.pull_snapshot(snap)
        for rel, inv in dbs.items():
            if inv["integrity"] != "ok":
                raise PullError(f"{rel}: integrity_check says {inv['integrity']}")
        free = shutil.disk_usage(self.home).free
        need = sum(p.stat().st_size for p in self.staging().rglob("*") if p.is_file())
        if free < need * 1.2:
            raise PullError(f"not enough disk to install: {need / 1e9:.1f} GB staged, {free / 1e9:.1f} GB free")
        mods = verify_modules(self.staging(), status.get("move_id"))
        self.st.update(phase="ready", final_snapshot=snap["snapshot_id"], ready_at=time.time())
        save(self.home, self.st)
        self._post("/v1/move/ready", {"databases": dbs, "files": files, "modules": mods})

    def tick(self):
        if self.st.get("phase") in (None, "") and self.st.get("code"):
            self.pair()
        ph = self.st.get("phase")
        if ph == "paired":
            self.seed()
        elif ph in ("seeded", "ready"):
            s = self._get("/v1/move/status")
            if s.get("phase") == "final_ready" and ph == "seeded":
                self.final(s)
            elif s.get("phase") == "idle" and s.get("move_state") in ("cancelled", "aborted", None) and ph == "ready":
                self.st["phase"] = "seeded"           # aborted: back to waiting (a new move re-runs the final copy)
                save(self.home, self.st)
            elif ph == "seeded" and time.time() - self.st.get("seeded_at", 0) > 600:
                self.seed()                           # keep the seed fresh while waiting for the time lock

    def _listening(self) -> bool:
        """Our own agent listener accepts connections: pairing hands the old coordinator our URL, and it calls back at
        once (sign the statement), so we pair only when that URL answers."""
        import socket
        from urllib.parse import urlsplit
        u = urlsplit(self.st.get("my_url") or "")
        if not u.hostname:
            return True
        try:
            socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout=2).close()
            return True
        except OSError:
            return False

    def run(self):
        while not self.stop.is_set() and self.st.get("code") and not self._listening():
            self.stop.wait(0.5)
        while not self.stop.is_set():
            try:
                if self.st.get("phase") not in ("promoting", "installed", "active", "aborted"):
                    self.tick()
            except Exception as e:
                self.db.event("coordinator_standby_error", reason=repr(e)[:300])
            self.stop.wait(3)

    # -- requests from the old coordinator (verified with the key we pinned at pairing)
    def verify_from_a(self, payload: bytes, sig: str) -> dict:
        if not self.st.get("a_cik") or not identity.verify(self.st["a_cik"], payload, sig or ""):
            raise PullError("request not signed by the paired coordinator")
        body = json.loads(payload)
        if abs(time.time() - body.get("ts", 0)) > 300:
            raise PullError("stale request")
        return body

    def sign_statement(self, stmt: str) -> str:
        d = json.loads(stmt)
        k = identity.key(self.home)
        if d.get("type") != identity.MOVE_TYPE or d["to"]["cik"] != k.public_b64 or d["from"]["cik"] != self.st.get("a_cik") \
                or d["epoch"] != self.st.get("a_epoch", 0) + 1 or d["fleet_id"] != self.st.get("fleet_id"):
            raise PullError("the statement does not name this machine, the paired coordinator and the next epoch")
        self.st["statement"] = stmt
        save(self.home, self.st)
        return k.sign(stmt)

    def promote(self, body: dict):
        """Ask the old coordinator for the commit decision; on yes install and restart. Runs on its own thread."""
        self.st.update(phase="promoting", move_id=body["move_id"], signed=body)
        save(self.home, self.st)
        try:
            d = self._post("/v1/move/commit", {"move_id": body["move_id"]})
            if not identity.verify(self.st["a_cik"], d["payload"], d["sig"]):
                raise PullError("commit decision not signed by the paired coordinator")
            dec = json.loads(d["payload"])
            if dec["move_id"] != body["move_id"]:
                raise PullError("commit decision for another move")
            if not dec["commit"]:
                self.st["phase"] = "seeded"
                save(self.home, self.st)
                self.db.event("coordinator_standby_aborted", reason=body["move_id"])
                return
            self.st.update(phase="installed", epoch=dec["epoch"], decided_at=time.time())
            install_staging(self.home)
            save(self.home, self.st)
        except Exception as e:
            self.db.event("coordinator_standby_error", reason=f"promote: {e!r}"[:300])
            self.st["phase"] = "ready"                # the old side's timeout decides; asking again is safe
            save(self.home, self.st)
            return
        from ..platform import service
        service.exit_now(RESTART_EXIT)                 # the service manager starts us again on the installed copy


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


def relink_external(db: DB):
    """Stored paths inside the home are relative (DB.rel), so they hold on any machine. Blobs that lived outside the
    old home arrived as external/<digest>: point their rows there."""
    for b in db.q("SELECT digest, path FROM blobs WHERE path IS NOT NULL"):
        ext = db.root / "external" / b["digest"]
        if Path(b["path"]).is_absolute() and ext.is_file():
            db.x("UPDATE blobs SET path=? WHERE digest=?", (f"external/{b['digest']}", b["digest"]))


def verify_modules(staging: Path, move_id: str | None = None) -> dict:
    """Each enabled module checks its state on the verified copy (integrity.check {scope: move_target}) before this
    standby reports ready; the old coordinator compares the fingerprints with its own. Runs on a throwaway copy of
    the database whose paths point into the staging files, so nothing staged is changed."""
    from oarbank_sdk import manifest as mf

    from . import modcalls, modfiles, modlife, modstore
    from .modulehost import ModuleError, ModuleHost, ModuleUnavailable
    vdir = staging.parent / "verify"
    shutil.rmtree(vdir, ignore_errors=True)
    vdir.mkdir(parents=True)
    src = staging / "databases" / "oarbank.sqlite3"
    if not src.exists():
        return {}
    shutil.copy2(src, vdir / "oarbank.sqlite3")
    vdb = DB(vdir / "oarbank.sqlite3")
    vdb.root = staging / "files"                   # the copy's stored paths resolve into the staged files
    out, built = {}, []
    try:
        relink_external(vdb)
        enabled = set(modstore.enabled_names(vdb))
        for ch in vdb.q("SELECT name, current FROM module_channels WHERE current IS NOT NULL ORDER BY name"):
            if ch["name"] not in enabled:
                continue
            name = ch["name"]
            rec = vdb.one("SELECT path FROM modules WHERE name=? AND version=?", (name, ch["current"]))
            if not rec or not vdb.abs(rec["path"]).is_dir():
                out[name] = {"ok": False, "fingerprint": None, "checks": [{"name": "core/bundle_present", "ok": False,
                                                                          "severity": "error", "detail": "not in the copy"}]}
                continue
            path = vdb.abs(rec["path"])
            man = mf.load(path / "oarbank-module.toml")
            why = modstore.coordinator_unsupported(man)
            if why:                                 # a forced move: disabled here at install (modlife.disable_unsupported)
                out[name] = {"ok": False, "fingerprint": None, "checks": [{"name": modlife.PLATFORM_BLOCKER, "ok": False,
                                                                          "severity": "error", "detail": why}]}
                continue
            res, err = None, None
            if "integrity.check" in man.coordinator.capabilities:
                if (path / "requirements.txt").exists() and not (path / ".venv").exists():
                    modstore._build_runtime(path)
                    built.append(path / ".venv")
                from . import modsandbox
                h = ModuleHost([modsandbox.coordinator_spec(vdir, name, man, path)], home=vdir,
                               callbacks=modcalls.host_callbacks(vdb))
                try:
                    res = h.call(name, "integrity.check", {"scope": "move_target", "deep": False, "move_id": move_id, "now": time.time()})
                except (ModuleUnavailable, ModuleError) as e:
                    err = f"integrity.check: {e}"
                finally:
                    h.close()
            skip = set((vdb.get_state("move_rules_plan") or {}).get("skip_blobs") or [])
            m = modlife._merge(res, modfiles.core_checks(vdb, name, skip=skip), err)
            out[name] = {"ok": m["ok"], "fingerprint": m["fingerprint"], "checks": m["checks"]}
    finally:
        vdb.conn.close()
        for v in built:                       # built for the check only: the install rebuilds runtimes in place
            shutil.rmtree(v, ignore_errors=True)
    return out


def install_staging(home: Path):
    """Put the verified staging copy in place: files by renames within one volume, each database's content through
    SQLite's backup API into the standby's own file, which this process and the console keep open (on Windows an open
    file cannot be replaced; elsewhere the console would go on reading the replaced one). Our identity key and move
    state stay."""
    import sqlite3
    st = home / "move" / "staging"
    for p in sorted((st / "files").rglob("*")) if (st / "files").exists() else []:
        if p.is_file():
            dst = home / p.relative_to(st / "files")
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(p, dst)
    for p in sorted((st / "databases").glob("**/*")) if (st / "databases").exists() else []:
        if p.is_file() and not p.name.endswith(".partial"):
            dst = home / p.relative_to(st / "databases")
            dst.parent.mkdir(parents=True, exist_ok=True)
            src, out = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True), sqlite3.connect(dst, timeout=30)
            try:
                src.backup(out)
            finally:
                src.close()
                out.close()
            p.unlink()


def finish_install(db: DB, home: Path) -> bool:
    """At start, after an install: become the active coordinator at the move's epoch, in the first transaction.
    Returns True when this start completed a move."""
    st = load(home)
    if st.get("phase") != "installed":
        return False
    with db.tx():
        db.set_state("coordinator_epoch", int(st["epoch"]))
        db.set_state("coordinator_role", "active")
        db.set_state("move_phase", "idle")
        db.set_state("move_commit_decided", None)
        db.set_state("coordinator_url", st["my_url"])
        db.set_state("reaper_grace_until", time.time() + C.LEASE_TTL + 120)
        db.set_state("coordinator_cik", identity.key(home).public_b64)
        relink_external(db)
        from . import modlife, modstore
        plan = db.get_state("move_rules_plan") or {}
        modlife.apply_move_rules(db, plan)
        db.set_state("move_postflight_pending", {
            "move_id": st.get("move_id"), "from_url": st.get("from_url"), "epoch": int(st["epoch"]), "items": plan.get("items") or [],
            "modules": modstore.enabled_names(db)})
        for k in ("move_rules_plan", "move_blockers", "move_preflight_at", "move_draining_at"):
            db.set_state(k, None)
        if st.get("move_id"):
            db.x("UPDATE coordinator_moves SET state='committed', ended_at=? WHERE move_id=?", (time.time(), st["move_id"]))
            if not db.one("SELECT 1 FROM coordinator_moves WHERE move_id=?", (st["move_id"],)) and st.get("signed"):
                s = st["signed"]
                d = json.loads(s["statement"])
                db.x("INSERT INTO coordinator_moves(move_id,plan_id,epoch,statement,sig_from,sig_to,sig_owner,state,created_at,"
                     "not_before,ended_at) VALUES(?,?,?,?,?,?,?,'committed',?,?,?)",
                     (d["move_id"], None, d["epoch"], s["statement"], s["signatures"]["from"], s["signatures"]["to"],
                      s["signatures"].get("owner"), time.time(), d["not_before"], time.time()))
        db.x("UPDATE coordinator_plans SET state='done' WHERE state IN ('prepared','paired','moving')")
        db.event("coordinator_promoted", reason=f"epoch {st['epoch']} from {st.get('from_url')}")
    st["phase"] = "active"
    save(home, st)
    shutil.rmtree(home / "move" / "staging", ignore_errors=True)
    from . import modlife
    with db.tx():
        off = modlife.disable_unsupported(db)
    if off:
        db.event("modules_disabled_after_move", reason=", ".join(off)[:300])
    try:
        from . import modlife
        rebuilt = modlife.runtimes_ok(db)              # venvs are machine-specific and were not carried
        if rebuilt:
            db.event("module_runtimes_rebuilt", reason=", ".join(rebuilt)[:300])
    except Exception as e:
        db.event("background_error", reason=f"rebuilding module runtimes after the move: {e!r}"[:300])
    return True
