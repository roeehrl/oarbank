"""oarbankd core (job-agnostic): enrollment, sessions, per-module certification, resource-fitting
dispatch, fencing, acceptance, reaper. Job specifics are delegated to modules, out of process (oarbankd.modcalls).

Every function takes the DB and returns plain dicts, so the HTTP layer stays thin and the
logic is unit-testable. Invariants (see docs/verification.md):
  * a result is canonical only if its attempt's generation and certification are current,
    its effective mode matches the job's expected mode, and the job is not already done;
  * lease expiry and user/limit/sleep releases never count as job failures;
  * offline is derived from missed heartbeats, never from Tailscale alone.
"""
import json
import secrets
from dataclasses import dataclass
import subprocess
from pathlib import Path

from oarbank_sdk import platform as pf

from . import config as C
from . import clock
from .db import DB, jl
from . import agentbuilds, coordmove, identity, modcalls, modstore, owner, placement, platforms, predicates, releases
from .modcalls import ModuleError, ModuleUnavailable
from ..common import sha256_hex


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str = "", headers: dict | None = None):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail, self.headers = status, code, detail, headers or {}


AWAIT_MODULE_TTL = 600.0     # lease held for a completion waiting on a module fault (> the agent's 300 s backoff cap)


NON_FAILURE_RELEASES = {"preempt_memory", "preempt_protection", "user_cancel", "limit_mem", "limit_cpu", "limit_schedule",
                        "transient"}
HOST_FAILURES = {"doctor", "mode_mismatch", "oom", "no_metrics"}   # failures that implicate the host first


def now():
    return clock.now()


# ---------------------------------------------------------------- tailscale identity
def tailscale_whois(ip: str) -> dict | None:
    """Stable node id + login for a Tailscale peer address, via the local tailscaled."""
    if not ip or not (ip.startswith("100.") or ip.startswith("fd7a:")):
        return None
    cmd = [C.TAILSCALE] + (["--socket", C.TAILSCALE_SOCKET] if C.TAILSCALE_SOCKET else []) + \
          ["whois", "--json", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return None
        d = json.loads(out.stdout)
        node = d.get("Node") or {}
        prof = d.get("UserProfile") or {}
        return {"ts_node_id": node.get("StableID") or str(node.get("ID")),
                "ts_name": node.get("ComputedName") or node.get("Name"),
                "login": prof.get("LoginName"), "tags": node.get("Tags") or []}
    except Exception:
        return None


def tailscale_peers() -> list[dict]:
    """Discovery hint only: peers from `tailscale status --json` on an OS an agent runs on (spec/platforms.md)."""
    cmd = [C.TAILSCALE] + (["--socket", C.TAILSCALE_SOCKET] if C.TAILSCALE_SOCKET else []) + \
          ["status", "--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        d = json.loads(out.stdout)
    except Exception:
        return []
    peers = list((d.get("Peer") or {}).values())
    me = (d.get("Self") or {}).get("UserID")
    if d.get("Self"):
        peers.append(d["Self"])
    res = []
    for p in peers:
        if (p.get("OS") or "").lower() not in ("macos", "linux", "windows"):
            continue
        # only the owner's own machines (or tagged dedicated nodes), not devices shared in by other users
        if me is not None and p.get("UserID") != me and not p.get("Tags"):
            continue
        res.append({"ts_node_id": p.get("ID"), "name": (p.get("DNSName") or "").split(".")[0],
                    "hostname": p.get("HostName"), "online": bool(p.get("Online")),
                    "last_seen": p.get("LastSeen"), "ips": p.get("TailscaleIPs") or [],
                    "relay": p.get("Relay"), "cur_addr": p.get("CurAddr")})
    return res


# ---------------------------------------------------------------- enrollment
def enroll(db: DB, hostname: str, facts: dict, peer_ip: str, csr: str, join: str | None = None) -> dict:
    """An enrollment request with the agent's CSR: approval issues a client certificate for the node's own key."""
    from cryptography import x509
    try:
        x509.load_pem_x509_csr(csr.encode())
    except ValueError:
        raise ApiError(400, "csr_required", "enrolling needs a PEM certificate request")
    who = tailscale_whois(peer_ip)
    ts_node_id = who["ts_node_id"] if who else None
    if ts_node_id:
        existing = db.one("SELECT enrollment_id,status FROM enrollments WHERE ts_node_id=? "
                          "AND status='pending'", (ts_node_id,))
        if existing:
            return {"enrollment_id": existing["enrollment_id"], "status": "pending"}
    eid = "enr_" + secrets.token_hex(6)
    db.x("INSERT INTO enrollments(enrollment_id,hostname,facts_json,peer_ip,ts_node_id,status,created_at,csr_pem)"
         " VALUES(?,?,?,?,?,'pending',?,?)", (eid, hostname, json.dumps(facts), peer_ip, ts_node_id, now(), csr))
    db.event("enroll_requested", actor=hostname, reason=peer_ip, enrollment_id=eid, ts=who)
    if join:
        from . import joincodes
        jc = joincodes.redeem(db, join)
        if jc is None:
            db.event("join_code_refused", actor=hostname, reason=peer_ip, enrollment_id=eid)
            return {"enrollment_id": eid, "status": "pending", "join": "refused"}
        approve_enrollment(db, eid, f"join:{jc['created_by']}", label=jc["label"])
        node = db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (eid,))
        db.x("UPDATE join_codes SET node_id=? WHERE code_hash=?", (node["node_id"], jc["code_hash"]))
        return {"enrollment_id": eid, "status": "approved"}
    return {"enrollment_id": eid, "status": "pending"}


def enroll_status(db: DB, eid: str) -> dict:
    with db.tx():
        e = db.one("SELECT * FROM enrollments WHERE enrollment_id=?", (eid,))
        if not e:
            raise ApiError(404, "not_found", eid)
        if e["status"] == "approved" and e["cert_json"]:
            cert = json.loads(e["cert_json"])
            db.x("UPDATE enrollments SET status='claimed', cert_json=NULL WHERE enrollment_id=?", (eid,))
            return {"status": "approved", "node_id": e["node_id"], "cert_pem": cert["cert_pem"], "ca_pem": cert["ca_pem"],
                    "cert_not_after": cert["not_after"]}
        return {"status": e["status"]}


def approve_enrollment(db: DB, eid: str, actor: str, label: str | None = None) -> dict:
    """Approve an enrollment: the node (a known Tailscale node keeps its node_id) gets its client certificate. Its name
    is `label` (a join code's), else a label it already had, else the hostname it reported; a labelled node keeps its
    name when its agent reports another one (hello)."""
    label = (label or "").strip() or None
    with db.tx():
        e = db.one("SELECT * FROM enrollments WHERE enrollment_id=?", (eid,))
        if not e or e["status"] != "pending":
            raise ApiError(409, "not_pending", eid)
        facts = jl(e["facts_json"], {})
        # Re-enrolment of a known Tailscale node keeps its node_id (and history).
        node = db.one("SELECT node_id FROM nodes WHERE ts_node_id=? AND ts_node_id IS NOT NULL",
                      (e["ts_node_id"],)) if e["ts_node_id"] else None
        node_id = node["node_id"] if node else "n_" + secrets.token_hex(4)
        if node:
            db.x("UPDATE nodes SET lifecycle='enrolled', facts_json=?, hostname=COALESCE(?, label, ?), label=COALESCE(?, label),"
                 " ts_ip=?, quarantine_reason=NULL, want_doctor=1 WHERE node_id=?",
                 (json.dumps(facts), label, e["hostname"], label, e["peer_ip"], node_id))
        else:
            db.x("INSERT INTO nodes(node_id,ts_node_id,hostname,label,ts_ip,facts_json,lifecycle,desired_state,"
                 "limits_json,policy_json,created_at) VALUES(?,?,?,?,?,?,'enrolled','active','{}',?,?)",
                 (node_id, e["ts_node_id"], label or e["hostname"], label, e["peer_ip"], json.dumps(facts),
                  json.dumps(C.policy_for(facts, db.get_setting("default_worker_disabled_services"))), now()))
        db.x("UPDATE nodes SET platform=?, os=?, arch=?, os_version=? WHERE node_id=?", (*_platform_cols(facts), node_id))
        from . import tlsca
        try:
            cert = tlsca.issue_client(Path(db.path).parent, e["csr_pem"], node_id)
        except tlsca.CAError as err:
            raise ApiError(400, "bad_csr", str(err))
        db.x("UPDATE nodes SET client_cert_fp=?, client_cert_prev_fp=NULL, client_cert_not_after=? WHERE node_id=?",
             (cert["fingerprint"], cert["not_after"], node_id))
        db.x("UPDATE enrollments SET status='approved', node_id=?, decided_at=?, decided_by=?, cert_json=? WHERE enrollment_id=?",
             (node_id, now(), actor, json.dumps(cert), eid))
        db.event("enroll_approved", actor=actor, node_id=node_id, enrollment_id=eid)
    releases.ensure(db, platforms.facts_platform(facts)["platform"])
    return {"node_id": node_id}


def _platform_cols(facts: dict) -> tuple:
    fp = platforms.facts_platform(facts)
    return fp["platform"], fp["os"], fp["arch"], fp["os_version"]


def reject_enrollment(db: DB, eid: str, actor: str) -> dict:
    db.x("UPDATE enrollments SET status='rejected', decided_at=?, decided_by=? WHERE enrollment_id=? "
         "AND status='pending'", (now(), actor, eid))
    db.event("enroll_rejected", actor=actor, enrollment_id=eid)
    return {"ok": True}


def auth_cert(db: DB, der: bytes | None, peer_ip: str) -> dict:
    """mTLS (D29): the client certificate the TLS layer verified against the coordinator CA names the node, and its
    fingerprint is the node's current (or, while renewing, previous) certificate. Nothing secret is stored here."""
    from . import tlsca
    if not der:
        raise ApiError(401, "client_certificate_required", "this listener needs the node's client certificate")
    nid, fp = tlsca.node_of(der), tlsca.fingerprint(der)
    node = db.one("SELECT * FROM nodes WHERE node_id=? AND (client_cert_fp=? OR client_cert_prev_fp=?)", (nid, fp, fp)) \
        if nid else None
    if not node:
        raise ApiError(401, "unauthorized", "unknown or replaced client certificate")
    if fp == node["client_cert_fp"] and node["client_cert_prev_fp"]:     # the renewed certificate is in use: retire the old
        db.x("UPDATE nodes SET client_cert_prev_fp=NULL WHERE node_id=?", (node["node_id"],))
    return _node_checks(db, node, peer_ip)


def renew_cert(db: DB, node: dict, csr: str) -> dict:
    """A fresh client certificate for the node's (possibly new) key; the current one stays valid until the new one is
    first used."""
    from . import tlsca
    try:
        cert = tlsca.issue_client(Path(db.path).parent, csr, node["node_id"])
    except tlsca.CAError as e:
        raise ApiError(400, "bad_csr", str(e))
    db.x("UPDATE nodes SET client_cert_prev_fp=client_cert_fp, client_cert_fp=?, client_cert_not_after=? WHERE node_id=?",
         (cert["fingerprint"], cert["not_after"], node["node_id"]))
    db.event("node_cert_renewed", node_id=node["node_id"], actor=node["hostname"], reason=cert["fingerprint"][:16])
    return {"cert_pem": cert["cert_pem"], "ca_pem": cert["ca_pem"], "cert_not_after": cert["not_after"]}


def _node_checks(db: DB, node: dict, peer_ip: str) -> dict:
    if node["lifecycle"] == "retired":
        raise ApiError(403, "node_retired", node["node_id"])
    if node["ts_node_id"] and peer_ip and peer_ip.startswith("100."):
        # A certificate presented from another Tailscale node: refuse (its key was copied off the node). The node's
        # own new address is re-pinned: a coordinator move installs the standby there.
        if peer_ip != node["ts_ip"]:
            who = tailscale_whois(peer_ip)
            if who and who["ts_node_id"] != node["ts_node_id"]:
                raise ApiError(401, "unauthorized", "certificate/node mismatch")
            db.x("UPDATE nodes SET ts_ip=? WHERE node_id=?", (peer_ip, node["node_id"]))
            db.event("node_ip_repinned", node_id=node["node_id"],
                     reason=f"{node['ts_ip']} -> {peer_ip} (whois {'confirmed' if who else 'unavailable'})")
    return node


# ---------------------------------------------------------------- session
def _node_directives(db: DB, node: dict) -> dict:
    rid = releases.assigned(db, node)
    rel = db.one("SELECT release_id, sha256, statement, signature FROM releases WHERE release_id=?", (rid,)) if rid else None
    release = None
    if rel and node["release_id"] != rel["release_id"]:
        release = {"release_id": rel["release_id"], "url": f"/v1/releases/{rel['release_id']}.tar.gz",
                   "sha256": rel["sha256"]}
        if C.RELEASE_SIGNING:
            release.update(statement=rel["statement"], signature=rel["signature"])
    return {"now": now(), "desired_state": node["desired_state"], "lifecycle": node["lifecycle"],
            "limits": jl(node["limits_json"], {}), "policy": jl(node["policy_json"], {}),
            "heartbeat_s": C.HEARTBEAT_S, "release": release,
            "release_pubkey": db.get_setting("release_pubkey") if C.RELEASE_SIGNING else None,
            "prefetch": prefetch_for(db, node), "run_doctor": bool(node["want_doctor"]),
            "run_probe": bool(node.get("want_probe")), "send_processes": bool(node.get("want_processes")),
            "agent_update": agentbuilds.directive(db, node),
            "coordinator": {"fleet_id": identity.fleet_id(db), "cik": identity.key(Path(db.path).parent).public_b64,
                            "epoch": identity.epoch(db)},
            "install_coordinator": jl(node.get("install_coordinator_json")),
            "renew_cert": bool(node.get("client_cert_fp") and (node.get("client_cert_not_after") or 0) - now() < _renew_within()),
            **coordmove.directives(db), **owner.directives(db)}


def _renew_within() -> float:
    from .tlsca import RENEW_WITHIN_S
    return RENEW_WITHIN_S


CLOCK_SKEW_S = 60.0          # a node clock further off than this is a node condition (CLOCK_SKEW)


def clock_offset(body: dict, t: float, prev: float | None) -> float | None:
    """The node's wall clock minus ours, from the `clock` it sent (protocol.md, "Clocks"); `prev` without one."""
    c = body.get("clock")
    return round(float(c) - t, 1) if isinstance(c, (int, float)) and not isinstance(c, bool) else prev


def hello(db: DB, node: dict, body: dict) -> dict:
    t = now()
    facts = dict(body.get("facts") or {})
    live = [int(a) for a in body.get("live_attempts") or []]
    if facts.get("platform"):
        releases.ensure(db, platforms.facts_platform(facts)["platform"])     # a platform the fleet has no release for yet
    with db.tx():
        db.x("UPDATE nodes SET agent_version=?, boot_id=?, facts_json=?, release_id=?, last_hello_at=?,"
             " last_heartbeat_at=?, ready_datasets_json=?, clock_offset_s=? WHERE node_id=?",
             (body.get("agent_version"), body.get("boot_id"), json.dumps(facts or jl(node["facts_json"], {})),
              body.get("release_id"), t, t, json.dumps(body.get("ready_datasets") or []),
              clock_offset(body, t, node.get("clock_offset_s")), node["node_id"]))
        if facts.get("platform"):
            cols = _platform_cols(facts)
            if node.get("platform") and cols[0] != node["platform"]:
                db.event("platform_changed", node_id=node["node_id"], reason=f"{node['platform']} -> {cols[0]}")
            db.x("UPDATE nodes SET platform=?, os=?, arch=?, os_version=? WHERE node_id=?", (*cols, node["node_id"]))
        # the name the node reports (a renamed machine, or OARBANK_NODE_NAME), unless its join code's label named it
        name = str(facts.get("hostname") or "").strip()[:63]
        if name and name != node["hostname"] and not node["label"]:
            db.x("UPDATE nodes SET hostname=? WHERE node_id=?", (name, node["node_id"]))
            db.event("node_renamed", node_id=node["node_id"], actor=name, reason=f"{node['hostname']} -> {name}")
        # Attempts the agent thinks are live but we don't: kill them.
        kill = []
        for aid in live:
            a = db.one("SELECT state,node_id FROM attempts WHERE attempt_id=?", (aid,))
            if not a or a["state"] != "live" or a["node_id"] != node["node_id"]:
                kill.append(aid)
            else:
                db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (t + C.LEASE_TTL, aid))
        # Attempts we think are live on this node but the agent doesn't know: it restarted.
        known = set(live)
        for a in db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live'", (node["node_id"],)):
            if a["attempt_id"] not in known:
                _end_attempt(db, a["attempt_id"], "released", "agent_restart", count_failure=False)
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
        agentbuilds.observe(db, node, body)
        _observe_identity(db, node, body)
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
        _lifecycle_step(db, node, facts)
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
    db.event("hello", actor=node["hostname"], node_id=node["node_id"], reason=body.get("boot_id"),
             agent_version=body.get("agent_version"), release_id=body.get("release_id"))
    run_pending_goldens(db, node["node_id"])
    d = _node_directives(db, node)
    d.update(node_id=node["node_id"], kill=kill)
    return d


def _observe_identity(db: DB, node: dict, body: dict):
    """Which coordinator key the agent pinned (shown beside oarbankd's own, for the owner to confirm once)."""
    mv = body.get("coordinator_move_state")
    if isinstance(mv, dict):
        db.x("UPDATE nodes SET coordinator_move_json=? WHERE node_id=?", (json.dumps(mv)[:4000], node["node_id"]))
    ic = body.get("coordinator_install")
    if isinstance(ic, dict) and ic.get("state") in ("installed", "failed"):
        db.x("UPDATE nodes SET install_coordinator_json=NULL WHERE node_id=?", (node["node_id"],))
        db.event(f"coordinator_install_{ic['state']}", node_id=node["node_id"], actor=node["hostname"],
                 reason=(ic.get("error") or "")[:300])
    fp = body.get("cik_pinned")
    if fp and fp != node.get("cik_pinned"):
        db.x("UPDATE nodes SET cik_pinned=? WHERE node_id=?", (fp, node["node_id"]))
        db.event("node_identity_pinned", node_id=node["node_id"], actor=node["hostname"], reason=fp[:16])


def heartbeat(db: DB, node: dict, body: dict) -> dict:
    t = now()
    nid = node["node_id"]
    tel, cap = body.get("telemetry") or {}, body.get("capacity") or {}
    with db.tx():
        was_offline = (node["last_heartbeat_at"] or 0) < t - C.OFFLINE_AFTER
        db.x("UPDATE nodes SET last_heartbeat_at=?, telemetry_json=?, capacity_json=?, ready_datasets_json=?, clock_offset_s=?"
             " WHERE node_id=?", (t, json.dumps(tel), json.dumps(cap),
                                  json.dumps(body.get("ready_datasets") or jl(node["ready_datasets_json"], [])),
                                  clock_offset(body, t, node.get("clock_offset_s")), nid))
        last = db.one("SELECT MAX(ts) m FROM node_samples WHERE node_id=?", (nid,))
        if not last or not last["m"] or t - last["m"] >= C.SAMPLE_EVERY:
            busy = db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='live'", (nid,))["n"]
            db.x("INSERT OR REPLACE INTO node_samples VALUES(?,?,?,?,?)", (nid, t, json.dumps(tel), json.dumps(cap), busy))
            db.x("DELETE FROM node_samples WHERE node_id=? AND ts<?", (nid, t - 7 * 86400))
        for a in body.get("attempts") or []:
            row = db.one("SELECT * FROM attempts WHERE attempt_id=?", (int(a["attempt_id"]),))
            if not row or row["state"] != "live" or row["node_id"] != nid:
                continue
            progressed = (a.get("cpu_s", 0) > (row["cpu_s"] or 0) + 0.01 or
                          a.get("log_bytes", 0) > (row["log_bytes"] or 0) or a.get("phase") in ("staging", "paused")
                          or row["cpu_s"] is None)
            if a.get("phase") and a.get("phase") != row["phase"]:
                db.x("INSERT OR IGNORE INTO attempt_phases VALUES(?,?,?)", (row["attempt_id"], a["phase"], t))
            db.x("UPDATE attempts SET phase=?, cpu_s=?, log_bytes=?, rss_gb=?, expires_at=?, last_progress_at=?"
                 " WHERE attempt_id=?",
                 (a.get("phase"), a.get("cpu_s", 0), a.get("log_bytes", 0), a.get("rss_gb"),
                  t + C.LEASE_TTL if progressed else row["expires_at"],
                  t if progressed else row["last_progress_at"], row["attempt_id"]))
        agentbuilds.observe(db, node, body)
        _observe_identity(db, node, body)
        if isinstance(body.get("processes"), list):
            db.x("UPDATE nodes SET processes_json=?, processes_at=?, want_processes=0 WHERE node_id=?",
                 (json.dumps(body["processes"][:200])[:400_000], t, nid))
        if body.get("doctor") is not None:
            db.x("UPDATE nodes SET doctor_json=?, doctor_at=?, want_doctor=0 WHERE node_id=?",
                 (json.dumps(body["doctor"]), t, nid))
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
        _lifecycle_step(db, node, jl(node["facts_json"], {}))
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
        ack = _ingest_journal(db, nid, body.get("journal") or [])
        cancel, revoke = jl(node["pending_cancel_json"], []), jl(node["pending_revoke_json"], [])
        db.x("UPDATE nodes SET pending_cancel_json='[]', pending_revoke_json='[]' WHERE node_id=?", (nid,))
        recert = bool(node["want_recertify"])
        if recert:
            db.x("UPDATE nodes SET want_recertify=0 WHERE node_id=?", (nid,))
        if node.get("want_probe"):
            db.x("UPDATE nodes SET want_probe=0 WHERE node_id=?", (nid,))     # sent once, in this reply
    if was_offline:
        db.event("node_online", node_id=nid, actor=node["hostname"])
    run_pending_goldens(db, nid)
    d = _node_directives(db, node)
    d.update(cancel=cancel, revoke=revoke, recertify=recert)
    if ack is not None:
        d["journal_ack"] = ack
    return d


def _ingest_journal(db: DB, node_id: str, records: list) -> int | None:
    """Store the agent's protection decisions (idempotent on (node, seq)); returns the highest seq stored."""
    top = None
    for r in records[:500]:
        try:
            seq = int(r["seq"])
        except (KeyError, TypeError, ValueError):
            continue
        db.x("INSERT OR IGNORE INTO protection_decisions(node_id,seq,t,kind,reason,rule,record_json) VALUES(?,?,?,?,?,?,?)",
             (node_id, seq, r.get("t"), r.get("kind"), r.get("reason"), r.get("rule"), json.dumps(r)[:8000]))
        top = seq if top is None else max(top, seq)
    return top


# ---------------------------------------------------------------- lifecycle (per node x module)
def node_modules(node: dict) -> dict:
    return jl(node.get("modules_json"), {}) or {}


def _set_module_state(db: DB, node_id: str, module: str, **fields):
    row = db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node_id,))
    ms = jl(row["modules_json"], {}) or {}
    cur = ms.get(module, {})
    cur.update(fields, at=now())
    ms[module] = cur
    db.x("UPDATE nodes SET modules_json=? WHERE node_id=?", (json.dumps(ms), node_id))
    return cur


def certified_modules(node: dict) -> list[str]:
    return [m for m, st in node_modules(node).items() if st.get("state") == "certified"]


def _lifecycle_step(db: DB, node: dict, facts: dict):
    """enrolled -> ready (current release installed); then per module: doctor ok -> certifying
    (golden jobs queued) -> certified. Re-certify a module on a release, platform or OS version change, or every 6 h."""
    nid, lc = node["node_id"], node["lifecycle"]
    if lc in ("retired", "quarantined"):
        return
    rel_id = releases.assigned(db, node)
    comp = releases.composition_of(db, rel_id)
    if lc == "enrolled":
        if rel_id and node["release_id"] == rel_id:
            db.x("UPDATE nodes SET lifecycle='ready', want_doctor=1 WHERE node_id=?", (nid,))
            db.event("lifecycle", node_id=nid, reason="ready (release installed)")
        return
    doc = jl(node["doctor_json"]) or {}
    reports = doc.get("modules") or {}
    states = node_modules(node)
    for name in modcalls.enabled(db):
        rep, st = reports.get(name), states.get(name, {})
        s = st.get("state")
        if rep is None:
            continue                      # agent hasn't doctored this module (yet)
        health = rep.get("health")
        if health == "undetected":        # the node cannot run it (runner protocol): never offered, no alert
            if s != "undetected":
                _set_module_state(db, nid, name, state="undetected", reason="doctor: undetected")
                _resolve_alert(db, f"doctor_failed:{name}", nid)
            continue
        if health != "healthy":
            if s != "doctor_failed":
                bad = [c["name"] for c in rep.get("checks", []) if not c.get("ok")]
                _set_module_state(db, nid, name, state="doctor_failed", reason=", ".join(bad))
                _alert(db, f"doctor_failed:{name}", nid, f"{node['hostname']}: {name} doctor failed: {', '.join(bad)}")
            continue
        if s == "golden_failed" and node["release_id"] == rel_id and now() - (st.get("at") or 0) > C.RECERT_EVERY:
            _set_module_state(db, nid, name, golden_failures=0)
            queue_goldens(db, nid, name)
            continue
        if s in (None, "doctor_failed", "undetected", "revoked") and node["release_id"] == rel_id:
            _resolve_alert(db, f"doctor_failed:{name}", nid)
            queue_goldens(db, nid, name)
            continue
        if s == "certified":
            reasons = []
            want = (comp.get(name) or {}).get("digest")
            if rel_id and node["release_id"] == rel_id and want and st.get("digest") != want:
                reasons.append("digest")
            fp = platforms.facts_platform(facts)
            if fp["platform"] and st.get("platform") and fp["platform"] != st["platform"]:
                reasons.append("platform")
            if fp["os_version"] and st.get("os_version") and fp["os_version"] != st["os_version"]:
                reasons.append("os_version")
            if st.get("certified_at") and now() - st["certified_at"] > C.RECERT_EVERY:
                reasons.append("periodic")
            if reasons:
                db.event("recertify", node_id=nid, reason=f"{name}: {','.join(reasons)}")
                queue_goldens(db, nid, name)


def _cancel_goldens(db: DB, node_id: str, module: str, why: str):
    for g in db.q("SELECT job_id FROM jobs WHERE target_node=? AND kind='golden' AND module=? AND state IN ('pending','leased')",
                  (node_id, module)):
        db.x("UPDATE jobs SET state='cancelled', generation=generation+1 WHERE job_id=?", (g["job_id"],))
        for a in db.q("SELECT attempt_id FROM attempts WHERE job_id=? AND state='live'", (g["job_id"],)):
            db.x("UPDATE attempts SET state='revoked', end_reason=?, ended_at=? WHERE attempt_id=?", (why, now(), a["attempt_id"]))
            _push(db, node_id, "revoke", a["attempt_id"])


def _golden_failed(db: DB, node_id: str, module: str, failures: int, reason: str):
    """Golden jobs keep failing on this node: stop retrying (TLA+ review F6). Retried automatically after
    RECERT_EVERY, or at once by a manual recertify."""
    _cancel_goldens(db, node_id, module, "golden_failed")
    _set_module_state(db, node_id, module, state="golden_failed", golden_failures=failures, generation=-1,
                      reason=f"{failures} golden failures (last: {reason})")
    db.event("golden_failed", node_id=node_id, reason=f"{module}: {failures} failures, last {reason}")
    _alert(db, f"golden_failed:{module}", node_id,
           f"{module}: golden jobs failed {failures} times on this node (last: {reason}); not certified", priority="high")


def queue_goldens(db: DB, node_id: str, module: str):
    """Start (re)certifying a module on a node. Runs inside the caller's transaction, so it only records
    the request (state certifying, goldens_pending); run_pending_goldens() asks the module for its golden
    set out of process after the commit and queues the jobs (module IPC never holds the write lock)."""
    _cancel_goldens(db, node_id, module, "superseded")      # a new set replaces any stale one (F6)
    prev = node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node_id,))).get(module, {})
    _set_module_state(db, node_id, module, state="certifying", generation=prev.get("generation", 0), reason=None,
                      certifying_since=now(), goldens_pending=True)


def run_pending_goldens(db: DB, node_id: str | None = None) -> int:
    """Fetch and queue golden sets requested by queue_goldens. Call outside any transaction. A module
    fault leaves the request pending (retried by the next heartbeat or reap) and is never charged to the
    node (S15). Returns the number of golden sets queued."""
    n = 0
    rows = db.q("SELECT * FROM nodes WHERE node_id=?", (node_id,)) if node_id else \
        db.q("SELECT * FROM nodes WHERE lifecycle='ready'")
    for node in rows:
        for module, st in node_modules(node).items():
            if not (st.get("state") == "certifying" and st.get("goldens_pending")):
                continue
            ver = modstore.version_for_node(db, module, node["node_id"])
            try:
                goldens = modcalls.goldens(db, module, node, ver)
            except (ModuleUnavailable, ModuleError) as e:
                db.event("module_fault", node_id=node["node_id"], reason=f"{module} golden.list: {e}")
                continue
            with db.tx():
                cur = node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node["node_id"],))).get(module, {})
                if not (cur.get("state") == "certifying" and cur.get("goldens_pending")
                        and cur.get("certifying_since") == st.get("certifying_since")):
                    continue                                  # superseded or cancelled meanwhile
                _insert_goldens(db, node["node_id"], module, goldens, ver)
                n += 1
    return n


def _insert_goldens(db: DB, node_id: str, module: str, goldens: list[dict], version: str | None = None):
    stamp = f"{node_id}:{now()}"
    try:
        mi = modcalls.info_for(module, version)
    except KeyError:
        mi = modcalls.info(module)
    for g in goldens:
        spec = {**g["payload"], "mounts": g.get("mounts") or {}, "expected": g["expected"]}
        key = sha256_hex(g["key"] + stamp)
        db.x("INSERT INTO jobs(job_key,dataset_id,kind,target_node,priority,state,spec_json,"
             "datasets_json,created_at,module,resources_json,name,stage,spec_version) VALUES(?,?, 'golden',?,1000,'pending',?,?,?,?,?,?,?,?)",
             (key, (g.get("datasets") or [None])[-1], node_id, json.dumps(spec), json.dumps(g.get("datasets") or []),
              now(), module, json.dumps(mi.stage_resources(g.get("stage"))), g["name"], g.get("stage"), g.get("spec_version") or 1))
    db.event("golden_queued", node_id=node_id, reason=module, n=len(goldens))
    _set_module_state(db, node_id, module, goldens_pending=False)
    if not goldens:
        # every module requires golden evidence before it gets work
        _set_module_state(db, node_id, module, state="doctor_failed", reason="no golden jobs configured")
        _alert(db, f"no_golden:{module}", node_id, f"{module} cannot be certified: no golden jobs configured")


def _certify(db: DB, node_id: str, module: str, note: str = ""):
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node_id,))
    gen = int(db.get_setting("cert_counter", 0)) + 1
    db.set_setting("cert_counter", gen)
    fp = platforms.facts_platform(jl(node["facts_json"], {}))
    digest = (releases.composition_of(db, node["release_id"]).get(module) or {}).get("digest")
    _set_module_state(db, node_id, module, state="certified", generation=gen, release=node["release_id"], digest=digest,
                      platform=fp["platform"], os_version=fp["os_version"], certified_at=now(), reason=None, golden_failures=0)
    db.x("UPDATE nodes SET cert_os_version=? WHERE node_id=?", (fp["os_version"], node_id))
    db.x("UPDATE nodes SET breaker_failures=0 WHERE node_id=?", (node_id,))
    db.event("certified", node_id=node_id, reason=f"{module} generation {gen} {note}".strip())
    _resolve_alert(db, f"certifying_stuck:{module}", node_id)
    _resolve_alert(db, f"golden_failed:{module}", node_id)  # the goldens pass now
    _resolve_alert(db, "breaker", node_id)                 # re-doctored and re-certified: recovered
    _resolve_alert(db, "quarantined", node_id)


def _golden_done(db: DB, node_id: str, module: str):
    pending = db.one("SELECT COUNT(*) n FROM jobs WHERE target_node=? AND kind='golden' AND module=? "
                     "AND state IN ('pending','leased')", (node_id, module))["n"]
    st = node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node_id,))).get(module, {})
    if not pending and st.get("state") == "certifying":
        _certify(db, node_id, module)


def _revoke_quiet(db: DB, node_id: str, module: str, reason: str):
    _set_module_state(db, node_id, module, state="revoked", reason=reason, generation=-1)
    for a in db.q("SELECT a.attempt_id FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.node_id=? "
                  "AND a.state='live' AND j.module=?", (node_id, module)):
        _end_attempt(db, a["attempt_id"], "revoked", "module_revoked", count_failure=False)
        _push(db, node_id, "revoke", a["attempt_id"])
    db.event("module_revoked", node_id=node_id, reason=f"{module}: {reason}")


def revoke_module(db: DB, node_id: str, module: str, reason: str):
    _revoke_quiet(db, node_id, module, reason)
    _alert(db, f"revoked:{module}", node_id, f"{module} revoked on node: {reason}", priority="high")


def quarantine(db: DB, node_id: str, reason: str, actor="system"):
    db.x("UPDATE nodes SET lifecycle='quarantined', quarantine_reason=? WHERE node_id=?", (reason, node_id))
    for a in db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live'", (node_id,)):
        _end_attempt(db, a["attempt_id"], "revoked", "node_quarantined", count_failure=False)
        _push(db, node_id, "revoke", a["attempt_id"])
    db.event("quarantined", actor=actor, node_id=node_id, reason=reason)
    if "nondeterminism" in reason:
        invalidate_node_results(db, node_id, reason)
    _alert(db, "quarantined", node_id, f"node quarantined: {reason}", priority="high")


def clear_quarantine(db: DB, node_id: str, actor: str):
    db.x("UPDATE nodes SET lifecycle='enrolled', quarantine_reason=NULL, want_doctor=1, doctor_json=NULL,"
         " breaker_failures=0, modules_json='{}' WHERE node_id=?", (node_id,))
    db.event("quarantine_cleared", actor=actor, node_id=node_id)


def recertify(db: DB, node_id: str, actor: str):
    db.x("UPDATE nodes SET modules_json='{}', want_doctor=1, doctor_json=NULL WHERE node_id=?", (node_id,))
    db.event("recertify", actor=actor, node_id=node_id, reason="manual (all modules)")


def _push(db: DB, node_id: str, which: str, attempt_id: int):
    col = "pending_cancel_json" if which == "cancel" else "pending_revoke_json"
    row = db.one(f"SELECT {col} v FROM nodes WHERE node_id=?", (node_id,))
    lst = jl(row["v"], []) if row else []
    if attempt_id not in lst:
        lst.append(attempt_id)
    db.x(f"UPDATE nodes SET {col}=? WHERE node_id=?", (json.dumps(lst), node_id))


PREFETCH_TTL_S = 15.0
_PREFETCH_CACHE: dict = {}      # id(db) -> {"at", "rows"}


def prefetch_for(db: DB, node: dict) -> list[str]:
    """Datasets this node should stage: everything referenced by open work it may run."""
    mods = set(certified_modules(node)) | {m for m, st in node_modules(node).items() if st.get("state") == "certifying"}
    if not mods:
        return []
    t = now()
    cache = _PREFETCH_CACHE.setdefault(id(db), {"at": -1e18, "rows": []})
    if not (0 <= t - cache["at"] <= PREFETCH_TTL_S):
        # one fleet-wide scan per TTL instead of one per heartbeat (bench/README.md bottleneck 3)
        cache["rows"] = db.q("SELECT DISTINCT datasets_json, module FROM jobs WHERE state IN ('pending','leased') "
                                       "AND target_node IS NULL LIMIT 500")
        cache["at"] = t
    rows = cache["rows"] + db.q("SELECT DISTINCT datasets_json, module FROM jobs WHERE target_node=? AND "
                                          "state IN ('pending','leased')", (node["node_id"],))
    want = []
    for r in rows:
        if r["module"] not in mods:
            continue
        for d in jl(r["datasets_json"], []):
            if d not in want:
                want.append(d)
    return want


# ---------------------------------------------------------------- dispatch
# ---------------------------------------------------------------- staged pipelines
def node_disabled_services(node: dict) -> list[str]:
    """Services the owner disabled on this node ("<module>/<service>" or "*/<service>")."""
    return list((jl(node.get("policy_json"), {}) or {}).get("disabled_services") or [])


def expand_pipeline(db: DB, job_id: int) -> int | None:
    """Split a freshly created eval job into its module's stage chain head -> tail when the pipeline is
    split. The eval job keeps its key, spec, campaign and labels (so caches and module views are unchanged);
    it becomes the tail stage and waits for a head job (kind 'call', key `<key>:<head>`) that produces its input."""
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))
    if not j or j["kind"] != "eval" or j["state"] != "pending" or j["depends_on"] or not modcalls.split_enabled(db, j["module"]):
        return None
    mi = modcalls.info(j["module"])
    head, tail = mi.chain
    cid = db.x("INSERT INTO jobs(job_key,campaign_id,labels_json,dataset_id,kind,priority,subpriority,state,spec_json,"
               "datasets_json,created_at,module,resources_json,stage,spec_version,platforms_json,group_key)"
               " VALUES(?,?,?,?,'call',?,?,'pending',?,?,?,?,?,?,?,?,?)",
               (j["job_key"] + ":" + head, j["campaign_id"], j["labels_json"], j["dataset_id"], j["priority"], j["subpriority"],
                j["spec_json"], j["datasets_json"], now(), j["module"], json.dumps(mi.stage_resources(head)), head,
                j["spec_version"], j["platforms_json"], j["group_key"]))
    db.x("UPDATE jobs SET stage=?, depends_on=?, resources_json=? WHERE job_id=?",
         (tail, cid, json.dumps(mi.stage_resources(tail)), job_id))
    placement.assign(db, job_id)                 # head and tail: one unit, feasible for both stages (D33)
    hit = placement.cache_hit(db, db.one("SELECT * FROM jobs WHERE job_id=?", (cid,)))
    if hit:
        db.x("UPDATE jobs SET state='done', canonical_result_id=?, done_at=? WHERE job_id=?", (hit, now(), cid))
    return cid


def set_pipeline(db: DB, module: str, mode: str, actor: str) -> dict:
    """Switch a module between single-stage and split (its stage chain). Enabling split expands every queued
    (pending, never started) eval job into head -> tail, so queued work is not funnelled to the nodes that
    can run the tail. Disabling leaves already-split jobs as they are (they finish as staged jobs). The
    module's golden.list gives nodes that can run only the head its head-stage goldens."""
    if mode not in ("single", "split") or (mode == "split" and not modcalls.info(module).splittable):
        raise ApiError(400, "bad_pipeline", f"{module}: {mode}")
    out = {"module": module, "mode": mode, "expanded": 0}
    with db.tx():
        db.set_setting(f"pipeline:{module}", mode)
        if mode == "split":
            for j in db.q("SELECT job_id FROM jobs WHERE module=? AND kind='eval' AND state='pending' AND depends_on IS NULL "
                          "AND NOT EXISTS (SELECT 1 FROM attempts a WHERE a.job_id=jobs.job_id)", (module,)):
                if expand_pipeline(db, j["job_id"]):
                    out["expanded"] += 1
    db.event("pipeline_changed", actor=actor, reason=f"{module}: {mode} ({out['expanded']} queued jobs split)")
    return out


def _dep_result(db: DB, j: dict) -> dict | None:
    """The canonical result of a job's dependency (the call feeding a score job)."""
    if not j["depends_on"]:
        return None
    r = db.one("SELECT r.* FROM jobs d JOIN results r ON r.result_id=d.canonical_result_id "
               "WHERE d.job_id=? AND d.state='done'", (j["depends_on"],))
    return r


def _requeue_dependents(db: DB, job_id: int, why: str) -> int:
    """A call's canonical result stopped being canonical (dispute, conviction, retry): every score job fed
    by it runs again once a new call result exists. Live score attempts on the old input are revoked."""
    n = 0
    for dj in db.q("SELECT * FROM jobs WHERE depends_on=? AND state IN ('pending','leased','done')", (job_id,)):
        for a in db.q("SELECT attempt_id, node_id FROM attempts WHERE job_id=? AND state='live'", (dj["job_id"],)):
            db.x("UPDATE attempts SET state='revoked', end_reason='input_invalidated', ended_at=? WHERE attempt_id=?",
                 (now(), a["attempt_id"]))
            _push(db, a["node_id"], "revoke", a["attempt_id"])
        db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL "
             "WHERE job_id=?", (dj["job_id"],))
        db.x("UPDATE results SET canonical=0 WHERE job_id=?", (dj["job_id"],))
        n += 1
    if n:
        reopen_campaigns(db)
        db.event("dependents_requeued", job_id=job_id, reason=f"{n} score jobs: {why}")
    return n


def _pool_usage(db: DB, nid: str) -> dict:
    use: dict = {}
    for r in db.q("SELECT j.resources_json FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                  "WHERE a.node_id=? AND a.state='live'", (nid,)):
        for p, n in ((jl(r["resources_json"], {}) or {}).get("pools") or {}).items():
            use[p] = use.get(p, 0) + int(n)
    return use


def _gpu_usage(db: DB, nid: str, platform: str | None) -> int:
    return sum(1 for r in db.q("SELECT j.module, j.resources_json FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                               "WHERE a.node_id=? AND a.state='live'", (nid,))
               if modcalls.job_uses_gpu(r["module"], jl(r["resources_json"], {}), platform))


def _other_node_can_take(db: DB, j: dict, nid: str) -> bool:
    """Is there another ready node, certified for the job's module, that has neither failed this job
    nor is party to its dispute? (If not, this node may retry it despite having failed it before.)"""
    if j["target_node"]:
        return False          # a targeted job (golden) can only ever run on its target (TLA+ review F4)
    failed = {r["node_id"] for r in db.q("SELECT DISTINCT node_id FROM attempts WHERE job_id=? AND state='failed'",
                                          (j["job_id"],))}
    f = _job_facts(db, j)
    disputed = set(f["dispute"].get("nodes", []))
    res = jl(j["resources_json"], {})
    for n in db.q("SELECT node_id, platform, modules_json, capacity_json, policy_json FROM nodes WHERE lifecycle='ready' AND node_id!=?", (nid,)):
        if n["node_id"] in failed or n["node_id"] in disputed or not predicates.platform_fits(f, n["platform"]) \
                or predicates.retry_max(f, n["platform"]) <= j["exec_failures"]:
            continue
        # it must be able to run it at all: a call-only worker cannot take a score job (sim finding)
        if (jl(n["modules_json"], {}) or {}).get(j["module"], {}).get("state") == "certified" and _pools_fit(n, res):
            return True
    return False


def node_view_for_claim(db: DB, node: dict, offered: set, ready: set, free_cpu: float, free_mem: float,
                        body: dict) -> predicates.NodeView:
    """Every node-level fact claim() decides on (read inside its transaction). explain builds the same."""
    from . import modsandbox
    nid = node["node_id"]
    excluded = modsandbox.node_exclusions(db, node, set(offered))
    return predicates.NodeView(
        node=node, states=node_modules(node), offered=set(offered) - set(excluded), excluded=excluded,
        excluded_why=modsandbox.exclusion_reasons(db, node, excluded),
        disabled=modstore.disabled_names(db),
        ready=set(ready), free_cpu=free_cpu, free_mem=free_mem,
        live=db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='live'", (nid,))["n"],
        limits=jl(node["limits_json"], {}) or {}, fleet_state=db.get_setting("fleet_state", "active"),
        current_release=releases.assigned(db, node),
        pool_cap=_node_pools(node), pool_use=_pool_usage(db, nid),
        failed_here={r["job_id"] for r in db.q("SELECT DISTINCT job_id FROM attempts WHERE node_id=? AND state='failed'", (nid,))},
        pool_jobs_only=bool(body.get("pool_jobs_only")),
        gpu_cap=None if body.get("gpu_jobs") is None else int(body["gpu_jobs"]), gpu_use=_gpu_usage(db, nid, node.get("platform")))


def _job_facts(db: DB, j: dict, cache: dict | None = None, cmp: dict | None = None) -> dict:
    """Every job-level fact the predicates decide on (claim and explain alike). `cache`: claim's map of bindings and
    datasets for its candidate loop; `cmp`: a comparison class {scope, class} instead of the job's dispute's."""
    d = jl(j.get("dispute_json"), {}) or {}
    return {**j, "dispute": {**d, "scope": (cmp or {}).get("scope"), "class": (cmp or {}).get("class")} if cmp is not None else d,
            "stage_platforms": modcalls.stage_platforms(j["module"], j["stage"]), "retry": modcalls.stage_retry(j["module"], j["stage"]),
            "placement": placement.facts(db, j, cache)}


# spec keys that belong to the envelope (or the host) rather than the module's payload
ENVELOPE_KEYS = ("envelope", "schema", "module", "module_id", "module_version", "job_key", "protocol", "resources",
                 "datasets", "mounts", "inputs", "timeout_s", "stage")
HOST_KEYS = ("expected",)                 # a golden job's expected result, checked here, never shown to the runner


def envelope(db: DB, j: dict, version: str | None, resources: dict | None = None, dep_artifacts: list | None = None, *,
             platform: str | None) -> dict:
    """The SpecEnvelope for a job (runner protocol; oarbank_sdk.envelopes.SpecEnvelope) on a node of `platform`. Stored
    specs are flat (payload plus envelope fields, as modules enqueue them); this splits them and adds the stage's
    reserved resources and timeout on that platform and, for a tail stage, its head's artifacts as inputs."""
    spec = jl(j["spec_json"], {}) or {}
    try:
        mi = modcalls.info_for(j["module"], version)
    except KeyError:
        mi = modcalls.info(j["module"])
    datasets = list(jl(j["datasets_json"], []) or spec.get("datasets") or [])
    mounts = dict(spec.get("mounts") or {})
    inputs = {}
    for a in dep_artifacts or []:
        inputs[a["name"]] = {"dataset": a["dataset"], "mount": a["name"]}
        datasets.append(a["dataset"])
        mounts[a["dataset"]] = a["name"]
    res = resources if resources is not None else \
        modcalls.resources_on(jl(j["resources_json"], {}) or mi.stage_resources(j["stage"]), platform)
    return {"envelope": 1, "schema": f"{j['module']}/spec@{j['spec_version']}", "module_id": mi.manifest.module.id,
            "module_version": mi.version or mi.manifest.module.version, "job_key": j["job_key"], "stage": j["stage"],
            "protocol": 1, "datasets": datasets, "mounts": mounts, "platform": platform, "inputs": inputs, "resources": res,
            "timeout_s": spec.get("timeout_s") or mi.stage_timeout(j["stage"], platform),
            "payload": {k: v for k, v in spec.items() if k not in ENVELOPE_KEYS + HOST_KEYS}}


def claim(db: DB, node: dict, body: dict) -> dict:
    """Grant pending jobs whose module is certified here (or golden jobs of a doctor-passed module)
    and whose resources fit the node's free CPU and memory."""
    t = now()
    nid = node["node_id"]
    if not coordmove.accepting_leases(db):          # a coordinator move is draining or frozen: no new leases
        return {"grants": []}
    free_cpu = float(body.get("free_cpu") if body.get("free_cpu") is not None else body.get("free_slots") or 0)
    free_mem = float(body.get("free_mem_gb") if body.get("free_mem_gb") is not None else 1e9)
    offered = set(body.get("modules") or modcalls.enabled(db)) - modstore.disabled_names(db)
    from . import modsandbox
    offered -= modsandbox.node_excluded(db, node, offered)     # platform, OS version, sandbox or agent mismatch
    ready = set(body.get("ready_datasets") or [])
    grants = []
    if free_cpu <= 0 or node["desired_state"] != "active" or node["lifecycle"] != "ready":
        return {"grants": []}
    if db.get_setting("fleet_state", "active") != "active":       # fleet.pause / fleet.halt (D14)
        return {"grants": []}
    if node["release_id"] != releases.assigned(db, node):
        return {"grants": []}
    states = node_modules(node)
    certified = {m for m, st in states.items() if st.get("state") == "certified"} & offered
    certifying = {m for m, st in states.items() if st.get("state") == "certifying"} & offered
    if not certified and not certifying:
        return {"grants": []}
    with db.tx():
        # every node-level decision comes from a row read inside the transaction: the row auth read
        # may predate a quarantine, revoke or pause committed since (TLA+ finding F1)
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
        if node["desired_state"] != "active" or node["lifecycle"] != "ready":
            return {"grants": []}
        states = node_modules(node)
        certified = {m for m, st in states.items() if st.get("state") == "certified"} & offered
        certifying = {m for m, st in states.items() if st.get("state") == "certifying"} & offered
        if not certified and not certifying:
            return {"grants": []}
        nv = node_view_for_claim(db, node, offered, ready, free_cpu, free_mem, body)
        if not predicates.eligible(predicates.admission(nv, first_fail=True)):
            return {"grants": []}
        cands = db.q(
            "SELECT j.* FROM jobs j LEFT JOIN campaigns c ON c.campaign_id=j.campaign_id "
            "WHERE j.state='pending' AND j.not_before<=? AND (j.target_node IS NULL OR j.target_node=?) "
            "AND (j.depends_on IS NULL OR EXISTS (SELECT 1 FROM jobs d WHERE d.job_id=j.depends_on AND d.state='done')) "
            "AND (j.kind='golden' OR c.state='running' OR j.campaign_id IS NULL) "
            "AND (j.kind!='golden' OR j.target_node=?) "
            # walks the jobs_dispatch index instead of sorting every pending job (job priority already
            # includes the campaign's priority; bench/README.md bottleneck 2)
            "ORDER BY j.priority DESC, j.subpriority DESC, j.job_id ASC LIMIT 500", (t, nid, nid))
        per_campaign = {r["campaign_id"]: r["n"] for r in db.q(
            "SELECT j.campaign_id, COUNT(*) n FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
            "WHERE a.state='live' GROUP BY j.campaign_id")}
        weights = {r["campaign_id"]: r["weight"] or 1 for r in db.q("SELECT campaign_id, weight FROM campaigns WHERE state='running'")}
        bindings: dict = {}               # units and datasets read in this transaction; first claims bind into it (D33)
        cands.sort(key=lambda j: (-(j["priority"] or 0),
                                  per_campaign.get(j["campaign_id"], 0) / max(weights.get(j["campaign_id"], 1), 1e-6),
                                  -(j["subpriority"] or 0), j["job_id"]))
        for j in cands:
            if len(grants) >= nv.max_new or nv.free_cpu <= 0:
                break
            res = modcalls.resources_on(jl(j["resources_json"], {}) or {"cpu": 1, "mem_gb": 1.0}, node.get("platform"))
            arts_box = {}

            def dep_ok(j=j, arts_box=arts_box):
                dep = _dep_result(db, j)
                arts_box["arts"] = (jl(dep["result_json"], {}) or {}).get("artifacts") if dep else None
                return bool(arts_box["arts"])

            results = predicates.placement(
                _job_facts(db, j, bindings), nv, t, dep_done=True, campaign_state="running",
                other_can_take=lambda j=j: _other_node_can_take(db, j, nid), datasets=jl(j["datasets_json"], []),
                resources=res, dep_artifacts=dep_ok if j["depends_on"] else True, first_fail=True,
                gpu=modcalls.job_uses_gpu(j["module"], res, node.get("platform")))
            if not predicates.eligible(results):
                continue
            placement.bind_on_claim(db, j, node, bindings)
            need_cpu, need_mem = float(res.get("cpu", 1)), float(res.get("mem_gb", 1.0))
            ver = modstore.version_for_node(db, j["module"], nid)
            # the runner gets a SpecEnvelope: the module's payload plus what the stage reserves and its inputs
            spec = envelope(db, j, ver, res, arts_box.get("arts") if j["depends_on"] else None, platform=node.get("platform"))
            gen = nv.states.get(j["module"], {}).get("generation", 0)
            aid = db.x("INSERT INTO attempts(job_id,node_id,generation,release_id,cert_generation,state,granted_at,"
                       "expires_at,hard_deadline,phase,last_progress_at,module_version) VALUES(?,?,?,?,?,'live',?,?,?,'staging',?,?)",
                       (j["job_id"], nid, j["generation"], node["release_id"], gen, t,
                        t + C.LEASE_TTL, t + max(600, spec.get("timeout_s") or 1800), t, ver))
            db.x("UPDATE jobs SET state='leased' WHERE job_id=?", (j["job_id"],))
            db.x("INSERT OR IGNORE INTO attempt_phases VALUES(?, 'granted', ?)", (aid, t))
            nv.free_cpu -= need_cpu
            nv.free_mem -= need_mem
            for p, k in (res.get("pools") or {}).items():
                nv.pool_use[p] = nv.pool_use.get(p, 0) + int(k)
            nv.gpu_use += modcalls.job_uses_gpu(j["module"], res, node.get("platform"))
            per_campaign[j["campaign_id"]] = per_campaign.get(j["campaign_id"], 0) + 1
            grants.append({"attempt_id": aid, "job_id": j["job_id"], "job_key": j["job_key"],
                           "generation": j["generation"], "kind": j["kind"], "module": j["module"],
                           "issued_at": t, "expires_at": t + C.LEASE_TTL,
                           "hard_deadline": t + max(600, spec.get("timeout_s") or 1800), "spec": spec})
    for g in grants:
        db.event("granted", node_id=nid, job_id=g["job_id"], attempt_id=g["attempt_id"], reason=g["module"])
    return {"grants": grants}


# ---------------------------------------------------------------- attempt outcomes
def _end_attempt(db: DB, attempt_id: int, state: str, reason: str, count_failure: bool):
    a = db.one("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,))
    if not a:
        return None
    db.x("UPDATE attempts SET state=?, end_reason=?, ended_at=? WHERE attempt_id=?", (state, reason, now(), attempt_id))
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (a["job_id"],))
    if count_failure and j and j["kind"] == "golden":
        # a golden job only ever runs on one host, so the >=2-hosts job quarantine never applies; count
        # failures per (node, module) across golden sets instead (TLA+ review F6)
        st = node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (a["node_id"],))).get(j["module"], {})
        gf = int(st.get("golden_failures") or 0) + 1
        if gf >= C.MAX_GOLDEN_FAILURES:
            _golden_failed(db, a["node_id"], j["module"], gf, reason)
            return a
        _set_module_state(db, a["node_id"], j["module"], golden_failures=gf)
    if j and j["state"] == "leased":
        others = db.one("SELECT COUNT(*) n FROM attempts WHERE job_id=? AND state='live'", (j["job_id"],))["n"]
        if not others:
            if count_failure and not counts_against_job(reason):
                # the host's fault (a missing dependency, a wrong mode): placed elsewhere (FAILED_HERE), its retries untouched
                db.x("UPDATE jobs SET state='pending' WHERE job_id=?", (j["job_id"],))
            elif count_failure:
                fails = j["exec_failures"] + 1
                if j["kind"] != "golden" and not _retry_possible(db, {**j, "exec_failures": fails}):
                    # stages[].retry spent on every node that could run it (golden failures count per node: _golden_failed)
                    db.x("UPDATE jobs SET state='quarantined', exec_failures=? WHERE job_id=?", (fails, j["job_id"]))
                    db.event("job_quarantined", job_id=j["job_id"], campaign_id=j["campaign_id"], reason=reason)
                else:
                    backoff = min(600, 15 * 2 ** (fails - 1))
                    db.x("UPDATE jobs SET state='pending', exec_failures=?, not_before=? WHERE job_id=?",
                         (fails, now() + backoff, j["job_id"]))
            else:
                extra = ", expirations=expirations+1" if state == "expired" else ""
                db.x(f"UPDATE jobs SET state='pending'{extra} WHERE job_id=?", (j["job_id"],))
    return a


def counts_against_job(reason: str) -> bool:
    """Whether a failure with this end reason spends the job's retries: its reason code says (contracts/reason_codes.py,
    counts_against_job); a reason without a code (a runner's own) counts."""
    from ..contracts import reason_codes as RC
    rc = RC.REGISTRY.get(RC.WIRE.get(reason, ""))
    return rc is None or rc.counts_against_job is not False


def _retry_possible(db: DB, j: dict) -> bool:
    """Can any ready node certified for the job's module, able to run its stage, still try it: its stage's retry
    (stages[].retry.max_attempts, for that node's platform) above the job's failures."""
    f = _job_facts(db, j)
    res = jl(j["resources_json"], {})
    for n in db.q("SELECT node_id, platform, modules_json, capacity_json, policy_json FROM nodes WHERE lifecycle='ready'"
                  + (" AND node_id=?" if j["target_node"] else ""), (j["target_node"],) if j["target_node"] else ()):
        if (predicates.retry_max(f, n["platform"]) > j["exec_failures"] and predicates.platform_fits(f, n["platform"])
                and (jl(n["modules_json"], {}) or {}).get(j["module"], {}).get("state") == "certified" and _pools_fit(n, res)):
            return True
    return False


def release(db: DB, node: dict, attempt_id: int, reason: str) -> dict:
    with db.tx():
        a = db.one("SELECT * FROM attempts WHERE attempt_id=? AND node_id=?", (attempt_id, node["node_id"]))
        if not a or a["state"] != "live":
            return {"ok": True, "noop": True}
        _end_attempt(db, attempt_id, "released", reason, count_failure=reason not in NON_FAILURE_RELEASES)
    db.event("released", node_id=node["node_id"], attempt_id=attempt_id, job_id=a["job_id"], reason=reason)
    return {"ok": True}


def fail(db: DB, node: dict, attempt_id: int, body: dict) -> dict:
    """A failed attempt. `fault` comes from the runner's failure.json (runner protocol, "Exit codes"): `transient` is
    no failure at all (the attempt is released and the job retried), `host` implicates this node (re-doctor), `job`
    is the job's own fault (it never trips this node's breaker)."""
    fault = body.get("fault")
    if fault == "transient":
        return release(db, node, attempt_id, "transient")
    reason = body.get("reason") or "exit_nonzero"
    if fault == "host" and reason not in HOST_FAILURES:
        reason = "doctor"
    tripped = False
    with db.tx():
        a = db.one("SELECT * FROM attempts WHERE attempt_id=? AND node_id=?", (attempt_id, node["node_id"]))
        if not a or a["state"] not in ("live", "expired"):
            return {"ok": True, "noop": True}
        j = db.one("SELECT module FROM jobs WHERE job_id=?", (a["job_id"],))
        # a job that already failed on another host is the job's fault (e.g. a parameter combination
        # that crashes the tool), not this host's: it must not trip the breaker on healthy nodes
        job_fault = fault == "job" or (reason not in HOST_FAILURES and bool(db.one(
            "SELECT 1 FROM attempts WHERE job_id=? AND node_id!=? AND state='failed'", (a["job_id"], node["node_id"]))))
        _end_attempt(db, attempt_id, "failed", reason, count_failure=True)
        n = db.one("SELECT breaker_failures b FROM nodes WHERE node_id=?", (node["node_id"],))["b"] + (0 if job_fault else 1)
        db.x("UPDATE nodes SET breaker_failures=? WHERE node_id=?", (n, node["node_id"]))
        tripped = n >= C.BREAKER_K or reason in HOST_FAILURES
        mstate = node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node["node_id"],))).get(
            (j or {}).get("module"), {}).get("state")
        if mstate == "golden_failed":
            tripped = False       # already out of service with its own alert; re-doctor would restart the loop
            db.x("UPDATE nodes SET breaker_failures=0 WHERE node_id=?", (node["node_id"],))
        if tripped and j and j["module"]:
            # back to doctor for that module: revoke it (ending its other live attempts on this node,
            # found by the state machine) and ask the agent to re-run doctor
            _revoke_quiet(db, node["node_id"], j["module"], f"breaker: {reason}")
            db.x("UPDATE nodes SET want_doctor=1, breaker_failures=0 WHERE node_id=?", (node["node_id"],))
    db.event("attempt_failed", node_id=node["node_id"], attempt_id=attempt_id, job_id=a["job_id"],
             reason=reason + (" (job fault: failed on another host too)" if job_fault else ""),
             exit_code=body.get("exit_code"), stderr_tail=(body.get("stderr_tail") or "")[-2000:])
    if tripped:
        db.event("breaker_tripped", node_id=node["node_id"], reason=reason)
        _alert(db, "breaker", node["node_id"], f"{node['hostname']}: {n} failures (last: {reason}) -> re-doctor")
    return {"ok": True}


def _requeue_cache_dependents(db: DB, result_ids, except_job=None) -> int:
    """Jobs in other campaigns that reused a result through the result cache stand or fall with it: when
    the result stops being canonical (retry, dispute), they run again (found by the Hypothesis machine)."""
    n = 0
    for rid in result_ids:
        for dj in db.q("SELECT job_id FROM jobs WHERE canonical_result_id=? AND state='done' "
                       "AND job_id IS NOT ?", (rid, except_job)):
            db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL, "
                 "exec_failures=0, not_before=0 WHERE job_id=?", (dj["job_id"],))
            n += 1
    if n:
        reopen_campaigns(db)
    return n


def reopen_campaigns(db: DB):
    """A finished campaign whose jobs were requeued (dispute, conviction, retry) runs again: claim only
    serves running campaigns. The owning module sees the requeued jobs in its next tick."""
    db.x("UPDATE campaigns SET state='running', finished_at=NULL WHERE state='done' AND campaign_id IN "
         "(SELECT campaign_id FROM jobs WHERE state='pending' AND campaign_id IS NOT NULL)")


def _dispute_parties(j: dict) -> set:
    d = jl(j["dispute_json"], {}) or {}
    return set(d.get("nodes", [])) if d.get("results") else set()


CERTIFYING_GRACE_S = 1800.0


def _can_serve(st: dict) -> bool:
    """Will this module state be given non-golden work (soon)? Certified, or certifying recently: a node
    stuck certifying never is, so it must not keep a replica or a dispute waiting (TLA+ finding F5)."""
    if st.get("state") == "certified":
        return True
    return st.get("state") == "certifying" and now() - (st.get("certifying_since") or st.get("at") or 0) < CERTIFYING_GRACE_S


def _node_pools(node: dict):
    """Pools a node may be scheduled against: its report (none until its first heartbeat), except that pools provided
    only by services the owner disabled on the node are zero, whatever it reports (e.g. it can see a VM another agent
    on the same machine runs)."""
    cap = (jl(node.get("capacity_json"), {}) or {}).get("pools") or {}
    off = modcalls.pools_of_disabled(node_disabled_services(node))
    return {**cap, **{p: 0 for p in off}} if off else cap


def _pools_fit(node: dict, resources: dict | None) -> bool:
    """Could this node ever run a job with these resources? Its pools must hold what the job reserves or needs."""
    res = resources or {}
    if not (res.get("pools") or res.get("needs_pools")):
        return True
    cap = _node_pools(node)
    return all(int(cap.get(p, 0)) >= int(k) for p, k in (res.get("pools") or {}).items()) and \
        all(int(cap.get(p, 0)) > 0 for p in (res.get("needs_pools") or []))


def _eligible_nodes(db: DB, j: dict, exclude: set, cmp: dict | None = None) -> int:
    """Ready nodes that can serve the job's module (see _can_serve), fit its pools and run it where it may run
    (predicates.platform_fits: its stage, platforms, unit class and comparison class), outside `exclude`. `cmp`: the
    comparison class {scope, class} to use instead of the job's own dispute's (a replica about to be queued)."""
    res, f = jl(j["resources_json"], {}), _job_facts(db, j, cmp=cmp)
    return sum(1 for n in db.q("SELECT node_id, platform, modules_json, capacity_json, policy_json FROM nodes WHERE lifecycle='ready'")
               if n["node_id"] not in exclude and _can_serve((jl(n["modules_json"], {}) or {}).get(j["module"], {}))
               and _pools_fit(n, res) and predicates.platform_fits(f, n["platform"]))


def _scope_mix(module: str, version: str | None) -> str:
    """The mix a result compares within, from the module version that produced it (oarbank-sdk spec/manifest.md,
    `results.determinism_scope`: global, os, arch or platform; an unknown scope is the strictest)."""
    try:
        i = modcalls.info_for(module, version)
    except KeyError:
        try:
            i = modcalls.info(module)        # that version is no longer active: the current one decides
        except KeyError:
            return "any"
    return pf.scope_mix(i.manifest.results.determinism_scope)


def _cmp(*results: dict) -> dict | None:
    """The comparison class of results that are compared with each other: the strictest of their scopes, keyed by the
    first one's platform (results.platform: what it was produced on), or None when they compare globally."""
    mix = "any"
    for r in results:
        mix = pf.stricter(mix, _scope_mix(r["module"], r["module_version"]))
    if mix == "any" or not results[0]["platform"]:
        return None
    return {"scope": mix, "class": pf.class_key(results[0]["platform"], mix)}


def _comparable(a: dict, b: dict) -> bool:
    c = _cmp(a, b)
    return c is None or (bool(b["platform"]) and pf.class_key(b["platform"], c["scope"]) == c["class"])


def _register_artifacts(db: DB, res: dict, module: str | None = None) -> str | None:
    """Artifacts a call stage uploaded (PUT /v1/artifacts/<sha256>) become content-addressed datasets
    `art:<digest>` owned by the job's module; the result records each dataset id for the score stage. None, or a
    rejection reason."""
    for a in res["artifacts"]:
        files = a.get("files") or []
        if not a.get("name") or not files:
            return "bad_artifact"
        for f in files:
            if not db.one("SELECT 1 FROM blobs WHERE digest=?", (f.get("digest"),)):
                return "artifact_missing"
        did = "art:" + sha256_hex(json.dumps([module or ""] + sorted((f["path"], f["digest"]) for f in files)))[:24]
        db.x("INSERT OR IGNORE INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
             (did, "artifact", module, json.dumps({"name": a["name"]}),
              json.dumps([{"path": f["path"], "digest": f["digest"], "size": f.get("size"), "origins": []} for f in files]), now()))
        a["dataset"] = did
    return None


def _maybe_replicate(db: DB, j: dict, node_id: str, cmp: dict | None):
    """Adaptive replication: re-run a deterministic sample of completed jobs on a different node,
    so a silently wrong node is caught statistically (a mismatch opens a quorum dispute)."""
    rate = float(db.get_setting("replica_rate", 0.03))
    if rate <= 0 or int(j["job_key"][:8], 16) / 0xFFFFFFFF >= rate:
        return
    if db.one("SELECT 1 FROM jobs WHERE kind='replica' AND job_key=?", (j["job_key"] + ":replica",)):
        return
    if not _eligible_nodes(db, j, {node_id}, cmp or {}):
        return                # nobody else could run it: it would sit pending forever (TLA+ finding F3)
    # a replica stays in its original's unit of work (D33) and compares within the original's class
    db.x("INSERT INTO jobs(job_key,dataset_id,kind,priority,state,spec_json,datasets_json,created_at,module,resources_json,"
         "dispute_json,name,stage,spec_version,placement_unit,platforms_json,group_key) "
         "VALUES(?,?,'replica',?,'pending',?,?,?,?,?,?,?,?,?,?,?,?)",
         (j["job_key"] + ":replica", j["dataset_id"], (j["priority"] or 0) - 1, j["spec_json"],
          j["datasets_json"], now(), j["module"], j["resources_json"],
          json.dumps({"nodes": [node_id], "replica_of": j["job_id"], **(cmp or {})}),
          f"replica of {j['job_id']}", j["stage"], j["spec_version"], j["placement_unit"], j["platforms_json"], j["group_key"]))
    db.event("replica_queued", job_id=j["job_id"], node_id=node_id)


def _check_replica(db: DB, rj: dict, rid: int, node_id: str, digest, value, post: list):
    """A replica finished: compare with the original job's canonical result; disagree -> dispute."""
    orig_id = (jl(rj["dispute_json"], {}) or {}).get("replica_of")
    oj = db.one("SELECT * FROM jobs WHERE job_id=?", (orig_id,)) if orig_id else None
    if not oj or oj["state"] != "done" or not oj["canonical_result_id"]:
        return
    can = db.one("SELECT * FROM results WHERE result_id=?", (oj["canonical_result_id"],))
    if not _differs(oj, can, value, digest):
        db.event("replica_match", job_id=oj["job_id"], node_id=node_id)
        return
    db.x("UPDATE results SET canonical=0, accepted=0, reason='disputed' WHERE result_id=?", (can["result_id"],))
    _requeue_cache_dependents(db, [can["result_id"]], oj["job_id"])
    _requeue_dependents(db, oj["job_id"], "replica disagrees with the call result")
    rd = jl(rj["dispute_json"], {}) or {}
    db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL, dispute_json=? "
         "WHERE job_id=?", (json.dumps({"nodes": [can["node_id"], node_id], "results": [can["result_id"], rid],
                                        **{k: rd[k] for k in ("scope", "class") if rd.get(k)}}), oj["job_id"]))
    post.append(lambda: _alert(db, f"dispute:{oj['job_id']}", node_id,
                               f"replica of job {oj['job_id']} disagrees with the canonical result; tie-break queued"))


def invalidate_node_results(db: DB, node_id: str, reason: str):
    """A node convicted of nondeterminism: every canonical result it produced is recomputed elsewhere."""
    rows = db.q("SELECT j.job_id FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.state='done' AND j.kind IN ('eval','call') AND r.node_id=?", (node_id,))
    for r_ in rows:
        db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL, "
             "exec_failures=0, not_before=0 WHERE job_id=?", (r_["job_id"],))
        db.x("UPDATE results SET canonical=0 WHERE job_id=?", (r_["job_id"],))
        _requeue_dependents(db, r_["job_id"], f"call result invalidated: {reason}")
    reopen_campaigns(db)
    db.event("results_invalidated", node_id=node_id, reason=f"{len(rows)} jobs requeued: {reason}")
    return len(rows)


def _differs(job, prior: dict, value, d_new) -> bool:
    """Do two results for the same job disagree? The module's digests decide when both exist (a measured
    value, e.g. a benchmark's throughput, may differ between honest runs); otherwise the values to 6 dp.
    d_new: the module's digest of the new result (from result.evaluate)."""
    if prior["digest"] and d_new:
        return prior["digest"] != d_new
    return prior["value"] is not None and value is not None and f"{prior['value']:.6f}" != f"{value:.6f}"


@dataclass
class _Evaluation:
    """The module's verdict on one completion, obtained before the write transaction."""
    job_id: int
    dep_result_id: int | None       # the call result a score stage was merged with (None: none/not staged)
    result: dict                    # what is stored: the merged result for score stages
    ok: bool
    reason: str
    value: float | None
    digest: str | None
    digest_version: int | None
    fields: dict
    golden_ok: bool | None


def _pre_evaluate(db: DB, attempt_id: int, res: dict) -> "_Evaluation | None":
    """Ask the module about a completion outside the DB lock. The verdict is a pure function of
    (module, spec, result, dependency result), so it stays valid unless the dependency changed, which the
    transaction re-checks. Raises ModuleUnavailable / ModuleError (module faults)."""
    a = db.one("SELECT a.job_id, a.module_version, n.platform FROM attempts a LEFT JOIN nodes n ON n.node_id=a.node_id "
               "WHERE a.attempt_id=?", (attempt_id,))
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (a["job_id"],)) if a else None
    if not j:
        return None
    # judged by the version that ran it (still active), else by the current version
    ver = a["module_version"] if a["module_version"] and (j["module"], a["module_version"]) in modcalls.VERSIONS else None
    dep_id, merged, arts = None, res, None
    dep = _dep_result(db, j) if j["depends_on"] else None
    if dep:
        dep_id = dep["result_id"]
        dres = jl(dep["result_json"], {}) or {}
        arts = dres.get("artifacts")
        head = modcalls.info_for(j["module"], ver).chain
        merged = modcalls.merge(db, j["module"], {head[0] if head else "head": dres, j["stage"]: res}, ver)
    spec = envelope(db, j, ver, None, arts, platform=a["platform"])
    v = modcalls.evaluate(db, j["module"], spec, merged, j["stage"], ver)
    gok = None
    if j["kind"] == "golden":
        gok = modcalls.golden_ok(db, j["module"], (jl(j["spec_json"], {}) or {}).get("expected") or {}, merged, v.digest, ver)
    return _Evaluation(j["job_id"], dep_id, merged, v.ok, v.reason, v.value, v.digest, v.digest_version, v.fields, gok)


def _await_module(db: DB, attempt_id: int, e: Exception):
    """A completion arrived while its module cannot evaluate it: keep the attempt's lease (and exempt it
    from the hard deadline) so the agent's outbox can redeliver it; charge nothing to anyone (S15)."""
    t = now()
    with db.tx():
        db.x("UPDATE attempts SET phase='awaiting_module', expires_at=MAX(expires_at, ?) WHERE attempt_id=? "
             "AND state IN ('live','expired')", (t + AWAIT_MODULE_TTL, attempt_id))
        db.event("module_fault", attempt_id=attempt_id, reason=str(e)[:300])
    retry = getattr(e, "retry_after", 5.0)
    raise ApiError(503, "module_unavailable", str(e)[:300], headers={"Retry-After": str(max(1, int(retry)))})


def complete(db: DB, node: dict, attempt_id: int, body: dict) -> dict:
    ik = body.get("idempotency_key") or f"att-{attempt_id}-complete"
    res = body.get("result") or {}
    post = []
    prev = db.one("SELECT response_json FROM idempotency WHERE key=?", (ik,))    # cheap optimistic check
    if prev:
        return json.loads(prev["response_json"])
    t_received = now()
    if db.one("SELECT 1 FROM results WHERE attempt_id=?", (attempt_id,)) is None:
        try:
            ev = _pre_evaluate(db, attempt_id, res)
        except (ModuleUnavailable, ModuleError) as e:
            _await_module(db, attempt_id, e)
    else:
        ev = None                      # a duplicate: answered from the stored row below
    with db.tx():
        # idempotency check, fencing, acceptance, revocation/quarantine and the stored response all
        # commit atomically: a crash can never leave a half-applied completion behind.
        prev = db.one("SELECT response_json FROM idempotency WHERE key=?", (ik,))
        if prev:
            return json.loads(prev["response_json"])
        # one result per attempt: a re-report under a different key gets the original verdict
        # (found by the Hypothesis state machine: it used to crash on the UNIQUE constraint)
        dup = db.one("SELECT accepted, canonical, reason FROM results WHERE attempt_id=?", (attempt_id,))
        if dup:
            return {"accepted": bool(dup["accepted"]), "canonical": bool(dup["canonical"]),
                    "reason": dup["reason"], "duplicate": True}
        a = db.one("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,))
        if not a or a["node_id"] != node["node_id"]:
            raise ApiError(404, "lease_lost", str(attempt_id))
        j = db.one("SELECT * FROM jobs WHERE job_id=?", (a["job_id"],))
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
        spec = jl(j["spec_json"], {})
        mstate = node_modules(node).get(j["module"], {})
        reason, accepted, canonical = "ok", 1, 0
        if j["stage"]:
            spec["stage"] = j["stage"]
        stage_problem = None
        dep = _dep_result(db, j) if j["depends_on"] else None
        if ev is None or ev.job_id != j["job_id"] or ev.dep_result_id != (dep["result_id"] if dep else None):
            # the dependency changed between evaluation and commit (a demoted call): evaluate again
            raise ApiError(503, "reevaluate", "the stage input changed during evaluation", headers={"Retry-After": "1"})
        if j["depends_on"]:
            # a tail-stage result stands on its head's result: same input, merged into one canonical result
            if not dep:
                stage_problem = "input_missing"
            elif ev.digest and dep["digest"] and ev.digest != dep["digest"]:
                stage_problem = "input_mismatch"
            res = ev.result
        elif res.get("artifacts") is not None:
            stage_problem = _register_artifacts(db, res, j["module"])
        ok, why = ev.ok, ev.reason
        if stage_problem:
            ok, why = False, stage_problem
        if a["state"] not in ("live", "expired"):
            # failed / released / revoked attempts are closed; only a live or merely expired (e.g. slept)
            # attempt may deliver a result (found by the Hypothesis state machine)
            reason, accepted = "attempt_closed", 0
        elif j["state"] in ("cancelled", "quarantined"):
            # a settled job is not revived by a late result (TLA+ finding F2, stranded-dispute case)
            reason, accepted = {"cancelled": "job_cancelled", "quarantined": "job_quarantined"}[j["state"]], 0
        elif node["node_id"] in _dispute_parties(j):
            # a party to the job's dispute never casts the tie-break vote (TLA+ finding F2)
            reason, accepted = "dispute_party", 0
        elif node["lifecycle"] in ("quarantined", "retired"):
            # a late result from a node convicted in the meantime (e.g. it slept through the verdict)
            reason, accepted = {"quarantined": "node_quarantined", "retired": "node_retired"}[node["lifecycle"]], 0
        elif a["generation"] != j["generation"]:
            reason, accepted = "stale_generation", 0
        elif j["kind"] != "golden" and a["cert_generation"] != mstate.get("generation"):
            reason, accepted = "release_invalid", 0
        elif not ok:
            reason, accepted = why, 0
        value = ev.value if accepted else None
        db.x("INSERT OR IGNORE INTO attempt_phases VALUES(?, 'completion_received', ?)", (attempt_id, t_received))
        db.x("INSERT OR IGNORE INTO attempt_phases VALUES(?, 'verdict', ?)", (attempt_id, now()))
        # comparisons use what the result was produced on and by, not the node's or catalog's state at comparison time
        mine = {"node_id": node["node_id"], "platform": node.get("platform"), "module": j["module"],
                "module_version": a.get("module_version") or modcalls.version_of(j["module"])}
        rid = db.x("INSERT INTO results(job_key,job_id,attempt_id,node_id,accepted,canonical,reason,at,module,module_version,"
                   "value,digest,digest_version,fields_json,result_json,platform) VALUES(?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?)",
                   (j["job_key"], j["job_id"], attempt_id, node["node_id"], accepted, reason, now(), j["module"],
                    mine["module_version"], value, ev.digest, ev.digest_version, json.dumps(ev.fields), json.dumps(res), mine["platform"]))
        if accepted and j["kind"] == "golden" and j["state"] == "done":
            # a second late golden result (both attempts expired, both reported): the job is settled
            reason, accepted = "job_done", 0
            db.x("UPDATE results SET accepted=0, reason=? WHERE result_id=?", (reason, rid))
        elif accepted and j["kind"] == "golden":
            exp = spec.get("expected") or {}
            if not ev.golden_ok:
                reason, accepted = "golden_mismatch", 0
                db.x("UPDATE results SET accepted=0, reason=? WHERE result_id=?", (reason, rid))
                db.x("UPDATE jobs SET state='done', done_at=?, canonical_result_id=? WHERE job_id=?", (now(), rid, j["job_id"]))
                _end_attempt(db, attempt_id, "completed", "golden_mismatch", count_failure=False)
                got = {k: res.get(k) for k in exp}
                post.append(lambda: revoke_module(db, node["node_id"], j["module"],
                                                  f"golden {j['name']} mismatch: got {got}, want {exp}"))
            else:
                canonical = 1
        elif accepted and j["state"] == "done":
            can = db.one("SELECT * FROM results WHERE result_id=?", (j["canonical_result_id"],))
            accepted, reason = 0, "job_done"
            db.x("UPDATE results SET accepted=0, reason=? WHERE result_id=?", (reason, rid))
            if can and can["node_id"] == node["node_id"] and _differs(j, can, value, ev.digest):
                # the same node gave two different answers for one job: it convicts itself
                reason = "self_inconsistent"
                db.x("UPDATE results SET reason=? WHERE result_id=?", (reason, rid))
                post.append(lambda: quarantine(db, node["node_id"],
                                               f"nondeterminism: two different results for job {j['job_id']}"))
            elif can and not _comparable(can, mine):
                db.event("replica_other_platform", node_id=node["node_id"], job_id=j["job_id"])   # not comparable
            elif can and _differs(j, can, value, ev.digest):
                # Replicas disagree. Don't blame whoever reported later: trust neither, exclude both
                # nodes and requeue for a tie-break on a third node (BOINC-style quorum).
                reason = "disputed"
                db.x("UPDATE results SET canonical=0, accepted=0, reason='disputed' WHERE result_id IN (?,?)",
                     (can["result_id"], rid))
                _requeue_cache_dependents(db, [can["result_id"]], j["job_id"])
                _requeue_dependents(db, j["job_id"], "call result disputed")
                # the generation bump fences every outstanding attempt, e.g. a party's older duplicate (F2)
                db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL, "
                     "dispute_json=? WHERE job_id=?", (json.dumps({"nodes": [can["node_id"], node["node_id"]],
                                                     "results": [can["result_id"], rid],
                                                     **(_cmp(mine, can) or {})}),
                                                     j["job_id"]))
                post.append(lambda: _alert(db, f"dispute:{j['job_id']}", node["node_id"],
                                           f"job {j['job_id']} ({j['module']}): replicas disagree; tie-break queued"))
            else:
                db.event("replica_match", node_id=node["node_id"], job_id=j["job_id"])
        elif accepted:
            canonical = 1
        if canonical and (jl(j["dispute_json"], {}) or {}).get("results"):
            d = jl(j["dispute_json"], {})
            rows = [db.one("SELECT * FROM results WHERE result_id=?", (r_,)) for r_ in d.get("results", [])]
            agree = [r_ for r_ in rows if r_ and not _differs(j, r_, value, ev.digest)]
            disagree = [r_ for r_ in rows if r_ and _differs(j, r_, value, ev.digest)]
            if agree:
                # majority found: the disagreeing node(s) produced the wrong answer
                for r_ in disagree:
                    post.append(lambda nid_=r_["node_id"]: quarantine(db, nid_, f"nondeterminism: outvoted on job {j['job_id']}"))
                db.x("UPDATE jobs SET dispute_json=NULL WHERE job_id=?", (j["job_id"],))
                db.event("dispute_resolved", job_id=j["job_id"], node_id=node["node_id"],
                         reason=f"agrees with {[r_['node_id'] for r_ in agree]}, outvoted {[r_['node_id'] for r_ in disagree]}")
            else:
                # three-way disagreement: widen the dispute and ask yet another node
                canonical, accepted, reason = 0, 0, "disputed"
                db.x("UPDATE results SET accepted=0, reason='disputed' WHERE result_id=?", (rid,))
                d["nodes"].append(node["node_id"])
                d["results"].append(rid)
                ready_nodes = db.one("SELECT COUNT(*) n FROM nodes WHERE lifecycle='ready'")["n"]
                if len(set(d["nodes"])) >= ready_nodes:
                    db.x("UPDATE jobs SET state='quarantined', dispute_json=? WHERE job_id=?", (json.dumps(d), j["job_id"]))
                    db.event("job_quarantined", job_id=j["job_id"], reason="no replica majority")
                else:
                    db.x("UPDATE jobs SET dispute_json=? WHERE job_id=?", (json.dumps(d), j["job_id"]))
                if a["state"] == "live":
                    _end_attempt(db, attempt_id, "completed", "disputed", count_failure=False)
                if len(set(d["nodes"])) >= ready_nodes:
                    for o in db.q("SELECT attempt_id, node_id FROM attempts WHERE job_id=? AND state='live'", (j["job_id"],)):
                        db.x("UPDATE attempts SET state='revoked', end_reason='job_quarantined', ended_at=? WHERE attempt_id=?",
                             (now(), o["attempt_id"]))
                        _push(db, o["node_id"], "revoke", o["attempt_id"])
                else:
                    # still leased while another attempt runs; pending only when nothing else is live (S5)
                    still = db.one("SELECT COUNT(*) n FROM attempts WHERE job_id=? AND state='live'", (j["job_id"],))["n"]
                    db.x("UPDATE jobs SET state=? WHERE job_id=?", ("leased" if still else "pending", j["job_id"]))
        if canonical:
            db.x("UPDATE results SET canonical=1 WHERE result_id=?", (rid,))
            db.x("UPDATE jobs SET state='done', done_at=?, canonical_result_id=? WHERE job_id=?", (now(), rid, j["job_id"]))
            db.x("UPDATE attempts SET state='completed', end_reason='ok', ended_at=? WHERE attempt_id=?", (now(), attempt_id))
            for o in db.q("SELECT attempt_id, node_id FROM attempts WHERE job_id=? AND state='live' AND attempt_id!=?",
                          (j["job_id"], attempt_id)):
                db.x("UPDATE attempts SET state='revoked', end_reason='lost_race', ended_at=? WHERE attempt_id=?",
                     (now(), o["attempt_id"]))
                _push(db, o["node_id"], "revoke", o["attempt_id"])
            db.x("UPDATE nodes SET breaker_failures=0 WHERE node_id=?", (node["node_id"],))
            placement.harden(db, j["placement_unit"], mine["platform"])        # the unit's first result fixes its class (D33)
            if j["kind"] == "call" or (j["kind"] == "eval" and not j["depends_on"]):
                _maybe_replicate(db, j, node["node_id"], _cmp(mine))
            elif j["kind"] == "replica":
                _check_replica(db, j, rid, node["node_id"], ev.digest, value, post)
        elif a["state"] == "live":
            # a wrong-mode run implicates the host: it is a failed attempt (consistent with exec_failures)
            host_fault = reason in ("mode_mismatch",)
            _end_attempt(db, attempt_id, "failed" if host_fault else "completed", reason, count_failure=host_fault)
        for fn in post:
            fn()
        if j["kind"] == "golden" and reason == "ok":
            _golden_done(db, node["node_id"], j["module"])
        db.event("completed", node_id=node["node_id"], attempt_id=attempt_id, job_id=j["job_id"], campaign_id=j["campaign_id"],
                 reason=reason, module=j["module"], value=value)
        resp = {"accepted": bool(accepted), "canonical": bool(canonical), "reason": reason}
        db.x("INSERT OR REPLACE INTO idempotency VALUES(?,?,?)", (ik, json.dumps(resp), now()))
    return resp


def append_log(attempt_id: int, node: dict, db: DB, text: bytes):
    a = db.one("SELECT node_id FROM attempts WHERE attempt_id=?", (attempt_id,))
    if not a or a["node_id"] != node["node_id"]:
        raise ApiError(404, "lease_lost", str(attempt_id))
    C.ATTEMPT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(C.ATTEMPT_LOG_DIR / f"{attempt_id}.log", "ab") as f:
        f.write(text[-65536:])


# ---------------------------------------------------------------- reaper + alerts
def _stranded_disputes(db: DB) -> list[dict]:
    """Pending disputed jobs that no node can ever tie-break: every ready node that is certified (or
    certifying) for the module is already party to the dispute. Waiting would never settle them."""
    out = []
    for j in db.q("SELECT * FROM jobs WHERE state='pending' AND dispute_json IS NOT NULL"):
        d = jl(j["dispute_json"], {}) or {}
        if not d.get("results"):
            continue
        if not _eligible_nodes(db, j, set(d.get("nodes", []))):
            out.append(j)
    return out


def reap(db: DB):
    t = now()
    if (db.get_setting("reaper_grace_until") or 0) > t:
        return                                  # just took over in a move: agents are still re-pointing to us
    with db.tx():
        for a in db.q("SELECT * FROM attempts WHERE state='live' AND expires_at<?", (t,)):
            _end_attempt(db, a["attempt_id"], "expired", "lease_expired", count_failure=False)
            db.event("expired", node_id=a["node_id"], attempt_id=a["attempt_id"], job_id=a["job_id"])
        for a in db.q("SELECT * FROM attempts WHERE state='live' AND hard_deadline<? "
                      "AND COALESCE(phase,'')!='awaiting_module'", (t,)):
            _end_attempt(db, a["attempt_id"], "killed", "timeout", count_failure=True)
            _push(db, a["node_id"], "revoke", a["attempt_id"])
            db.event("timeout", node_id=a["node_id"], attempt_id=a["attempt_id"], job_id=a["job_id"])
        for rj in db.q("SELECT * FROM jobs WHERE kind='replica' AND state='pending'"):
            rd = jl(rj["dispute_json"], {}) or {}
            if not _eligible_nodes(db, rj, set(rd.get("nodes", []))):
                db.x("UPDATE jobs SET state='cancelled', generation=generation+1 WHERE job_id=?", (rj["job_id"],))
                db.event("replica_dropped", job_id=rj["job_id"], reason="no other eligible node")
        # a score job whose call can never finish (cancelled / quarantined) settles the same way (liveness)
        for dj in db.q("SELECT j.job_id, j.campaign_id, d.state dstate FROM jobs j JOIN jobs d ON d.job_id=j.depends_on "
                       "WHERE j.state='pending' AND d.state IN ('cancelled','quarantined')"):
            db.x("UPDATE jobs SET state=?, generation=generation+1 WHERE job_id=? AND state='pending'", (dj["dstate"], dj["job_id"]))
            db.event("job_" + dj["dstate"], job_id=dj["job_id"], campaign_id=dj["campaign_id"], reason=f"its call job was {dj['dstate']}")
        stranded = _stranded_disputes(db)
        for j in stranded:
            db.x("UPDATE jobs SET state='quarantined' WHERE job_id=? AND state='pending'", (j["job_id"],))
            db.event("job_quarantined", job_id=j["job_id"], campaign_id=j["campaign_id"],
                     reason="replicas disagree and no uninvolved node can break the tie")
        placed = placement.reap(db)
    for n in db.q("SELECT node_id, hostname, modules_json, capacity_json FROM nodes WHERE lifecycle='ready'"):
        if not (jl(n["capacity_json"], {}) or {}).get("admit", True):
            continue          # yielding (user present, a protected app, schedule): not claiming, not stuck
        for mname, st in (jl(n["modules_json"], {}) or {}).items():
            if st.get("state") == "certifying" and not _can_serve(st):
                # goldens that never finish (e.g. the Mac sleeps through every run) no longer block work (F5),
                # but the operator must hear about it (TLA+ review follow-up)
                _alert(db, f"certifying_stuck:{mname}", n["node_id"],
                       f"{n['hostname']}: {mname} has been certifying for over {int(CERTIFYING_GRACE_S // 60)} min")
    run_pending_goldens(db)             # backstop: golden sets whose fetch failed or was interrupted
    for raise_, rule, subject, detail in placed:
        if raise_:
            _alert(db, rule, subject, detail, priority="high" if rule.startswith("placement_stranded") else "default")
        else:
            _resolve_alert(db, rule, subject)
    for j in stranded:
        _alert(db, f"dispute:{j['job_id']}", f"job:{j['job_id']}", f"job {j['job_id']} ({j['module']}): replicas disagree and no third "
               "node is available to break the tie; quarantined (retry it once another node is certified)")
    for n in db.q("SELECT * FROM nodes WHERE lifecycle NOT IN ('retired')"):
        hb = n["last_heartbeat_at"] or 0
        if hb and t - hb > C.OFFLINE_ALERT_AFTER:          # a sleeping Mac comes back within minutes (alerting.py)
            _alert(db, "node_offline", n["node_id"], f"{n['hostname']} offline for {int((t - hb) / 60)} min")
        elif hb and t - hb < C.OFFLINE_AFTER:
            _resolve_alert(db, "node_offline", n["node_id"])
    from . import alerting, protection
    protection.check_alerts(db, t)
    alerting.promote_pending(db, t)


def _alert(db: DB, rule: str, subject: str, detail: str, priority="default"):
    """Open an alert under its rule's policy (coordinator/alerting.py): a rule with a pending period records the
    alert as pending and notifies only if it outlives it; repeated trips of one rule on one subject open a
    single `<rule>:flapping` alert instead of a stack of notifications."""
    from . import alerting, notify
    ex = db.one("SELECT * FROM alerts WHERE rule=? AND subject=? AND state IN ('open','pending')", (rule, subject))
    if ex:
        return
    pol, t = alerting.policy(rule), now()
    flap = pol.get("flap")
    if flap and alerting.trips(db, rule, subject, flap[1], t) + 1 >= flap[0]:
        frule = f"{rule}:flapping"
        db.x("INSERT INTO alerts(rule,subject,state,detail,opened_at,resolved_at,resolved_how) VALUES(?,?,'dismissed',?,?,?,?)",
             (rule, subject, detail, t, t, "collapsed into flapping"))
        if not db.one("SELECT 1 FROM alerts WHERE rule=? AND subject=? AND state='open'", (frule, subject)):
            n = alerting.trips(db, rule, subject, flap[1], t)
            fdetail = f"{detail} — {n} times in the last {int(flap[1] // 60)} min"
            db.x("INSERT INTO alerts(rule,subject,state,detail,opened_at,last_notified_at) VALUES(?,?,'open',?,?,?)",
                 (frule, subject, fdetail, t, t))
            db.event("alert_opened", reason=frule, node_id=subject if subject.startswith("n_") else None, detail=fdetail)
            notify.send(db, title=f"Oarbank: {frule}", message=fdetail, priority=priority)
        return
    if pol["pending_s"] > 0:
        db.x("INSERT INTO alerts(rule,subject,state,detail,opened_at) VALUES(?,?,'pending',?,?)", (rule, subject, detail, t))
        return
    db.x("INSERT INTO alerts(rule,subject,state,detail,opened_at,last_notified_at) VALUES(?,?,'open',?,?,?)",
         (rule, subject, detail, t, t))
    db.event("alert_opened", reason=rule, node_id=subject if subject.startswith("n_") else None, detail=detail)
    notify.send(db, title=f"Oarbank: {rule}", message=detail, priority=priority)


def _resolve_alert(db: DB, rule: str, subject: str):
    ex = db.one("SELECT * FROM alerts WHERE rule=? AND subject=? AND state IN ('open','pending')", (rule, subject))
    if not ex:
        return
    if ex["state"] == "pending":                   # cleared within its pending period: never notified
        db.x("UPDATE alerts SET state='dismissed', resolved_at=?, resolved_how='cleared while pending' WHERE alert_id=?",
             (now(), ex["alert_id"]))
        return
    db.x("UPDATE alerts SET state='resolved', resolved_at=?, resolved_how=COALESCE(resolved_how,'auto') WHERE alert_id=?",
         (now(), ex["alert_id"]))
    db.event("alert_resolved", reason=rule, detail=ex["detail"])


# ---------------------------------------------------------------- user controls
def set_campaign_state(db: DB, campaign_id: str, action: str, actor: str):
    """pause | resume | cancel (cancel also cancels the campaign's pending and leased jobs). Which states take which
    operation is the registry's (operations.CAMPAIGN_OPS), checked by the operation handlers."""
    if action not in ("pause", "resume", "cancel"):
        raise ApiError(400, "bad_action", action)
    c = db.one("SELECT state FROM campaigns WHERE campaign_id=?", (campaign_id,))
    if not c:
        raise ApiError(404, "not_found", campaign_id)
    with db.tx():
        db.x("UPDATE campaigns SET state=?, finished_at=? WHERE campaign_id=?",
             ({"pause": "paused", "resume": "running", "cancel": "cancelled"}[action], now() if action == "cancel" else None, campaign_id))
        if action == "cancel":
            for j in db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('pending','leased')", (campaign_id,)):
                cancel_job(db, j["job_id"], actor)
        db.event("campaign_" + action, actor=actor, campaign_id=campaign_id)


def set_node_state(db: DB, node_id: str, desired: str, actor: str):
    if desired not in ("active", "paused", "draining"):
        raise ApiError(400, "bad_state", desired)
    db.x("UPDATE nodes SET desired_state=? WHERE node_id=?", (desired, node_id))
    db.event("node_state", actor=actor, node_id=node_id, reason=desired)


def set_limits(db: DB, node_id: str, patch: dict, actor: str, clear_all=False) -> dict:
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node_id,))
    if not node:
        raise ApiError(404, "not_found", node_id)
    old = jl(node["limits_json"], {})
    new = {} if clear_all else dict(old)
    facts = jl(node["facts_json"], {})
    for k, v in (patch or {}).items():
        if k == "enforce":
            if v not in ("soft", "hard"):
                raise ApiError(400, "bad_enforce", v)
            new[k] = v
            continue
        if k not in C.LIMIT_KEYS:
            raise ApiError(400, "unknown_limit", k)
        if v is None or v == "":
            new.pop(k, None)
            continue
        if k == "schedule":
            new[k] = v
            continue
        v = float(v)
        if v <= 0:
            raise ApiError(400, "bad_limit", f"{k} must be > 0")
        cores, ram = platforms.cores(facts), platforms.memory_gb(facts)
        if k == "cpu_cores" and cores and v > cores:
            raise ApiError(400, "over_hardware", f"cpu_cores {v} > {cores} cores")
        if k in ("mem_gb", "vm_mem_gb") and ram and v > ram:
            raise ApiError(400, "over_hardware", f"{k} {v} > {ram:g} GB RAM")
        new[k] = int(v) if k in ("cpu_cores", "jobs", "vm_cpus") else v
    if [k for k in new if k != "enforce"] == []:
        new.pop("enforce", None)
    db.x("UPDATE nodes SET limits_json=? WHERE node_id=?", (json.dumps(new), node_id))
    db.event("limits_changed", actor=actor, node_id=node_id, old=old, new=new)
    return new


def set_policy(db: DB, node_id: str, patch: dict, actor: str, reason: str | None = None, source: str = "set_policy") -> dict:
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node_id,))
    pol = jl(node["policy_json"], {})
    for k, v in patch.items():
        if k not in C.DEFAULT_POLICY:
            raise ApiError(400, "unknown_policy", k)
        if k == "protection":
            from ..contracts import protection as P
            try:
                P.ProtectionConfig.model_validate(v)
            except ValueError as e:
                raise ApiError(422, "bad_protection", str(e)[:500])
        pol[k] = v
    if "protection" in patch:
        from . import protection
        protection.record_version(db, node_id, patch["protection"], actor, reason, source)
    old_disabled = set(node_disabled_services(node))
    db.x("UPDATE nodes SET policy_json=? WHERE node_id=?", (json.dumps(pol), node_id))
    db.event("policy_changed", actor=actor, node_id=node_id, patch=patch)
    if "disabled_services" in patch and set(pol.get("disabled_services") or []) != old_disabled:
        # the node's role changed (a service on or off): doctor checks and golden proof may differ, so every
        # module is re-doctored and re-certified under the new role
        for m in node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (node_id,))):
            _revoke_quiet(db, node_id, m, f"disabled_services -> {sorted(pol.get('disabled_services') or [])}")
        db.x("UPDATE nodes SET want_doctor=1 WHERE node_id=?", (node_id,))
    return pol


def retry_job(db: DB, job_id: int, actor: str):
    """Re-run a finished job as a new generation: the old canonical result is demoted, so there is
    never more than one canonical result per job."""
    with db.tx():
        own = [r["result_id"] for r in db.q("SELECT result_id FROM results WHERE job_id=? AND canonical=1", (job_id,))]
        n = db.x("UPDATE jobs SET state='pending', generation=generation+1, exec_failures=0, not_before=0, "
                 "canonical_result_id=NULL, done_at=NULL WHERE job_id=? AND state IN ('failed','quarantined','cancelled','done')",
                 (job_id,))
        db.x("UPDATE results SET canonical=0 WHERE job_id=?", (job_id,))
        _requeue_cache_dependents(db, own, job_id)
        _requeue_dependents(db, job_id, "call retried")
    db.event("job_retry", actor=actor, job_id=job_id)


def cancel_job(db: DB, job_id: int, actor: str):
    with db.tx():
        db.x("UPDATE jobs SET state='cancelled', generation=generation+1 WHERE job_id=? AND state IN ('pending','leased')",
             (job_id,))
        for a in db.q("SELECT attempt_id,node_id FROM attempts WHERE job_id=? AND state='live'", (job_id,)):
            db.x("UPDATE attempts SET state='revoked', end_reason='user_cancel', ended_at=? WHERE attempt_id=?",
                 (now(), a["attempt_id"]))
            _push(db, a["node_id"], "cancel", a["attempt_id"])
    db.event("job_cancelled", actor=actor, job_id=job_id)
