"""Sites: nodes that share one internet line (PLAN D55; docs/design/sites.md).

A site is a first-class, owner-confirmed partition of the fleet: a node is at no site or at exactly one. Its owner
sets an uplink budget (how many bulk transfers and network-heavy jobs may run at once, and optionally the rate the
fleet's transfers may use together), and the coordinator enforces two things over every node of the site:

- **The hold.** While any protected process at the site is in a phase tagged `uplink` (or such a phase cannot be read,
  or a node with one has not reported for 60 s: protection.node_phases, never looser), network-heavy fleet work pauses
  on every node of the site: no transfer lease is granted, every lease is revoked (the agents pause their transfers at
  the next renew, within SITE_HOLD_BOUND_S), network-heavy jobs are not admitted and the agents pause running ones.
  A revoked lease keeps its slot until its agent, having stopped, gives it back, or until it expires: an answer that
  granted or renewed it may still be on its way (specs/OarbankSiteUplink.tla found that race).
- **The budget.** Outside such phases, agents take a lease for each bulk transfer (staging, uploads, checkpoints,
  releases); at most `max_transfers` leases are live at a site, each paced at `uplink_mbps / max_transfers` when a rate
  is set, and at most `max_heavy_jobs` network-heavy jobs (stages[].requires.resources.network = "heavy") run there.

Sites are suggested from what nodes observe of their network (a keyed fingerprint of the default gateway's hardware
address, which the agent computes with a fleet salt, and of a public address the coordinator sees a node connect from);
the owner confirms. Neither a gateway address nor an IP address is ever stored or shown: only keyed fingerprints.
"""
import hashlib
import hmac
import ipaddress
import re
import secrets

from . import clock, modcalls, protection
from .db import DB, jl

TAG = "uplink"                     # the phase tag that holds a site (docs/design/gpu-cotenancy.md, "Tags")
LEASE_TTL_S = 20.0                 # a lease not renewed for this long is gone (the agent stops 5 s before, by its own clock)
POLL_S = 2.0                       # how often an agent with a lease or a network-heavy job asks for its site's state
SITE_HOLD_BOUND_S = 5.0            # from the agent seeing an uplink phase begin to every node of its site pausing
HEAVY_MIN_BYTES = 8 << 20          # transfers smaller than this need no lease (the agent's rule; protocol.md)
HINT_MIN_BYTES = 32 << 20          # transfers this large count toward the measured-capacity hint
HINT_WINDOW_S = 14 * 86400
TRANSFERS_KEEP_S = 30 * 86400
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
MAX_TRANSFERS_MAX = 32
DEFAULT_MAX_TRANSFERS = 1          # the measurement behind the feature: two large uploads at once each took 4x as long
DEFAULT_MAX_HEAVY_JOBS = 1


class SiteError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


def now() -> float:
    return clock.now()


# ------------------------------------------------------------------ store

def get(db: DB, ref: str) -> dict | None:
    return db.one("SELECT * FROM sites WHERE site_id=? OR name=?", (ref, ref))


def must(db: DB, ref: str) -> dict:
    s = get(db, ref or "")
    if not s:
        raise SiteError(404, "not_found", f"no site {ref!r}")
    return s


def site_of(db: DB, node_id: str) -> dict | None:
    return db.one("SELECT s.* FROM site_members m JOIN sites s ON s.site_id=m.site_id WHERE m.node_id=?", (node_id,))


def members(db: DB, site_id: str) -> list[str]:
    return [r["node_id"] for r in db.q("SELECT m.node_id FROM site_members m JOIN nodes n ON n.node_id=m.node_id "
                                       "WHERE m.site_id=? AND n.lifecycle!='retired' ORDER BY n.hostname", (site_id,))]


def resolve_nodes(db: DB, refs) -> list[dict]:
    out = []
    for ref in refs or []:
        n = db.one("SELECT node_id, hostname FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'",
                   (str(ref), str(ref)))
        if not n:
            raise SiteError(404, "not_found", f"no node {ref!r}")
        if n["node_id"] not in {x["node_id"] for x in out}:
            out.append(n)
    return out


def budget(params: dict, base: dict | None = None) -> dict:
    """The budget fields of a create or update, checked: `uplink_mbps` (a positive rate or null: no pacing),
    `max_transfers` (1..32) and `max_heavy_jobs` (0..32; 0 admits no network-heavy job at the site)."""
    out = {k: (base or {}).get(k) for k in ("uplink_mbps", "max_transfers", "max_heavy_jobs")}
    if base is None:
        out.update(max_transfers=DEFAULT_MAX_TRANSFERS, max_heavy_jobs=DEFAULT_MAX_HEAVY_JOBS)
    if "uplink_mbps" in params:
        v = params["uplink_mbps"]
        if v in (None, "", "none", 0, "0"):
            out["uplink_mbps"] = None
        else:
            try:
                v = float(v)
            except (TypeError, ValueError):
                raise SiteError(400, "bad_params", "uplink_mbps is a rate in Mbit/s (or empty: no pacing)")
            if not 0 < v <= 100_000:
                raise SiteError(400, "bad_params", "uplink_mbps is between 0 and 100000 Mbit/s")
            out["uplink_mbps"] = v
    for k, lo in (("max_transfers", 1), ("max_heavy_jobs", 0)):
        if k in params:
            try:
                v = int(params[k])
            except (TypeError, ValueError):
                raise SiteError(400, "bad_params", f"{k} is a whole number")
            if not lo <= v <= MAX_TRANSFERS_MAX:
                raise SiteError(400, "bad_params", f"{k} is between {lo} and {MAX_TRANSFERS_MAX}")
            out[k] = v
    return out


def check_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not NAME_RE.match(name):
        raise SiteError(400, "bad_params", "a site name is 1 to 63 of a-z 0-9 . _ - (starting with a letter or digit)")
    return name


def create(db: DB, name: str, params: dict, actor: str) -> dict:
    name = check_name(name)
    if get(db, name):
        raise SiteError(409, "exists", f"a site named {name} exists")
    b = budget(params)
    sid = "site_" + secrets.token_hex(6)
    t = now()
    db.x("INSERT INTO sites(site_id,name,description,uplink_mbps,max_transfers,max_heavy_jobs,hold_on,created_by,created_at,"
         "updated_by,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?,?)",
         (sid, name, (params.get("description") or "")[:500], b["uplink_mbps"], b["max_transfers"], b["max_heavy_jobs"],
          actor, t, actor, t))
    nodes = resolve_nodes(db, params.get("nodes"))
    moved = assign(db, sid, [n["node_id"] for n in nodes], actor)
    if params.get("suggestion"):
        db.x("INSERT OR REPLACE INTO site_dismissed(key, by, at, why) VALUES(?,?,?,'accepted')", (params["suggestion"], actor, t))
    db.event("site_created", actor=actor, reason=name, site=sid, nodes=[n["hostname"] for n in nodes])
    refresh(db, sid, t)
    return {"site_id": sid, "name": name, "moved": moved, **b}


def update(db: DB, site: dict, params: dict, actor: str) -> dict:
    fields = {}
    if "name" in params and params["name"] != site["name"]:
        name = check_name(params["name"])
        other = get(db, name)
        if other and other["site_id"] != site["site_id"]:
            raise SiteError(409, "exists", f"a site named {name} exists")
        fields["name"] = name
    if "description" in params:
        fields["description"] = (params.get("description") or "")[:500]
    b = budget(params, site)
    changed = {k: v for k, v in b.items() if v != site.get(k)}
    fields.update(changed)
    if not fields:
        return {"site_id": site["site_id"], "changed": []}
    sets = ", ".join(f"{k}=?" for k in fields)
    db.x(f"UPDATE sites SET {sets}, updated_by=?, updated_at=? WHERE site_id=?",
         (*fields.values(), actor, now(), site["site_id"]))
    if changed:
        # a new budget applies to every lease at once: the agents ask again, at the new rate and count, within POLL_S
        revoke_leases(db, site["site_id"], "budget changed")
    db.event("site_updated", actor=actor, reason=fields.get("name", site["name"]), site=site["site_id"], changed=sorted(fields))
    return {"site_id": site["site_id"], "changed": sorted(fields)}


def delete(db: DB, site: dict, actor: str) -> dict:
    gone = members(db, site["site_id"])
    db.x("DELETE FROM uplink_leases WHERE site_id=?", (site["site_id"],))
    db.x("DELETE FROM site_members WHERE site_id=?", (site["site_id"],))
    db.x("DELETE FROM sites WHERE site_id=?", (site["site_id"],))
    db.event("site_deleted", actor=actor, reason=site["name"], site=site["site_id"])
    return {"site_id": site["site_id"], "released": gone}


def assign(db: DB, site_id: str, node_ids: list[str], actor: str) -> list[dict]:
    """Put nodes at this site (a node is at one site: one at another moves). [{node_id, from}] for nodes that moved."""
    moved, t = [], now()
    for nid in node_ids:
        cur = db.one("SELECT site_id FROM site_members WHERE node_id=?", (nid,))
        if cur and cur["site_id"] == site_id:
            continue
        if cur:
            db.x("DELETE FROM uplink_leases WHERE node_id=?", (nid,))
            moved.append({"node_id": nid, "from": cur["site_id"]})
        db.x("INSERT OR REPLACE INTO site_members(node_id, site_id, added_by, added_at) VALUES(?,?,?,?)", (nid, site_id, actor, t))
    return moved


def unassign(db: DB, node_ids: list[str]) -> list[str]:
    out = []
    for nid in node_ids:
        if db.one("SELECT 1 FROM site_members WHERE node_id=?", (nid,)):
            db.x("DELETE FROM uplink_leases WHERE node_id=?", (nid,))
            db.x("DELETE FROM site_members WHERE node_id=?", (nid,))
            out.append(nid)
    return out


# ------------------------------------------------------------------ the hold

def _hostnames(db: DB, ids) -> dict:
    ids = list(ids)
    if not ids:
        return {}
    rows = db.q(f"SELECT node_id, hostname FROM nodes WHERE node_id IN ({','.join('?' * len(ids))})", tuple(ids))
    return {r["node_id"]: r["hostname"] for r in rows}


def state(db: DB, site: dict, t: float | None = None) -> dict:
    """Whether the site holds network-heavy work now, and why: protection.any_phase_on over its members for `uplink`
    (on when a tagged phase is on or unreadable, or a node with one is silent over 60 s), with each cause in words."""
    t = now() if t is None else t
    ids = members(db, site["site_id"])
    if not ids:
        return {"hold": False, "why": "", "causes": []}
    agg = protection.any_phase_on(db, ids, TAG, now=t)
    names = _hostnames(db, ids)
    causes = []
    for nid, d in protection.node_phases(db, ids, TAG, now=t).items():
        host = names.get(nid, nid)
        for p in d["phases"]:
            if p.get("on") or p.get("readable") is False:
                st = "on" if p.get("readable") is not False else "unreadable"
                causes.append({"node_id": nid, "hostname": host, "rule": p.get("rule"), "key": p.get("key"), "state": st,
                               "since": p.get("since"),
                               "text": f"{host}'s rule {p.get('rule')} is in an upload phase ({p.get('key')})" if st == "on"
                               else f"{host}'s rule {p.get('rule')}: its phase source cannot be read, so it counts as in an "
                                    f"upload phase ({p.get('key')})"})
        if d["phases"] and not d["fresh"]:
            causes.append({"node_id": nid, "hostname": host, "rule": None, "key": None, "state": "silent", "since": None,
                           "text": f"{host} has an upload phase and has not reported for over {protection.PHASES_FRESH_S} s"})
    hold = bool(agg["on"])                 # the helper decides; the causes only put it in words
    if hold and not causes:
        causes = [{"node_id": None, "hostname": None, "rule": None, "key": None, "state": "on", "since": None,
                   "text": "; ".join(agg["why"])}]
    return {"hold": hold, "why": "; ".join(c["text"] for c in causes) if hold else "", "causes": causes if hold else []}


def refresh(db: DB, site_id: str, t: float | None = None) -> dict:
    """The site's state now, persisted when it changed: an event (site_uplink_hold / site_uplink_free), and on a hold
    every lease revoked (the agents pause their transfers at their next renew)."""
    t = now() if t is None else t
    site = db.one("SELECT * FROM sites WHERE site_id=?", (site_id,))
    if not site:
        return {"hold": False, "why": "", "causes": []}
    st = state(db, site, t)
    began, ended = st["hold"] and not site["hold_on"], bool(site["hold_on"]) and not st["hold"]
    since = (t if began else site["hold_since"]) if st["hold"] else None
    if began or ended or (st["hold"] and site["hold_why"] != st["why"]):
        db.x("UPDATE sites SET hold_on=?, hold_since=?, hold_why=? WHERE site_id=?",
             (int(st["hold"]), since, st["why"] or None, site_id))
        if began or ended:
            db.event("site_uplink_hold" if began else "site_uplink_free", reason=st["why"] or site["name"],
                     site=site_id, name=site["name"])
    if st["hold"]:
        revoke_leases(db, site_id, "uplink phase")
    st["since"] = since
    return st


def revoke_leases(db: DB, site_id: str, why: str) -> int:
    """Revoke the site's live leases: each is answered `revoked` at its next renewal, and keeps its slot (and its rate)
    until its agent gives it back after stopping (release) or it expires."""
    n = db.one("SELECT COUNT(*) n FROM uplink_leases WHERE site_id=? AND revoked_at IS NULL", (site_id,))["n"]
    if n:
        db.x("UPDATE uplink_leases SET revoked_at=? WHERE site_id=? AND revoked_at IS NULL", (now(), site_id))
    return n


def tick(db: DB, t: float | None = None) -> None:
    """The reaper's pass: expire unrenewed leases and recompute every site (a node falling silent holds its site)."""
    t = now() if t is None else t
    with db.tx():
        db.x("DELETE FROM uplink_leases WHERE expires_at<?", (t,))
        for s in db.q("SELECT site_id FROM sites"):
            refresh(db, s["site_id"], t)


def observe(db: DB, node: dict, t: float | None = None) -> None:
    """A member's heartbeat (its phases may have changed): recompute its site at once."""
    s = db.one("SELECT site_id FROM site_members WHERE node_id=?", (node["node_id"],))
    if s:
        refresh(db, s["site_id"], t)


# ------------------------------------------------------------------ the budget

def heavy_running(db: DB, site_id: str) -> int:
    """Live attempts of network-heavy stages on the site's nodes."""
    rows = db.q("SELECT j.module, j.resources_json, n.platform FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                "JOIN nodes n ON n.node_id=a.node_id JOIN site_members m ON m.node_id=a.node_id "
                "WHERE a.state='live' AND m.site_id=?", (site_id,))
    return sum(1 for r in rows if is_heavy(jl(r["resources_json"], {}) or {}, r["platform"]))


def is_heavy(resources: dict, platform: str | None = None) -> bool:
    return (modcalls.resources_on(resources or {}, platform).get("network") or "normal") == "heavy"


def usage(db: DB, site: dict, t: float | None = None) -> dict:
    t = now() if t is None else t
    leases = db.q("SELECT * FROM uplink_leases WHERE site_id=? AND expires_at>=? ORDER BY granted_at", (site["site_id"], t))
    return {"transfers": len(leases), "revoked": sum(1 for x in leases if x["revoked_at"]), "max_transfers": site["max_transfers"],
            "mbps": round(sum(x["mbps"] or 0 for x in leases), 2) if site["uplink_mbps"] else None,
            "uplink_mbps": site["uplink_mbps"], "heavy_jobs": heavy_running(db, site["site_id"]),
            "max_heavy_jobs": site["max_heavy_jobs"], "leases": leases}


def lease_rate(site: dict) -> float | None:
    return round(site["uplink_mbps"] / max(1, site["max_transfers"]), 3) if site["uplink_mbps"] else None


def directive(db: DB, node: dict, st: dict | None = None) -> dict | None:
    """What the agent needs about its site (the heartbeat's `uplink.site`, and every renew): null at no site."""
    site = site_of(db, node["node_id"])
    if not site:
        return None
    st = st if st is not None else refresh(db, site["site_id"])
    return {"id": site["site_id"], "name": site["name"], "hold": st["hold"], "code": "SITE_UPLINK_BUSY" if st["hold"] else None,
            "why": st["why"] or None, "since": st.get("since"), "lease_ttl_s": LEASE_TTL_S, "poll_s": POLL_S,
            "lease_mbps": lease_rate(site), "max_transfers": site["max_transfers"]}


def directives(db: DB, node: dict) -> dict:
    """The heartbeat reply's `uplink`: the node's site (or null) and the salt its agent keys gateway fingerprints with."""
    return {"uplink": {"site": directive(db, node), "salt": agent_salt(db)}}


def lease(db: DB, node: dict, body: dict, t: float | None = None) -> dict:
    """A bulk transfer may start (POST /v1/agent/uplink/lease {kind, dir, bytes}): granted with a lease id and the rate
    to pace at, or refused with the code and when to ask again. A node at no site needs no lease."""
    t = now() if t is None else t
    with db.tx():
        site = site_of(db, node["node_id"])
        if not site:
            return {"granted": True, "lease_id": None, "site": None}
        st = refresh(db, site["site_id"], t)
        out = {"site": directive(db, node, st)}
        if st["hold"]:
            return {**out, "granted": False, "code": "SITE_UPLINK_BUSY", "why": st["why"], "retry_s": POLL_S}
        db.x("DELETE FROM uplink_leases WHERE site_id=? AND expires_at<?", (site["site_id"], t))
        held = db.q("SELECT mbps FROM uplink_leases WHERE site_id=?", (site["site_id"],))   # revoked ones included
        n, rate = len(held), lease_rate(site)
        if n >= site["max_transfers"]:
            return {**out, "granted": False, "code": "SITE_UPLINK_BUDGET", "retry_s": POLL_S,
                    "why": f"site {site['name']} runs {n} of its {site['max_transfers']} transfers"}
        used = sum(x["mbps"] or 0 for x in held)
        if rate and used + rate > site["uplink_mbps"] + 1e-6:
            return {**out, "granted": False, "code": "SITE_UPLINK_BUDGET", "retry_s": POLL_S,
                    "why": f"site {site['name']} has {used:g} of its {site['uplink_mbps']:g} Mbit/s leased"}
        lid = "ul_" + secrets.token_hex(8)
        kind = str(body.get("kind") or "transfer")[:32]
        direction = "up" if body.get("dir") == "up" else "down"
        size = int(body["bytes"]) if isinstance(body.get("bytes"), int) and body["bytes"] >= 0 else None
        db.x("INSERT INTO uplink_leases(lease_id,site_id,node_id,kind,dir,bytes,mbps,granted_at,renewed_at,expires_at,peak) "
             "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
             (lid, site["site_id"], node["node_id"], kind, direction, size, rate, t, t, t + LEASE_TTL_S, n + 1))
        db.x("UPDATE uplink_leases SET peak=MAX(peak, ?) WHERE site_id=?", (n + 1, site["site_id"]))
        return {**out, "granted": True, "lease_id": lid, "mbps": rate, "ttl_s": LEASE_TTL_S}


def renew(db: DB, node: dict, body: dict, t: float | None = None) -> dict:
    """POST /v1/agent/uplink/renew {leases: [...]}: each of the node's leases renewed ("ok"), or "revoked" (the site
    holds, the budget changed, it expired or was never this node's), and the site's state. A revoked lease is not
    deleted here: the answer may be lost, so it keeps its slot until the agent gives it back or it expires."""
    t = now() if t is None else t
    ids = [str(x) for x in (body.get("leases") or []) if isinstance(x, str)][:64]
    with db.tx():
        site = site_of(db, node["node_id"])
        st = refresh(db, site["site_id"], t) if site else None
        res = {}
        for lid in ids:
            row = db.one("SELECT * FROM uplink_leases WHERE lease_id=? AND node_id=?", (lid, node["node_id"]))
            live = row and site and row["site_id"] == site["site_id"] and row["expires_at"] >= t and not row["revoked_at"]
            if live and not st["hold"]:
                db.x("UPDATE uplink_leases SET renewed_at=?, expires_at=? WHERE lease_id=?", (t, t + LEASE_TTL_S, lid))
                res[lid] = "ok"
            else:
                if row and row["expires_at"] < t:
                    db.x("DELETE FROM uplink_leases WHERE lease_id=?", (lid,))
                elif live:
                    db.x("UPDATE uplink_leases SET revoked_at=? WHERE lease_id=?", (t, lid))
                res[lid] = "revoked"
        return {"site": directive(db, node, st) if site else None, "leases": res}


def release(db: DB, node: dict, body: dict, t: float | None = None) -> dict:
    """POST /v1/agent/uplink/release {lease_id, dir, bytes, seconds, paced}: the transfer ended, or its agent stopped
    using a revoked lease: the slot is free. A large transfer's rate is kept for the measured-capacity hint."""
    t = now() if t is None else t
    lid = str(body.get("lease_id") or "")
    with db.tx():
        row = db.one("SELECT * FROM uplink_leases WHERE lease_id=? AND node_id=?", (lid, node["node_id"])) if lid else None
        if row:
            db.x("DELETE FROM uplink_leases WHERE lease_id=?", (lid,))
        site = site_of(db, node["node_id"])
        try:
            size, secs = int(body.get("bytes") or 0), float(body.get("seconds") or 0)
        except (TypeError, ValueError):
            size, secs = 0, 0.0
        if site and size >= (1 << 20) and secs > 0:
            mbps = size * 8 / secs / 1e6
            db.x("INSERT INTO uplink_transfers(site_id,node_id,kind,dir,bytes,seconds,mbps,solo,paced,at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (site["site_id"], node["node_id"], str(body.get("kind") or (row or {}).get("kind") or "transfer")[:32],
                  "up" if body.get("dir", (row or {}).get("dir")) == "up" else "down", size, round(secs, 3), round(mbps, 3),
                  int(not row or (row["peak"] or 1) <= 1), int(bool(body.get("paced"))), t))
            db.x("DELETE FROM uplink_transfers WHERE at<?", (t - TRANSFERS_KEEP_S,))
    return {"ok": True}


def hint(db: DB, site_id: str, t: float | None = None) -> dict:
    """The measured-capacity hint: the 90th percentile of the rates large transfers reached at the site while no other
    leased transfer ran there and nothing paced them, per direction, over 14 days ("fleet transfers here reached ...").
    It measures the path to wherever the transfers went (often the coordinator on the LAN), so it is a ceiling to start
    the budget from, not the line's capacity."""
    t = now() if t is None else t
    out = {}
    for d in ("up", "down"):
        rates = sorted(r["mbps"] for r in db.q(
            "SELECT mbps FROM uplink_transfers WHERE site_id=? AND dir=? AND solo=1 AND paced=0 AND bytes>=? AND at>=?",
            (site_id, d, HINT_MIN_BYTES, t - HINT_WINDOW_S)))
        if rates:
            out[d] = {"mbps": round(rates[min(len(rates) - 1, int(0.9 * len(rates)))], 1), "n": len(rates)}
    return out


# ------------------------------------------------------------------ claim

def claim_view(db: DB, node: dict, t: float | None = None) -> dict | None:
    """What claim() and explain need about the node's site (predicates.NodeView.site)."""
    site = site_of(db, node["node_id"])
    if not site:
        return None
    st = state(db, site, t)
    return {"site_id": site["site_id"], "name": site["name"], "hold": st["hold"], "why": st["why"],
            "heavy_running": heavy_running(db, site["site_id"]), "max_heavy_jobs": site["max_heavy_jobs"]}


# ------------------------------------------------------------------ suggestions from what nodes observe

def _key(db: DB) -> bytes:
    k = db.get_state("site_fp_key")
    if not k:
        k = secrets.token_hex(32)
        db.set_state("site_fp_key", k)
    return bytes.fromhex(k)


def agent_salt(db: DB) -> str:
    """The salt every agent keys its gateway fingerprint with: the same for the whole fleet (so two nodes behind one
    gateway agree), unknown outside it (so a fingerprint cannot be matched against a hardware address by anyone else)."""
    return hmac.new(_key(db), b"oarbank-site-agent-salt-1", hashlib.sha256).hexdigest()


def public_fp(db: DB, ip: str) -> str | None:
    """A keyed fingerprint of a public address a node connected from (never stored as the address); None for private,
    loopback, link-local, CGNAT (a tailnet) and other non-global addresses."""
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    if not a.is_global:
        return None
    if a.version == 6:
        a = ipaddress.ip_network(f"{a}/64", strict=False).network_address     # one line hands out a /64 or wider
    return hmac.new(_key(db), f"public:{a}".encode(), hashlib.sha256).hexdigest()[:16]


FP_RE = re.compile(r"^[0-9a-f]{16,64}$")


def observe_network(db: DB, node: dict, body: dict, peer_ip: str | None) -> dict:
    """POST /v1/agent/uplink/network {gateway_fp}: what the node observes of its network (its agent's keyed gateway
    fingerprint) and the public address the coordinator sees it connect from (kept only as a keyed fingerprint)."""
    t = now()
    gw = str(body.get("gateway_fp") or "").lower()
    gw = gw[:32] if FP_RE.match(gw) else None
    pub = public_fp(db, peer_ip or "")
    with db.tx():
        db.x("INSERT INTO node_net(node_id, gateway_fp, public_fp, observed_at) VALUES(?,?,?,?) ON CONFLICT(node_id) DO "
             "UPDATE SET gateway_fp=excluded.gateway_fp, public_fp=COALESCE(excluded.public_fp, node_net.public_fp), "
             "observed_at=excluded.observed_at", (node["node_id"], gw, pub, t))
    return {"ok": True}


def suggestions(db: DB) -> list[dict]:
    """Groups of two or more nodes that look like they share an internet line and are not already all at one site:
    the same gateway fingerprint, or the same public-address fingerprint. Each names its evidence (never an address),
    the nodes, the site some of them are at already, and a stable key (accept: sites.create with `suggestion`, or
    sites.assign; dismiss: sites.dismiss)."""
    rows = db.q("SELECT x.node_id, x.gateway_fp, x.public_fp, n.hostname, m.site_id FROM node_net x JOIN nodes n ON "
                "n.node_id=x.node_id LEFT JOIN site_members m ON m.node_id=x.node_id WHERE n.lifecycle!='retired'")
    dismissed = {r["key"] for r in db.q("SELECT key FROM site_dismissed")}
    names = {r["site_id"]: r["name"] for r in db.q("SELECT site_id, name FROM sites")}
    out, seen = [], set()
    for kind, col, words in (("gateway", "gateway_fp", "share a default gateway"),
                             ("public", "public_fp", "connect from the same public address")):
        groups: dict = {}
        for r in rows:
            if r[col]:
                groups.setdefault(r[col], []).append(r)
        for fp, rs in sorted(groups.items()):
            if len(rs) < 2:
                continue
            ids = tuple(sorted(r["node_id"] for r in rs))
            sites_now = {r["site_id"] for r in rs}
            if len(sites_now) == 1 and None not in sites_now:
                continue                                   # already one site
            key = hashlib.sha256(f"{kind}:{fp}:{','.join(ids)}".encode()).hexdigest()[:16]
            if key in dismissed or ids in seen:
                continue
            seen.add(ids)
            at = sorted({names.get(s, s) for s in sites_now if s})
            out.append({"key": key, "evidence": kind, "label": f"{kind} {fp[:6]}",
                        "text": f"{len(rs)} nodes {words}" + (f" (some are at {', '.join(at)})" if at else ""),
                        "nodes": [{"node_id": r["node_id"], "hostname": r["hostname"], "site": names.get(r["site_id"])}
                                  for r in sorted(rs, key=lambda r: r["hostname"] or "")],
                        "sites": at})
    return out


def dismiss(db: DB, key: str, actor: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{16}", key or ""):
        raise SiteError(400, "bad_params", "a suggestion key is 16 hex characters (oarbank sites suggest)")
    db.x("INSERT OR REPLACE INTO site_dismissed(key, by, at, why) VALUES(?,?,?,'dismissed')", (key, actor, now()))
    return {"key": key}


# ------------------------------------------------------------------ views (console, CLI, API)

def _member_rows(db: DB, site: dict, t: float) -> list[dict]:
    out = []
    for nid in members(db, site["site_id"]):
        n = db.one("SELECT node_id, hostname, last_heartbeat_at, telemetry_json FROM nodes WHERE node_id=?", (nid,))
        tel = jl(n["telemetry_json"], {}) or {}
        phases = [p for p in (tel.get("protection") or {}).get("phases") or [] if TAG in (p.get("tags") or [])]
        up = tel.get("uplink")
        out.append({"node_id": nid, "hostname": n["hostname"], "phases": phases,
                    "online": (n["last_heartbeat_at"] or 0) >= t - protection.PHASES_FRESH_S,
                    "uplink": up if isinstance(up, dict) else None,
                    "reports_uplink": isinstance(up, dict)})
    return out


def summary(db: DB, site: dict, t: float | None = None) -> dict:
    t = now() if t is None else t
    st = state(db, site, t)
    u = usage(db, site, t)
    return {"site_id": site["site_id"], "name": site["name"], "description": site["description"] or "",
            "uplink_mbps": site["uplink_mbps"], "max_transfers": site["max_transfers"],
            "max_heavy_jobs": site["max_heavy_jobs"], "lease_mbps": lease_rate(site),
            "hold": st["hold"], "why": st["why"], "causes": st["causes"],
            "since": site["hold_since"] if st["hold"] else None,
            "state": f"paused because {st['why']}" if st["hold"] else "free",
            "transfers": u["transfers"], "heavy_jobs": u["heavy_jobs"], "mbps_in_use": u["mbps"],
            "hint": hint(db, site["site_id"], t), "members": [n["hostname"] for n in _member_rows(db, site, t)],
            "updated_by": site["updated_by"], "updated_at": site["updated_at"]}


def listing(db: DB, t: float | None = None) -> dict:
    t = now() if t is None else t
    sites = [summary(db, s, t) for s in db.q("SELECT * FROM sites ORDER BY name")]
    placed = {r["node_id"] for r in db.q("SELECT node_id FROM site_members")}
    unplaced = [r["hostname"] for r in db.q("SELECT node_id, hostname FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
                if r["node_id"] not in placed]
    return {"sites": sites, "suggestions": suggestions(db), "unplaced": unplaced}


def detail(db: DB, ref: str, t: float | None = None) -> dict:
    t = now() if t is None else t
    site = must(db, ref)
    u = usage(db, site, t)
    names = _hostnames(db, {x["node_id"] for x in u["leases"]})
    leases = [{"lease_id": x["lease_id"], "node": names.get(x["node_id"], x["node_id"]), "kind": x["kind"], "dir": x["dir"],
               "bytes": x["bytes"], "mbps": x["mbps"], "age_s": round(t - x["granted_at"], 1)} for x in u["leases"]]
    recent = db.q("SELECT t.*, n.hostname FROM uplink_transfers t LEFT JOIN nodes n ON n.node_id=t.node_id WHERE t.site_id=? "
                  "ORDER BY t.at DESC LIMIT 20", (site["site_id"],))
    events = db.q("SELECT ts, kind, reason FROM events WHERE kind IN ('site_uplink_hold','site_uplink_free','site_created',"
                  "'site_updated') AND payload_json LIKE ? ORDER BY event_id DESC LIMIT 20", (f'%"{site["site_id"]}"%',))
    return {**summary(db, site, t), "member_rows": _member_rows(db, site, t), "leases": leases,
            "recent_transfers": [dict(r) for r in recent], "events": [dict(e) for e in events],
            "suggestions": [s for s in suggestions(db) if site["name"] in s["sites"]]}


def node_site(db: DB, node_id: str, t: float | None = None) -> dict | None:
    """The node page's line: its site, the site's state in words, and whether the agent enforces it."""
    site = site_of(db, node_id)
    if not site:
        return None
    st = state(db, site, t)
    return {"site_id": site["site_id"], "name": site["name"], "hold": st["hold"], "why": st["why"],
            "state": f"paused because {st['why']}" if st["hold"] else "free"}
