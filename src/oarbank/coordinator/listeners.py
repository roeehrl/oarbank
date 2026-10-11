"""Inbound listeners on the coordinator side (docs/design/inbound-listeners.md; PLAN D47-D49, invariant S24).

The agent owns every listener: it accepts TCP connections on a node, maps the port on the router (D48) and relays each
connection to the module's endpoint service. The coordinator decides nothing on the wire; it keeps three things:

- **The owner's configuration** (`system_state` `listener_config`: `{node_id: {"<module>/<listener>": entry}}`), edited by
  `listeners.configure` and `listeners.remove`. Each entry travels, resolved against the module's manifest, in the node's
  signed statement (statements.py, `listeners`), but only while the module version that node runs requests that inbound
  listener and its sandbox grants are approved by digest.
- **What the agent reports**: its listeners, router mappings and network view (`nodes.listeners_json`), the top client
  addresses while an operator looks (`nodes.listener_talkers_json`, kept 10 minutes), and the kill switch
  (`listeners.disable` for a node or the fleet).
- **The dial-back probes** (D49, table `listener_probes`): a probe is scheduled from a report's `probe_wanted` or
  `listeners.probe`, at most one a minute per listener, at the external address the node's own router reported; a fleet
  node on another network dials it (`dial_probes`), the target expects it (`listener_probes`), and the outcome reaches
  the target as `listener_reachability`.
"""
import ipaddress
import json
import re
import secrets
import time

from . import clock
from . import config as C
from .db import DB, jl

SCHEMA = """
-- dial-back probes of inbound listeners (docs/design/inbound-listeners.md, "The dial-back probe"): `node_id` is the target,
-- `prober` the fleet node that dials; state pending | reachable | unreachable | no_prober | retried
CREATE TABLE IF NOT EXISTS listener_probes (
  probe_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, key TEXT NOT NULL, host TEXT, port INT, nonce TEXT NOT NULL,
  prober TEXT, via TEXT, state TEXT NOT NULL, detail TEXT, created_at REAL NOT NULL, done_at REAL,
  tried_json TEXT DEFAULT '[]');
CREATE INDEX IF NOT EXISTS listener_probes_target ON listener_probes(node_id, key, created_at);
CREATE INDEX IF NOT EXISTS listener_probes_prober ON listener_probes(prober, state);
"""
# nodes columns (db.py adds them to a home made by an earlier version)
NODE_COLUMNS = {"listeners_json": "TEXT",            # {"listeners": [...], "portmaps": [...], "network": {...}, ...}
                "listeners_at": "REAL",              # when the agent last reported them
                "listener_talkers_json": "TEXT",     # {key: [{addr, conns, refused, last}]}, only the latest
                "listener_talkers_at": "REAL",
                "want_talkers_until": "REAL",        # send_listener_talkers while an operator looks (until this time)
                "listeners_disabled": "INT DEFAULT 0",   # listeners.disable for this node (the kill switch)
                "observed_addr": "TEXT"}             # the node's request source address when it is public

CONFIG = "listener_config"                 # system_state: {node_id: {key: entry}}
FLEET_DISABLED = "listeners_disabled"      # system_state: the fleet kill switch
HISTORY = "listener_statement_keys"        # system_state: {node_id: {seq: [keys]}}, the listeners each statement listed
HISTORY_KEEP = 32

KEY_RE = re.compile(r"^([a-z0-9][a-z0-9_.-]{0,63})/([a-z][a-z0-9_]*)$")
FALLBACK_RE = re.compile(r"^next_free:(\d{4,5})-(\d{4,5})$")
MAPPINGS = ("auto", "pcp", "natpmp", "upnp", "manual", "none")
IPV6 = ("auto", "off")
LIMIT_KEYS = ("max_conns", "max_conns_per_ip", "new_conns_per_ip_per_s", "idle_timeout_s", "max_bytes_per_s")
INT_LIMITS = ("max_conns", "max_conns_per_ip")
FIELDS = ("external_port", "fallback", "mapping", "ipv6", "bind", "internal_port", "limits", "allow")

PROBE_EVERY_S = 60.0                       # at most one probe a minute per listener
PROBE_TTL_S = 60.0                         # a probe nobody answered expires
TALKERS_TTL_S = 600.0                      # top talkers are kept, and asked for, 10 minutes
SATURATED_QUIET_S = 600.0                  # listener_saturated resolves after 10 minutes without new refusals
MAX_LISTENERS, MAX_PORTMAPS, MAX_ROUTER_MAPPINGS, MAX_TALKERS = 64, 128, 128, 20
# the doctor's results that open listener_unreachable (after 10 minutes; contracts/alert_rules.py)
UNREACHABLE_RESULTS = ("MAPPED_UNREACHABLE", "DOUBLE_NAT", "CGNAT", "NO_MAPPING_PROTOCOL", "FIREWALL_BLOCKED",
                       "PORT_TAKEN")
# the explain codes the coordinator registers for listeners (contracts/reason_codes.py)
EXPLAIN_RESULTS = ("PORT_TAKEN", "DOUBLE_NAT", "CGNAT", "NO_MAPPING_PROTOCOL", "MAPPED_UNREACHABLE", "FIREWALL_BLOCKED")


class ListenerError(ValueError):
    def __init__(self, detail: str, status: int = 400, code: str = "bad_listener"):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


# ------------------------------------------------------------------ addresses

_V4_NOT_PUBLIC = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                                                     "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
                                                     "240.0.0.0/4")]
_V6_NOT_PUBLIC = [ipaddress.ip_network(n) for n in ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def public_ip(addr) -> str | None:
    """The address as text when it is public: not RFC 1918, not 100.64.0.0/10 (carrier-grade NAT and Tailscale), not
    loopback, link-local, unique-local (Tailscale's IPv6 range is one), multicast or unspecified; else None."""
    if not isinstance(addr, str) or not addr:
        return None
    try:
        ip = ipaddress.ip_address(addr.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    nets = _V4_NOT_PUBLIC if ip.version == 4 else _V6_NOT_PUBLIC
    return None if any(ip in n for n in nets) else str(ip)


def split_hostport(s) -> tuple[str, int] | None:
    """("198.51.100.7", 9000) from "198.51.100.7:9000", ("2001:db8::7", 9000) from "[2001:db8::7]:9000"; None when it is
    not an address and port."""
    if not isinstance(s, str):
        return None
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d{1,5})", s.strip()) or re.fullmatch(r"([^:\s]+):(\d{1,5})", s.strip())
    if not m or not 0 < int(m.group(2)) < 65536:
        return None
    return m.group(1), int(m.group(2))


# ------------------------------------------------------------------ manifests and grants

_STATUS_CACHE: dict = {}


def _grant_status(db, name: str, version: str) -> dict | None:
    """modsandbox.status of an installed version (cached by the approval it has): None when it is not installed."""
    from . import modsandbox
    row = db.one("SELECT digest, approved_at FROM module_grants WHERE name=? AND version=?", (name, version))
    ck = (str(db.path), name, version, (row or {}).get("digest"), (row or {}).get("approved_at"))
    if ck not in _STATUS_CACHE:
        try:
            _STATUS_CACHE[ck] = modsandbox.status(db, name, version)
        except (modsandbox.GrantError, OSError, ValueError):
            return None
        if len(_STATUS_CACHE) > 512:
            _STATUS_CACHE.pop(next(iter(_STATUS_CACHE)))
    return _STATUS_CACHE[ck]


def manifest_for(db, name: str, version: str | None):
    """The manifest of an installed module version (the module host's catalogue first), else None."""
    if not version:
        return None
    from . import modcalls, modsandbox
    try:
        return modcalls.info_for(name, version).manifest
    except KeyError:
        pass
    try:
        return modsandbox._manifest(db, name, version)[0]
    except (modsandbox.GrantError, OSError, ValueError):
        return None


def declared(db, node_id: str, key: str):
    """(module, listener, version, the manifest's InboundListener or None) for a key on a node: the module version the
    node runs (modstore.version_for_node)."""
    from . import modstore
    m = KEY_RE.fullmatch(key or "")
    if not m:
        raise ListenerError(f"{key!r} is not <module>/<listener>")
    mod, name = m.group(1), m.group(2)
    ver = modstore.version_for_node(db, mod, node_id)
    man = manifest_for(db, mod, ver)
    lst = man.sandbox.net.listener(name) if man is not None else None
    return mod, name, ver, lst


def granted(db, node_id: str, key: str) -> bool:
    """Whether the module version the node runs requests this inbound listener and its grants are approved by digest."""
    try:
        mod, name, ver, lst = declared(db, node_id, key)
    except ListenerError:
        return False
    if lst is None:
        return False
    st = _grant_status(db, mod, ver)
    return bool(st and st["approved"] and any(x.get("name") == name for x in (st["requests"].get("inbound") or [])))


# ------------------------------------------------------------------ the owner's configuration

def config(db) -> dict:
    return db.get_state(CONFIG, {}) or {}


def node_config(db, node_id: str) -> dict:
    return dict(config(db).get(node_id) or {})


def default_fallback(lst, external_port) -> str:
    """`refuse` for a stable port; for a flexible one the next 16 ports from the external port (or the hint), else the
    port the router assigns."""
    if lst.port_policy == "stable":
        return "refuse"
    p = external_port or lst.port_hint
    return f"next_free:{p}-{min(p + 15, 65535)}" if p else "router_choice"


def resolve(entry: dict, lst) -> dict:
    """An entry with every key explicit, as the statement carries it: what the owner set, else the default from the
    manifest (docs/design/inbound-listeners.md, "The owner's configuration on the node")."""
    ext = entry["external_port"] if "external_port" in entry else lst.port_hint
    return {"external_port": ext, "fallback": entry.get("fallback") or default_fallback(lst, ext),
            "mapping": entry.get("mapping") or "auto", "ipv6": entry.get("ipv6") or "auto",
            "bind": entry.get("bind") or "default_route", "internal_port": entry.get("internal_port"),
            "limits": {k: v for k, v in sorted((entry.get("limits") or {}).items())
                       if k in LIMIT_KEYS and _lower(lst, k, v)},
            "allow": list(entry.get("allow") or [])}


def _ceiling(lst, k):
    return getattr(lst, k, None)


def _lower(lst, k, v) -> bool:
    top = _ceiling(lst, k)
    return top is None or v < top


def statement_listeners(db, node_id: str) -> dict:
    """{key: resolved entry}: the node's configured listeners whose module version on the node requests them with
    approved grants (statements.content)."""
    out = {}
    for key, entry in sorted(node_config(db, node_id).items()):
        if not granted(db, node_id, key):
            continue
        lst = declared(db, node_id, key)[3]
        out[key] = resolve(entry, lst)
    return out


def _port(v, what: str):
    if v is None:
        return None
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v.strip())
    if not isinstance(v, int) or isinstance(v, bool) or not 1024 <= v <= 65535:
        raise ListenerError(f"{what}: a port from 1024 to 65535 (got {v!r}); ports below 1024 are never mapped")
    return v


def check_entry(db, node: dict, key: str, params: dict) -> tuple[dict, object, str]:
    """The owner's entry for a key on a node, validated and merged over what is set (a field given as null returns to
    its default): (entry as stored, the manifest's listener, the module version). ListenerError names what is wrong."""
    nid = node["node_id"]
    facts = jl(node.get("facts_json"), {}) or {}
    lf = facts.get("listeners") if isinstance(facts.get("listeners"), dict) else {}
    if not isinstance(lf.get("version"), int) or lf["version"] < 1:
        raise ListenerError(f"the agent on {node['hostname']} does not support inbound listeners (its facts report no "
                            "listener support): update it to an agent of core 2.10 or later", 409, "agent_unsupported")
    mod, name, ver, lst = declared(db, nid, key)
    if ver is None:
        raise ListenerError(f"module {mod} is not enabled for {node['hostname']}", 409, "module_not_enabled")
    if lst is None:
        raise ListenerError(f"{mod} {ver} (the version {node['hostname']} runs) does not request an inbound listener "
                            f"named {name!r} in [sandbox].net.inbound", 409, "listener_not_requested")
    if getattr(lst, "handover", "connections") == "listen_fd" and (node.get("os") == "windows" or
                                                                  str(node.get("platform") or "").startswith("windows")):
        raise ListenerError(f"{key} hands its service a listening socket (handover = listen_fd), which Windows nodes do not "
                            f"support: {node['hostname']} would refuse it", 409, "handover_unsupported")
    unknown = sorted(set(params) - set(FIELDS))
    if unknown:
        raise ListenerError(f"unknown fields {unknown} (a listener entry has {', '.join(FIELDS)})")
    entry = dict(node_config(db, nid).get(key) or {})
    for k, v in params.items():
        if v is None or (k in ("fallback", "mapping", "ipv6", "bind") and v == ""):
            entry.pop(k, None)
            continue
        if k in ("external_port", "internal_port"):
            entry[k] = _port(v, k)
        elif k == "fallback":
            m = FALLBACK_RE.fullmatch(str(v).strip())
            if str(v).strip() in ("refuse", "router_choice"):
                entry[k] = str(v).strip()
            elif m and 1024 <= int(m.group(1)) <= int(m.group(2)) <= 65535:
                entry[k] = f"next_free:{int(m.group(1))}-{int(m.group(2))}"
            else:
                raise ListenerError(f"fallback: refuse, router_choice or next_free:<a>-<b> with 1024 <= a <= b <= 65535 "
                                    f"(got {v!r})")
        elif k == "mapping":
            if v not in MAPPINGS:
                raise ListenerError(f"mapping: one of {', '.join(MAPPINGS)} (got {v!r})")
            entry[k] = v
        elif k == "ipv6":
            if v not in IPV6:
                raise ListenerError(f"ipv6: auto or off (got {v!r})")
            entry[k] = v
        elif k == "bind":
            if v != "default_route":
                try:
                    v = str(ipaddress.ip_address(str(v).strip()))
                except ValueError:
                    raise ListenerError(f"bind: default_route or an IP address (got {v!r})") from None
                if v in ("0.0.0.0", "::"):
                    raise ListenerError("bind: never the wildcard address; default_route or one of the node's addresses")
            entry[k] = v
        elif k == "limits":
            if not isinstance(v, dict):
                raise ListenerError("limits: an object of the manifest's limit keys")
            lim = {}
            for lk, lv in v.items():
                if lk not in LIMIT_KEYS:
                    raise ListenerError(f"limits: unknown key {lk!r} (one of {', '.join(LIMIT_KEYS)})")
                if lv is None:
                    continue
                try:
                    lv = float(lv)
                except (TypeError, ValueError):
                    raise ListenerError(f"limits.{lk}: a number (got {lv!r})") from None
                if not lv > 0:
                    raise ListenerError(f"limits.{lk}: more than 0 (got {lv:g})")
                if lk in INT_LIMITS:
                    if lv != int(lv):
                        raise ListenerError(f"limits.{lk}: a whole number (got {lv:g})")
                    lv = int(lv)
                elif lv.is_integer():
                    lv = int(lv)
                top = _ceiling(lst, lk)
                if top is not None and lv > top:
                    raise ListenerError(f"limits.{lk}: {lv:g} is above the module's ceiling of {top:g}; the owner may only "
                                        f"lower a listener's limits, never raise them")
                if top is None or lv < top:
                    lim[lk] = lv
            if lim:
                entry[k] = dict(sorted(lim.items()))
            else:
                entry.pop(k, None)
        elif k == "allow":
            if isinstance(v, str):
                v = [x for x in re.split(r"[\s,]+", v) if x]
            if not isinstance(v, list) or len(v) > 256:
                raise ListenerError("allow: a list of at most 256 CIDRs")
            nets = []
            for c in v:
                try:
                    n = str(ipaddress.ip_network(str(c).strip(), strict=False))
                except ValueError:
                    raise ListenerError(f"allow: {c!r} is not a CIDR (198.51.100.0/24, 2001:db8::/32)") from None
                if n not in nets:
                    nets.append(n)
            if nets:
                entry[k] = nets
            else:
                entry.pop(k, None)
    return entry, lst, ver


def describe_entry(key: str, r: dict) -> str:
    """One line for a preview or the CLI: port, fallback, mapping and the lowered limits."""
    port = f"external port {r['external_port']}" if r.get("external_port") else "the internal port as the external port"
    lim = ", ".join(f"{k} {v:g}" for k, v in (r.get("limits") or {}).items())
    allow = f"; only {', '.join(r['allow'])}" if r.get("allow") else ""
    return (f"{key}: {port}, fallback {r['fallback']}, mapping {r['mapping']}, IPv6 {r['ipv6']}, bind {r['bind']}"
            + (f", internal port {r['internal_port']}" if r.get("internal_port") else "")
            + (f"; limits lowered: {lim}" if lim else "; the module's limits") + allow)


def set_entry(db, node_id: str, key: str, entry: dict | None) -> None:
    cfg = config(db)
    mine = dict(cfg.get(node_id) or {})
    if entry is None:
        mine.pop(key, None)
    else:
        mine[key] = entry
    if mine:
        cfg[node_id] = dict(sorted(mine.items()))
    else:
        cfg.pop(node_id, None)
    db.set_state(CONFIG, cfg)


def refresh_statements(db, node_ids=None) -> list[str]:
    """Rebuild the statements of nodes with listener configuration, or whose statement lists listeners: a module
    version that changes on a node, or grants approved later, add or drop entries (statements.refresh)."""
    from . import statements
    if node_ids is None:
        sts = statements.statements(db)
        node_ids = set(config(db)) | {nid for nid, s in sts.items() if (json.loads(s["statement"]).get("listeners") or {})}
        live = {r["node_id"] for r in db.q("SELECT node_id FROM nodes WHERE lifecycle!='retired'")}
        node_ids = sorted(set(node_ids) & live)
    return statements.refresh(db, list(node_ids)) if node_ids else []


_LAST_TICK: dict = {}


def tick(db, now: float | None = None) -> None:
    """The background step (core.reap): statements follow module and grant changes (every 30 s), probes expire, top
    talkers older than 10 minutes go."""
    t = clock.now() if now is None else now
    expire_probes(db, t)
    db.x("UPDATE nodes SET listener_talkers_json=NULL, listener_talkers_at=NULL WHERE listener_talkers_at<?",
         (t - TALKERS_TTL_S,))
    k = str(db.path)
    if t - _LAST_TICK.get(k, 0) >= 30:
        _LAST_TICK[k] = t
        refresh_statements(db)
        # finished probes older than a day go, except the latest outcome of each listener (listener_reachability)
        db.x("DELETE FROM listener_probes WHERE state!='pending' AND created_at<? AND probe_id NOT IN ("
             "SELECT (SELECT q.probe_id FROM listener_probes q WHERE q.node_id=p.node_id AND q.key=p.key "
             "AND q.state IN ('reachable','unreachable','no_prober') ORDER BY q.done_at DESC LIMIT 1) "
             "FROM listener_probes p GROUP BY p.node_id, p.key)", (t - 86400,))


def note_statement(db, node_id: str, seq: int, keys) -> None:
    """Remember which listeners statement `seq` of a node listed (S24 checks a report against the statement it applied)."""
    h = db.get_state(HISTORY, {}) or {}
    mine = h.get(node_id) or {}
    mine[str(seq)] = sorted(keys)
    for s in sorted(mine, key=int)[:-HISTORY_KEEP]:
        mine.pop(s)
    h[node_id] = mine
    db.set_state(HISTORY, h)


# ------------------------------------------------------------------ reports (heartbeat)

def report(node: dict) -> dict:
    """{"listeners": [...], "portmaps": [...], "network": {...}} as the node last reported them."""
    d = jl(node.get("listeners_json"), {}) or {}
    return {"listeners": d.get("listeners") or [], "portmaps": d.get("portmaps") or [], "network": d.get("network") or {},
            "saturated": d.get("saturated") or {}}


def _dicts(xs, n):
    return [x for x in (xs if isinstance(xs, list) else [])[:n] if isinstance(x, dict)]


def ingest(db, node: dict, body: dict, peer_ip: str = "") -> None:
    """The heartbeat's listener reports (inside core.heartbeat's transaction): `listeners`, `portmaps` and `network`
    (bounded) as the node's `listeners_json`, `probe_results` into the probe table, `listener_talkers` (only the latest),
    the node's public source address, probes the report asks for, and the listener alerts."""
    nid, t = node["node_id"], clock.now()
    obs = public_ip(peer_ip)
    if obs != node.get("observed_addr"):
        db.x("UPDATE nodes SET observed_addr=? WHERE node_id=?", (obs, nid))
    if any(k in body for k in ("listeners", "portmaps", "network")):
        old = report(node)
        net = body.get("network") if isinstance(body.get("network"), dict) else {}
        if net:
            net = {**net, "router_mappings": _dicts(net.get("router_mappings"), MAX_ROUTER_MAPPINGS)}
        doc = {"listeners": _dicts(body.get("listeners"), MAX_LISTENERS),
               "portmaps": _dicts(body.get("portmaps"), MAX_PORTMAPS), "network": net}
        doc["saturated"] = _saturation(db, node, old, doc["listeners"], t)
        text = json.dumps(doc, default=str)
        if len(text) > 400_000:                   # never a truncated document: drop the bulkiest parts instead
            doc["network"] = {k: v for k, v in net.items() if k != "router_mappings"}
            doc["listeners"], doc["portmaps"] = doc["listeners"][:16], doc["portmaps"][:32]
            text = json.dumps(doc, default=str)
            if len(text) > 400_000:
                text = json.dumps({"listeners": [], "portmaps": [], "network": {}, "saturated": {}})
        db.x("UPDATE nodes SET listeners_json=?, listeners_at=? WHERE node_id=?", (text, t, nid))
        _reachability_alerts(db, node, old["listeners"], doc["listeners"])
        for x in doc["listeners"]:
            if x.get("probe_wanted") is True and isinstance(x.get("key"), str):
                try:
                    schedule(db, nid, x["key"], t, listener=x)
                except ListenerError:
                    pass
    if isinstance(body.get("probe_results"), list):
        for r in _dicts(body["probe_results"], 64):
            record_result(db, nid, r, t)
    if isinstance(body.get("listener_talkers"), dict):
        tk = {str(k)[:160]: _dicts(v, MAX_TALKERS) for k, v in list(body["listener_talkers"].items())[:MAX_LISTENERS]}
        db.x("UPDATE nodes SET listener_talkers_json=?, listener_talkers_at=?, want_talkers_until=NULL WHERE node_id=?",
             (json.dumps(tk)[:200_000], t, nid))


def _saturation(db, node: dict, old: dict, new: list, t: float) -> dict:
    """listener_saturated (P4): a listener whose refusals for its connection caps (`cap`, `per_ip`) grew since the last
    report; it resolves after 10 minutes without new ones. Returns {key: when they last grew}."""
    from . import core
    nid = node["node_id"]
    prev = {x.get("key"): x for x in old["listeners"] if isinstance(x, dict)}
    seen = dict(old.get("saturated") or {})
    for x in new:
        key = x.get("key")
        if not isinstance(key, str):
            continue
        ref = ((x.get("conns") or {}).get("refused") or {}) if isinstance(x.get("conns"), dict) else {}
        pref = (((prev.get(key) or {}).get("conns") or {}).get("refused") or {}) if key in prev else None
        grew = pref is not None and any(_num(ref.get(k)) > _num(pref.get(k)) for k in ("cap", "per_ip"))
        if grew:
            seen[key] = t
            core._alert(db, f"listener_saturated:{key}", nid,
                        f"{node['hostname']}: {key} refuses connections at its caps ({_num(ref.get('cap')):g} for the "
                        f"listener cap, {_num(ref.get('per_ip')):g} per address so far)")
    for key, at in list(seen.items()):
        if t - at >= SATURATED_QUIET_S or key not in {x.get("key") for x in new}:
            core._resolve_alert(db, f"listener_saturated:{key}", nid)
            seen.pop(key)
    return seen


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def _result(x: dict) -> str | None:
    r = x.get("reachability")
    return r.get("result") if isinstance(r, dict) else None


def _reachability_alerts(db, node: dict, old: list, new: list) -> None:
    """listener_unreachable (P3, pending 10 minutes): the doctor's result for a listener is one the owner must fix;
    it clears when the result no longer is (REACHABLE, or the listener is gone)."""
    from . import core
    nid = node["node_id"]
    keys = set()
    for x in new:
        key = x.get("key")
        if not isinstance(key, str):
            continue
        keys.add(key)
        res = _result(x)
        if res in UNREACHABLE_RESULTS:
            text = (x.get("reachability") or {}).get("text") or res
            core._alert(db, f"listener_unreachable:{key}", nid, f"{node['hostname']}: {key} {res}: {text}"[:500])
        else:
            core._resolve_alert(db, f"listener_unreachable:{key}", nid)
    for x in old:
        if isinstance(x.get("key"), str) and x["key"] not in keys:
            core._resolve_alert(db, f"listener_unreachable:{x['key']}", nid)


# ------------------------------------------------------------------ probes (D49)

def facts_of(node: dict) -> dict:
    f = jl(node.get("facts_json"), {}) or {}
    return f.get("listeners") if isinstance(f.get("listeners"), dict) else {}


def supports(node: dict) -> bool:
    v = facts_of(node).get("version")
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def can_probe(node: dict) -> bool:
    return supports(node) and facts_of(node).get("probe") is True


def node_public(node: dict) -> str | None:
    """The node's public IPv4 or IPv6 address as far as anyone knows: its router's external address, the address it was
    observed from, else what its agent reports observing (a STUN check)."""
    net = report(node)["network"]
    return public_ip(net.get("gateway_external")) or public_ip(node.get("observed_addr")) or public_ip(net.get("observed"))


def _online(node: dict | None, t: float) -> bool:
    return bool(node and node.get("last_heartbeat_at") and t - node["last_heartbeat_at"] < C.OFFLINE_AFTER)


def pick_prober(db, target: dict, target_addr: str | None, exclude=(), t: float | None = None) -> dict | None:
    """An online node other than the target whose agent can dial probes: first one whose public address is known and
    differs from the target's (the probe really comes from outside), else one whose address is unknown (the target
    tells when a probe came from its own network). A node known to share the target's address never dials it."""
    t = clock.now() if t is None else t
    mine = {a for a in (target_addr, node_public(target)) if a}
    known, unknown = [], []
    for n in db.q("SELECT * FROM nodes WHERE lifecycle NOT IN ('retired','quarantined') AND node_id!=? ORDER BY node_id",
                  (target["node_id"],)):
        if n["node_id"] in exclude or not _online(n, t) or not can_probe(n):
            continue
        a = node_public(n)
        if a and a not in mine:
            known.append(n)
        elif not a:
            unknown.append(n)
    return (known or unknown or [None])[0]


def _listener_report(node: dict, key: str) -> dict | None:
    return next((x for x in report(node)["listeners"] if x.get("key") == key), None)


def schedule(db, node_id: str, key: str, now: float | None = None, listener: dict | None = None,
             force: bool = False) -> dict:
    """Create a dial-back probe of a node's listener at the external address its router reported, unless one was made
    within the minute (`force` does not lift that). No prober: the outcome is `no_prober` at once."""
    t = clock.now() if now is None else now
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node_id,))
    if not node:
        raise ListenerError(f"unknown node {node_id}", 404, "not_found")
    x = listener or _listener_report(node, key)
    if x is None:
        raise ListenerError(f"{node['hostname']} reports no listener {key}", 409, "listener_not_reported")
    hp = split_hostport(x.get("external"))
    if hp is None:
        raise ListenerError(f"{node['hostname']} has no external address for {key} yet (its router has not mapped it)",
                            409, "no_external_address")
    last = db.one("SELECT probe_id, state, created_at FROM listener_probes WHERE node_id=? AND key=? AND tried_json='[]' "
                  "ORDER BY created_at DESC LIMIT 1", (node_id, key))
    if last and t - last["created_at"] < PROBE_EVERY_S:
        raise ListenerError(f"{key} on {node['hostname']} was probed {t - last['created_at']:.0f} s ago: at most one probe "
                            "a minute per listener", 429, "probe_rate_limited")
    return _create(db, node, key, hp, t, [])


def _create(db, node: dict, key: str, hp: tuple, t: float, tried: list) -> dict:
    prober = pick_prober(db, node, public_ip(hp[0]), exclude=tried, t=t)
    pid, nonce = secrets.token_hex(16), secrets.token_hex(16)
    if prober is None:
        db.x("INSERT INTO listener_probes(probe_id,node_id,key,host,port,nonce,prober,via,state,detail,created_at,done_at,"
             "tried_json) VALUES(?,?,?,?,?,?,NULL,NULL,'no_prober',?,?,?,?)",
             (pid, node["node_id"], key, hp[0], hp[1], nonce, "no other online node can dial it" if not tried
              else "every other prober is on the same network", t, t, json.dumps(tried)))
        return {"probe_id": pid, "state": "no_prober", "prober": None}
    via = f"fleet:{prober['node_id']}"
    db.x("INSERT INTO listener_probes(probe_id,node_id,key,host,port,nonce,prober,via,state,detail,created_at,tried_json)"
         " VALUES(?,?,?,?,?,?,?,?,'pending',NULL,?,?)",
         (pid, node["node_id"], key, hp[0], hp[1], nonce, prober["node_id"], via, t, json.dumps(tried)))
    db.event("listener_probe", node_id=node["node_id"], reason=f"{key} at {hp[0]}:{hp[1]} by {prober['hostname']}")
    return {"probe_id": pid, "state": "pending", "prober": prober["node_id"]}


def record_result(db, reporter: str, r: dict, t: float) -> None:
    """A `probe_results` entry: only the probe's prober may report success; the prober or the target may report a
    failure. `same_network` (the target saw the probe come from its own network) tries another prober once."""
    pid = r.get("probe_id")
    if not isinstance(pid, str):
        return
    p = db.one("SELECT * FROM listener_probes WHERE probe_id=? AND state='pending'", (pid,))
    if not p or reporter not in (p["prober"], p["node_id"]):
        return
    ok, detail = r.get("ok") is True, (str(r["detail"])[:300] if r.get("detail") is not None else None)
    if ok and reporter != p["prober"]:
        return
    if ok:
        rtt = r.get("rtt_ms")
        detail = detail or (f"rtt {float(rtt):.0f} ms" if isinstance(rtt, (int, float)) and not isinstance(rtt, bool) else None)
        _finish(db, p, "reachable", detail, t)
        return
    if detail == "same_network":
        _finish(db, p, "retried", detail, t)
        tried = json.loads(p["tried_json"] or "[]") + [p["prober"]]
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (p["node_id"],))
        if node and len(tried) < 2:
            _create(db, node, p["key"], (p["host"], p["port"]), t, tried)
        elif node:
            db.x("INSERT INTO listener_probes(probe_id,node_id,key,host,port,nonce,prober,via,state,detail,created_at,"
                 "done_at,tried_json) VALUES(?,?,?,?,?,?,NULL,NULL,'no_prober',?,?,?,?)",
                 (secrets.token_hex(16), p["node_id"], p["key"], p["host"], p["port"], secrets.token_hex(16),
                  "every prober tried is on the same network", t, t, json.dumps(tried)))
        return
    _finish(db, p, "unreachable", detail, t)


def _finish(db, p: dict, state: str, detail, t: float) -> None:
    db.x("UPDATE listener_probes SET state=?, detail=?, done_at=? WHERE probe_id=?", (state, detail, t, p["probe_id"]))
    if state != "retried":
        db.event("listener_probe_done", node_id=p["node_id"], reason=f"{p['key']}: {state}" + (f" ({detail})" if detail else ""))


def expire_probes(db, t: float) -> int:
    """Probes nobody answered within 60 s: `unreachable` when the prober was online (it should have reported),
    `no_prober` when it went away."""
    n = 0
    for p in db.q("SELECT * FROM listener_probes WHERE state='pending' AND created_at<?", (t - PROBE_TTL_S,)):
        prober = db.one("SELECT node_id, last_heartbeat_at FROM nodes WHERE node_id=?", (p["prober"],))
        if _online(prober, t):
            _finish(db, p, "unreachable", "expired", t)
        else:
            _finish(db, p, "no_prober", "the prober went offline", t)
        n += 1
    return n


def reachability(db, node_id: str) -> dict:
    """{key: {state, at, via, detail}}: the outcome of the latest finished probe of each of the node's listeners."""
    out = {}
    for p in db.q("SELECT key, state, done_at, via, detail FROM listener_probes WHERE node_id=? "
                  "AND state IN ('reachable','unreachable','no_prober') ORDER BY done_at", (node_id,)):
        out[p["key"]] = {"state": p["state"], "at": p["done_at"], "via": p["via"], "detail": p["detail"]}
    return out


# ------------------------------------------------------------------ directives

def disabled(db, node: dict) -> bool:
    return bool(db.get_state(FLEET_DISABLED, False)) or bool(node.get("listeners_disabled"))


def directives(db, node: dict) -> dict:
    """The heartbeat reply's listener directives (docs/design/inbound-listeners.md, "Protocol"): the kill switch, the
    dial-backs to expect and to make, the latest probe outcomes, the node's public source address (only when public)
    and whether to send the top talkers once."""
    nid, t = node["node_id"], clock.now()
    out = {"listeners_disabled": disabled(db, node),
           "listener_probes": [{"probe_id": p["probe_id"], "key": p["key"], "nonce": p["nonce"],
                                "expires_at": p["created_at"] + PROBE_TTL_S}
                               for p in db.q("SELECT probe_id, key, nonce, created_at FROM listener_probes "
                                             "WHERE node_id=? AND state='pending'", (nid,))],
           "dial_probes": [{"probe_id": p["probe_id"], "host": p["host"], "port": p["port"], "nonce": p["nonce"]}
                           for p in db.q("SELECT probe_id, host, port, nonce FROM listener_probes "
                                         "WHERE prober=? AND state='pending'", (nid,))],
           "listener_reachability": reachability(db, nid),
           "send_listener_talkers": bool((node.get("want_talkers_until") or 0) > t)}
    obs = public_ip(node.get("observed_addr"))
    if obs:
        out["observed_addr"] = obs
    return out


def want_talkers(db, node_id: str, now: float | None = None) -> None:
    """An operator looks at a listener: the next replies ask the node for its top talkers (for 10 minutes)."""
    t = clock.now() if now is None else now
    db.x("UPDATE nodes SET want_talkers_until=? WHERE node_id=?", (t + TALKERS_TTL_S, node_id))


def talkers(node: dict, key: str, now: float | None = None) -> list | None:
    t = clock.now() if now is None else now
    if not node.get("listener_talkers_at") or t - node["listener_talkers_at"] > TALKERS_TTL_S:
        return None
    return (jl(node.get("listener_talkers_json"), {}) or {}).get(key)


# ------------------------------------------------------------------ what people read (detail, console, CLI, explain)

def node_doc(r, n: dict, manifest_for_=None, now: float | None = None) -> dict:
    """The node's listeners, router mappings, network view and reachability (detail.node, the node page's Network card,
    `oarbank listener list|show|mappings`): per configured or reported key, the owner's entry, the statement's, what
    the agent reports and the latest probe; pure over a reader."""
    from . import statements
    t = clock.now() if now is None else now
    nid = n["node_id"]
    rep = report(n)
    cfg = (r.get_state(CONFIG, {}) or {}).get(nid) or {}
    st = statements.statements(r).get(nid) or {}
    signed = (json.loads(st["statement"]).get("listeners") or {}) if st else {}
    reach = {}
    for p in r.q("SELECT key, state, done_at, via, detail, prober, created_at FROM listener_probes WHERE node_id=? "
                 "ORDER BY created_at", (nid,)):
        if p["state"] in ("reachable", "unreachable", "no_prober"):
            reach[p["key"]] = {"state": p["state"], "at": p["done_at"], "via": p["via"], "detail": p["detail"]}
        elif p["state"] == "pending":
            reach.setdefault(p["key"], {})
            reach[p["key"]] = {**reach[p["key"]], "pending": {"via": p["via"], "since": p["created_at"]}}
    reported = {x.get("key"): x for x in rep["listeners"] if isinstance(x.get("key"), str)}
    rows = []
    for key in sorted(set(cfg) | set(reported) | set(signed)):
        x = reported.get(key) or {}
        ra = x.get("reachability") if isinstance(x.get("reachability"), dict) else {}
        conns = x.get("conns") if isinstance(x.get("conns"), dict) else {}
        maps = [m for m in rep["portmaps"] if m.get("key") == key]
        rows.append({"key": key, "configured": cfg.get(key), "statement": signed.get(key), "reported": bool(x),
                     "state": x.get("state"), "refused": x.get("refused"), "detail": x.get("detail"),
                     "statement_seq": x.get("statement_seq"), "bind": x.get("bind"), "bind_v6": x.get("bind_v6"),
                     "external": x.get("external"), "external_v6": x.get("external_v6"),
                     "announced": x.get("announced"), "since": x.get("since"),
                     "result": ra.get("result"), "flags": list(ra.get("flags") or []), "text": ra.get("text"),
                     "fix": ra.get("fix"), "checked_via": ra.get("via"), "checked_at": ra.get("at"),
                     "conns": {"open": conns.get("open"), "accepted": conns.get("accepted"),
                               "bytes_in": conns.get("bytes_in"), "bytes_out": conns.get("bytes_out"),
                               "refused": dict(conns.get("refused") or {}) if isinstance(conns.get("refused"), dict) else {}},
                     "portmaps": maps, "probe": reach.get(key), "talkers": talkers(n, key, t)})
    hb = n.get("last_heartbeat_at") or 0
    return {"node_id": nid, "hostname": n.get("hostname"), "online": bool(hb and t - hb < C.OFFLINE_AFTER),
            "supported": supports(n), "can_probe": can_probe(n),
            "disabled": {"node": bool(n.get("listeners_disabled")), "fleet": bool(r.get_state(FLEET_DISABLED, False))},
            "listeners": rows, "portmaps": rep["portmaps"], "network": rep["network"],
            "reachability": {k: {x: v[x] for x in ("state", "at", "via", "detail")} for k, v in reach.items() if "state" in v},
            "router_mappings": list(rep["network"].get("router_mappings") or []),
            "observed_addr": n.get("observed_addr"), "reported_at": n.get("listeners_at"),
            "statement_seq": st.get("seq") if st else None, "statement_signed": bool(st and st.get("signature"))}


def fleet_doc(r, node: str | None = None, now: float | None = None) -> dict:
    """GET /api/v1/listeners: every node's document (or one node's)."""
    t = clock.now() if now is None else now
    rows = r.q("SELECT * FROM nodes WHERE lifecycle!='retired' AND (? IS NULL OR node_id=? OR hostname=?) ORDER BY hostname",
               (node, node, node))
    docs = [node_doc(r, n, now=t) for n in rows]
    return {"nodes": [d for d in docs if d["listeners"] or d["portmaps"] or d["router_mappings"] or node],
            "fleet_disabled": bool(r.get_state(FLEET_DISABLED, False))}


def module_rows(r, module: str, now: float | None = None) -> list[dict]:
    """The module page's listeners: per node, each of the module's listeners with its state and reachability."""
    out = []
    for n in r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"):
        d = node_doc(r, n, now=now)
        for x in d["listeners"]:
            if x["key"].split("/", 1)[0] == module:
                out.append({"node_id": d["node_id"], "hostname": d["hostname"], "online": d["online"], **x})
    return out


def explain_rows(n: dict) -> list[dict]:
    """Node explain's listener conditions: [{code, detail}] for each listener the agent refused (LISTENER_UNAVAILABLE)
    and each doctor result the owner must fix."""
    out = []
    for x in report(n)["listeners"]:
        key = x.get("key")
        if not isinstance(key, str):
            continue
        if x.get("state") == "refused" and x.get("refused"):
            out.append({"code": "LISTENER_UNAVAILABLE", "detail": {"listener": key, "why": x.get("refused"),
                                                                   "detail": x.get("detail")}})
        res = _result(x)
        if res in EXPLAIN_RESULTS:
            ra = x.get("reachability") or {}
            out.append({"code": res, "detail": {"listener": key, "text": ra.get("text"), "fix": ra.get("fix")}})
    return out


def retire_warning(db, node_id: str) -> str | None:
    """The retire preview's warning: an offline node with router mappings cannot release them."""
    n = db.one("SELECT * FROM nodes WHERE node_id=?", (node_id,))
    if not n or not report(n)["portmaps"] or _online(n, clock.now()):
        return None
    return (f"router mappings may persist until their lease expires ({len(report(n)['portmaps'])} held by "
            f"{n['hostname']}, which is offline and cannot release them)")


# ------------------------------------------------------------------ invariant S24

def s24_violations(db) -> list[str]:
    """S24: every listener and router mapping a node reports belongs to an approved grant (the module version the node
    runs requests that inbound listener; its grants are approved by digest), an assignment (the node's statement lists
    it) and the statement the node applied: the key is in the statement whose seq the report names, or in the current
    statement."""
    from . import statements
    rows = db.q("SELECT node_id, listeners_json FROM nodes WHERE lifecycle!='retired' AND listeners_json IS NOT NULL")
    if not rows:
        return []
    sts, hist = statements.statements(db), db.get_state(HISTORY, {}) or {}
    out = []
    for n in rows:
        nid = n["node_id"]
        rep = report(n)
        cur = sts.get(nid)
        cur_seq = cur["seq"] if cur else 0
        cur_keys = set((json.loads(cur["statement"]).get("listeners") or {}) if cur else {})
        open_ = [(x.get("key"), x.get("statement_seq"), "listener") for x in rep["listeners"]
                 if x.get("state") in ("listening", "held")]
        maps = [(m.get("key"), None, "router mapping") for m in rep["portmaps"]
                if m.get("state") not in ("removed", "released")]
        seqs = {x.get("key"): x.get("statement_seq") for x in rep["listeners"]}
        for key, seq, what in open_ + maps:
            if not isinstance(key, str):
                out.append(f"S24 node {nid} reports a {what} without a key")
                continue
            if not granted(db, nid, key):
                out.append(f"S24 node {nid} reports {what} {key}, which no approved grant of the module version it runs covers")
                continue
            seq = seq if seq is not None else seqs.get(key)
            if isinstance(seq, int) and not isinstance(seq, bool) and seq > cur_seq:
                out.append(f"S24 node {nid} reports {what} {key} under statement {seq}, above the latest issued ({cur_seq})")
                continue
            applied = set((hist.get(nid) or {}).get(str(seq)) or []) if isinstance(seq, int) else set()
            if key not in cur_keys and key not in applied:
                out.append(f"S24 node {nid} reports {what} {key}, which neither its current statement (seq {cur_seq}) nor "
                           f"the statement it applied (seq {seq}) assigns")
    return out
