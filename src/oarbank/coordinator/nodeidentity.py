"""Which node a pending enrollment is (docs/design/node-enrollment.md, "Re-enrolment").

A node is its key (D29, D25): the P-256 key its agent generated, which never leaves the machine. The Tailscale binding
in core._node_checks is an extra that refuses a certificate presented from another tailnet device, so a key copied off
a node cannot be used elsewhere. When a machine is re-added to the tailnet (a tag applied in the admin console, a
re-login) it becomes a new Tailscale device with a new StableID and address, the binding refuses its certificate, and
its agent enrolls again with a CSR for the same key.

That request proves the node: a CSR's signature verifies only with the private key, and its public key is the one the
node's current (or, while renewing, previous) certificate was issued for. Approving it keeps the node's id, and with it
every node-scoped setting (paused, per-node module switches, caps, protection, labels and groups) and its history; the
node is re-pinned to the new Tailscale device. The owner still approves it (a multi-use join code that approves
automatically does not), since a copied key and a re-added machine look the same to the coordinator.

A request that does not prove a node but reports a known node's host name is a machine that lost its key (reinstalled,
or a different machine with the same name). Approving it makes a new node; the preview says so, and that the old node's
settings will not apply, and offers retiring the old record, or, when the owner knows it is the same machine, carrying
the old node's settings over and retiring it in the approval (admission.py, `adopt_settings_from`).

These functions only read (`r` is the coordinator DB or the console's reader).
"""
from . import clock, config as C, tlsca
from .db import jl


def proven_node(r, csr_pem: str | None) -> dict | None:
    """The node, not retired, whose current or previous certificate was issued for the key that signed this CSR."""
    k = tlsca.key_of_csr(csr_pem or "")
    if not k:
        return None
    return r.one("SELECT * FROM nodes WHERE lifecycle!='retired' AND (client_key_sha256=? OR client_key_prev_sha256=?) "
                 "ORDER BY client_key_sha256=? DESC LIMIT 1", (k, k, k))


def _hw(facts: dict) -> tuple:
    facts = facts or {}
    plat, cpu = facts.get("platform") or {}, facts.get("cpu") or {}
    return plat.get("os"), plat.get("arch"), cpu.get("model"), facts.get("memory_gb")


def _host(name: str | None) -> str:
    return (name or "").strip().split(".")[0].casefold()


def lookalikes(r, e: dict, exclude: set) -> list[dict]:
    """Known nodes (not retired, not in `exclude`) whose reported host name is the enrollment's: [{node_id, hostname,
    same_hardware, offline}]."""
    want = _host(e.get("hostname"))
    if not want:
        return []
    mine = _hw(jl(e.get("facts_json"), {}))
    out = []
    for n in r.q("SELECT node_id, hostname, facts_json, last_heartbeat_at FROM nodes WHERE lifecycle!='retired'"):
        if n["node_id"] in exclude:
            continue
        facts = jl(n["facts_json"], {}) or {}
        if want not in {_host(facts.get("hostname")), _host(n["hostname"])}:
            continue
        theirs = _hw(facts)
        out.append({"node_id": n["node_id"], "hostname": n["hostname"],
                    "same_hardware": all(theirs) and theirs == mine, "last_heartbeat_at": n["last_heartbeat_at"]})
    return out


def of_enrollment(r, e: dict) -> dict:
    """What approving this enrollment does to node identity:
    {node_id: the node it keeps (None: a new node), via: "node_key"|"tailscale"|None, ts_changed: bool,
     old_ts_node_id, lookalikes: [...] (only when it becomes a new node)}."""
    node = proven_node(r, e.get("csr_pem"))
    via = "node_key" if node else None
    if not node and e.get("ts_node_id"):
        node = r.one("SELECT * FROM nodes WHERE ts_node_id=?", (e["ts_node_id"],))
        via = "tailscale" if node else None
    ts_changed = bool(node and via == "node_key" and e.get("ts_node_id") and node["ts_node_id"]
                      and node["ts_node_id"] != e["ts_node_id"])
    hb = node["last_heartbeat_at"] if node else None
    return {"node_id": node["node_id"] if node else None, "hostname": node["hostname"] if node else None, "via": via,
            "ts_changed": ts_changed, "old_ts_node_id": node["ts_node_id"] if node else None,
            "online": bool(hb and clock.now() - hb < C.OFFLINE_AFTER),
            "lookalikes": [] if node else lookalikes(r, e, set())}


def impact(r, e: dict | None) -> dict:
    """The approval preview's identity rows (contracts/impact.py renders them in the console and the CLI)."""
    if not e:
        return {}
    i = of_enrollment(r, e)
    if i["node_id"]:
        how = ("it proves the node's own key" if i["via"] == "node_key" else "the same Tailscale device")
        out = {"re_enrolment_of": f"{i['hostname']} ({i['node_id']}): {how}; it keeps the node id, its settings "
                                  f"(paused, module switches, caps, protection, labels, groups) and its history"}
        if i["ts_changed"]:
            out["tailscale_device_changed"] = (f"{i['old_ts_node_id']} -> {e.get('ts_node_id')}: approve only if this "
                                               f"machine was re-added to the tailnet")
            if i["online"]:
                out["warning"] = (f"{i['hostname']} is still online from its own Tailscale device: this request holds "
                                  f"its key from another one; reject it unless you moved the node yourself")
        return out
    if not i["lookalikes"]:
        return {"new_node": True}
    names = ", ".join(f"{n['hostname']} ({n['node_id']}{', same hardware' if n['same_hardware'] else ''})"
                      for n in i["lookalikes"])
    return {"new_node": True,
            "warning": (f"looks like {names} but does not prove that node's key: approving makes a NEW node, and the "
                        f"old node's settings (paused, module switches, caps, protection, labels, groups) do NOT apply "
                        f"to it"),
            "old_record": [f"retire {n['node_id']} once the new node runs: oarbank op nodes.retire {n['node_id']} "
                           f"(or Retire on the waiting card); if it is the same machine, carry its settings over and "
                           f"retire it in the approval: oarbank node approve {e.get('enrollment_id')} "
                           f"--adopt-settings-from {n['node_id']}" for n in i["lookalikes"]]}
