"""Detail documents for one node and one job: what `oarbank node show` and `oarbank job show` print (through
GET /api/v1/nodes/{id} and /api/v1/jobs/{id}) and what the console's node and job pages render. The console calls them
on its own read connection (D10). One function per document, so the CLI and the console never say different
things (docs/design/console-parity.md).

Every function here is pure over a reader (q/one/get_setting): oarbankd's DB or the console's query-only pool. Module
manifests come from the caller (`manifest_for`), since only oarbankd holds the active versions in memory and the console
has the catalogue it fetched.
"""
from collections.abc import Callable

from . import checkpoints, folders, nodeservices, platforms
from . import config as C
from .db import jl


def gpu(facts: dict, doctor: dict | None) -> dict:
    """The GPU APIs the node's doctor reports (docs/protocol.md "Doctor"), with the evidence for each API (what was
    found, or why not), and how its containers get the GPU (the facts' `containers.gpu`): `cdi:<kind>` on Linux and
    Windows, `virtio-gpu:venus` on macOS with krunkit, else none."""
    g = (doctor or {}).get("gpu_apis")
    how = ((facts or {}).get("containers") or {}).get("gpu") or ""
    mechanism = f"{how[4:]} (CDI)" if how.startswith("cdi:") else "Venus over virtio-gpu (krunkit)" if how == "virtio-gpu:venus" else None
    return {"reported": g is not None, "host": list((g or {}).get("host") or []), "containers": list((g or {}).get("containers") or []),
            "evidence": dict((g or {}).get("evidence") or {}), "mechanism": mechanism}


def enforcement(facts: dict, mods: list[str], manifest_for: Callable) -> dict:
    """Per sandbox capability: what the node's backend does (`enforced`, `cooperative`, `unavailable`, or `not
    reported`), which of its modules need it, and which of those it therefore keeps out (`CAPABILITY_NOT_ENFORCED`)."""
    enf = platforms.enforcement(facts)
    need = {}
    for m in mods:
        man = manifest_for(m)
        for c in (platforms.sandbox_needs(man) if man else []):
            need.setdefault(c, []).append(m)
    rows = []
    for c in sorted(set(enf) | set(need)):
        state = enf.get(c, "not reported")
        rows.append({"capability": c, "state": state, "needed_by": sorted(need.get(c, [])),
                     "blocks": sorted(need.get(c, [])) if state != "enforced" else []})
    return {"backend": ((facts or {}).get("sandbox") or {}).get("backend"), "capabilities": rows}


def folder_grants(r, n: dict) -> list[dict]:
    """The folders mapped to the node (the folder registry), each with what the node's agent last reported applying,
    and whether the node's current folder statement carries the owner's signature."""
    nid, rep = n["node_id"], folders.report(n)
    stmt = folders.statements(r).get(nid) or {}
    out = []
    for fid, e in sorted(folders.registry(r).items()):
        if nid in (e.get("nodes") or {}):
            got = rep.get(fid) or {}
            out.append({"id": fid, "access": e.get("access"), "path": e["nodes"][nid], "status": got.get("status") or "not applied yet",
                        "statement_seq": stmt.get("seq"), "signed": bool(stmt.get("signature"))})
    out += [{"id": fid, "access": got.get("access"), "path": None, "status": got.get("status"), "statement_seq": stmt.get("seq"),
             "signed": bool(stmt.get("signature"))} for fid, got in sorted(rep.items()) if fid not in {x["id"] for x in out}]
    return out


def doctor(doc: dict | None) -> dict | None:
    """The latest doctor report, per module: its health and the checks that failed."""
    if not doc:
        return None
    mods = [{"module": m, "health": rep.get("health"), "checks": len(rep.get("checks") or []),
             "failed": [{"name": c.get("name"), "detail": c.get("detail")} for c in rep.get("checks") or [] if not c.get("ok")]}
            for m, rep in sorted((doc.get("modules") or {}).items())]
    return {"at": doc.get("at"), "release_id": doc.get("release_id"), "capabilities": list(doc.get("capabilities") or []),
            "modules": mods}


def node(r, nid: str, now: float, manifest_for: Callable[[str], object]) -> dict | None:
    """The node's detail document, by node id or hostname: `oarbank node show` prints it (GET /api/v1/nodes/{id}) and the
    console's node page renders its GPU API, enforcement and folder sections. `services` are the agent's per-service
    report (nodeservices.rows), the rows of the node page's Services table."""
    n = r.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
    if not n:
        return None
    facts, mods = jl(n["facts_json"], {}) or {}, jl(n.get("modules_json"), {}) or {}
    hb, doc = n["last_heartbeat_at"] or 0, jl(n["doctor_json"])
    return {
        "node": {"node_id": n["node_id"], "hostname": n["hostname"], "platform": platforms.node_platform(n),
                 "lifecycle": n["lifecycle"], "desired_state": n["desired_state"], "online": bool(hb and now - hb < C.OFFLINE_AFTER),
                 "agent_version": n.get("agent_version"), "quarantine_reason": n.get("quarantine_reason")},
        "modules": {m: {"state": st.get("state"), "reason": st.get("reason")} for m, st in sorted(mods.items())},
        "doctor": doctor(doc), "gpu": gpu(facts, doc), "containers": (facts.get("containers") or None),
        "services": nodeservices.rows(n), "services_at": n.get("services_at"), "folders": folder_grants(r, n),
        "sandbox": enforcement(facts, sorted(mods), manifest_for)}


def job(r, jid: int) -> dict | None:
    """The job's detail document (`oarbank job show`, the console's job page): the job, every attempt (and the
    checkpoint it resumed from), the checkpoint its next attempt resumes from, and its results."""
    j = r.one("SELECT * FROM jobs WHERE job_id=?", (jid,))
    if not j:
        return None
    atts = r.q("SELECT a.*, n.hostname FROM attempts a LEFT JOIN nodes n ON n.node_id=a.node_id WHERE a.job_id=? "
               "ORDER BY a.attempt_id", (jid,))
    for a in atts:
        a["resume"] = jl(a.pop("resume_json", None))
    ck = checkpoints.for_job(r, j)
    res = r.q("SELECT result_id, attempt_id, node_id, accepted, canonical, reason, value, digest, module_version, platform, at "
              "FROM results WHERE job_id=? ORDER BY result_id", (jid,))
    keys = ("job_id", "kind", "state", "module", "stage", "campaign_id", "dataset_id", "generation", "priority",
            "exec_failures", "expirations", "target_node", "created_at", "done_at", "depends_on")
    return {"job": {**{k: j[k] for k in keys}, "labels": jl(j["labels_json"], {}) or {},
                    "platforms": jl(j.get("platforms_json")) or None, "images": jl(j.get("images_json")) or []},
            "attempts": atts,
            "checkpoint": {**{k: ck[k] for k in ("attempt_id", "node_id", "seq", "digest", "size", "at")},
                           "files": len(jl(ck["files_json"], []))} if ck else None,
            "results": res}

