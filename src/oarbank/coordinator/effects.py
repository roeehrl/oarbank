"""Effects (UI contract 1, D22/D23): the only way module code changes core state.

A module's op.apply or campaign.tick returns effects; oarbankd validates each against what the module
declared and what it owns (its own campaigns, jobs, store and settings), then applies them on the
single writer inside the caller's transaction, together with the audit row. Nothing here calls a module.
"""
import json
import re

from oarbank_sdk import effects as fx

from . import modcalls, clock, core, modimages, placement
from .db import DB, jl

CAMPAIGN_ID = re.compile(r"^[a-z][a-z0-9_]{3,40}$")
# a job key is what oarbank_sdk.keys.job_key returns (spec/envelopes.md `job_key`): the sha256 hex digest of the canonical
# {module, compat, inputs}, then `:<stage>` for a staged job; the result cache, replica sampling and chain stage keys
# (`<key>:<stage>`) rely on it
JOB_KEY = re.compile(rf"[0-9a-f]{{64}}(:{fx.STAGE.pattern})?")
STORE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
MAX_JOBS_PER_EFFECT = 5000


class EffectError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def _own_campaign(db: DB, module: str, cid: str) -> dict:
    c = db.one("SELECT * FROM campaigns WHERE campaign_id=?", (cid,))
    if not c:
        raise EffectError(404, "unknown_campaign", cid)
    if c["module"] != module:
        raise EffectError(403, "not_owner", f"campaign {cid} belongs to {c['module']}")
    return c


def settings_key(module: str) -> str:
    return f"module_settings:{module}"


def enqueue(db: DB, module: str, campaign: dict, jobs: list[dict]) -> dict:
    """Insert a module's planned jobs into its campaign. Same (key, labels) twice is a no-op; each job joins its unit
    of work (placement.assign); a canonical result for the key the job may reuse makes it done at once (the result
    cache, filtered by the unit's class); a job that names no stage expands into the chain when the pipeline is split,
    one that names a stage runs exactly that stage. Raises PlacementError for a job no class can run with its unit, or a
    stage that is not a standalone stage."""
    created = cached = skipped = 0
    for j in jobs:
        key, spec = j["job_key"], dict(j["spec"] or {})
        # envelope fields may come on the item or inside the spec; jobs store them flat in the spec
        for k in ("mounts", "timeout_s"):
            if j.get(k) is not None:
                spec[k] = j[k]
        datasets = j.get("datasets") or spec.get("datasets") or []
        stage = placement.check_stage(module, j)
        # what the job reserves: the item's, else the manifest's for its stage (none named: the default stage)
        resources = j.get("resources") or spec.get("resources") or modcalls.info(module).stage_resources(stage)
        labels = json.dumps(j.get("labels") or {}, sort_keys=True)
        if db.one("SELECT 1 FROM jobs WHERE campaign_id=? AND job_key=? AND labels_json=? AND state!='cancelled'",
                  (campaign["campaign_id"], key, labels)):
            skipped += 1
            continue
        target = j.get("target_node")
        group, plats = placement.check_item(module, j)
        try:
            images = modimages.check_job_images(modcalls.info(module).manifest, stage, j.get("images"))
        except modimages.ImageRefused as e:
            raise EffectError(e.status, e.code, e.detail)
        jid = db.x("INSERT INTO jobs(job_key,campaign_id,labels_json,dataset_id,kind,target_node,priority,subpriority,state,"
                   "spec_json,datasets_json,created_at,module,resources_json,name,spec_version,platforms_json,group_key,stage,"
                   "images_json) VALUES(?,?,?,?,'eval',?,?,?,'pending',?,?,?,?,?,?,?,?,?,?,?)",
                   (key, campaign["campaign_id"], labels, j.get("dataset_id"), target,
                    int(campaign["priority"] or 0) + int(j.get("priority") or 0), int(j.get("subpriority") or 0),
                    json.dumps(spec), json.dumps(datasets), clock.now(), module, json.dumps(resources), j.get("name"),
                    int(j.get("spec_version") or 1), json.dumps(plats) if plats else None, group, stage,
                    json.dumps(images) if images else None))
        placement.assign(db, jid)
        # the result cache is scoped to the module (another module's key never satisfies this one) and to the job's unit
        hit = None if target else placement.cache_hit(db, db.one("SELECT * FROM jobs WHERE job_id=?", (jid,)))
        if hit:
            db.x("UPDATE jobs SET state='done', canonical_result_id=?, done_at=? WHERE job_id=?", (hit, clock.now(), jid))
            cached += 1
        else:
            created += 1
            core.expand_pipeline(db, jid)
    return {"created": created, "cached": cached, "skipped": skipped}


def apply(db: DB, module: str, allowed: set, effects: list[dict], actor: str = "system") -> list[dict]:
    """Apply effects in order (inside the caller's db.tx()). Returns a compact record for the audit row."""
    done = []
    try:
        for e in effects:
            done.append(_apply_one(db, module, allowed, e, actor))
    except placement.PlacementError as pe:
        raise EffectError(pe.status, pe.code, pe.detail)
    return done


def _apply_one(db: DB, module: str, allowed: set, e: dict, actor: str) -> dict:
    """One effect, validated and applied; a compact record of it."""
    kind, a = e.get("kind"), e.get("args") or {}
    if kind not in allowed:
        raise EffectError(502, "undeclared_effect", f"{module} asked for {kind!r}, which it did not declare")
    rec = {"kind": kind}
    if kind == "module_settings.update":
        cur = db.get_setting(settings_key(module), {}) or {}
        db.set_setting(settings_key(module), {**cur, **a})
        rec["keys"] = sorted(a)
    elif kind == "campaigns.create":
        cid = a.get("campaign_id", "")
        if not CAMPAIGN_ID.match(cid):
            raise EffectError(422, "bad_campaign_id", f"{cid!r} (a lowercase letter, then 3-40 of [a-z0-9_])")
        if db.one("SELECT 1 FROM campaigns WHERE campaign_id=?", (cid,)):
            raise EffectError(409, "campaign_exists", cid)
        pol = placement.campaign_policy(module, a.get("placement"))      # stricter than the manifest's, never looser
        db.x("INSERT INTO campaigns(campaign_id,module,name,state,priority,weight,labels_json,created_by,created_at,placement_json)"
             " VALUES(?,?,?,'running',?,?,?,?,?,?)",
             (cid, module, str(a.get("name") or cid)[:120], int(a.get("priority") or 0), float(a.get("weight") or 1.0),
              json.dumps(a.get("labels") or {}), actor, clock.now(), json.dumps(pol) if pol else None))
        db.event("campaign_created", actor=actor, campaign_id=cid, reason=f"{module}: {a.get('name') or cid}", module=module)
        if pol and pol["unit"] == "campaign":
            placement.open_campaign_unit(db, module, cid, pol)        # pinned now, or bound by capacity
        rec["campaign_id"] = cid
    elif kind == "campaigns.update":
        c = _own_campaign(db, module, a.get("campaign_id", ""))
        state = a.get("state", c["state"])
        if state not in ("running", "paused", "done") or c["state"] == "cancelled":
            raise EffectError(422, "bad_state", f"{c['campaign_id']}: {c['state']} -> {state}")
        if state == "done" and db.one("SELECT 1 FROM jobs WHERE campaign_id=? AND state IN ('pending','leased')",
                                      (c["campaign_id"],)):
            # decided on a stale snapshot (work was added meanwhile, e.g. by an operation): not done yet
            state, rec["deferred"] = c["state"], True
        labels = {**(jl(c["labels_json"], {}) or {}), **(a.get("labels") or {})}
        db.x("UPDATE campaigns SET state=?, name=?, priority=?, weight=?, labels_json=?, finished_at=? WHERE campaign_id=?",
             (state, str(a.get("name") or c["name"])[:120], int(a.get("priority", c["priority"]) or 0),
              float(a.get("weight", c["weight"]) or 1.0), json.dumps(labels),
              clock.now() if state == "done" and c["state"] != "done" else (None if state != "done" else c["finished_at"]),
              c["campaign_id"]))
        if state != c["state"]:
            db.event("campaign_" + state, actor=actor, campaign_id=c["campaign_id"], reason=a.get("message"))
            if state == "done":
                from . import notify
                notify.send(db, "Oarbank: campaign finished", f"{c['name']}: {a.get('message') or 'done'}"[:300])
        rec.update(campaign_id=c["campaign_id"], state=state)
    elif kind == "campaigns.cancel":
        c = _own_campaign(db, module, a.get("campaign_id", ""))
        core.set_campaign_state(db, c["campaign_id"], "cancel", actor)
        rec["campaign_id"] = c["campaign_id"]
    elif kind == "jobs.enqueue":
        c = _own_campaign(db, module, a.get("campaign_id", ""))
        jobs = a.get("jobs") or []
        if len(jobs) > MAX_JOBS_PER_EFFECT:
            raise EffectError(422, "too_many_jobs", f"{len(jobs)} > {MAX_JOBS_PER_EFFECT}")
        for j in jobs:
            if not (isinstance(j.get("job_key"), str) and JOB_KEY.fullmatch(j["job_key"])):
                raise EffectError(422, "bad_job_key", f"{j.get('job_key')!r} is not a job key: keys.job_key(module_id, compat, "
                                                      "key_inputs[, stage]) gives 64 lowercase hex digits, then :<stage>")
        if c["state"] in ("cancelled",):
            raise EffectError(409, "campaign_cancelled", c["campaign_id"])
        if c["state"] == "done":
            db.x("UPDATE campaigns SET state='running', finished_at=NULL WHERE campaign_id=?", (c["campaign_id"],))
        rec.update(campaign_id=c["campaign_id"], **enqueue(db, module, c, jobs))
    elif kind == "jobs.cancel":
        n = 0
        for jid in a.get("job_ids") or []:
            j = db.one("SELECT module, state FROM jobs WHERE job_id=?", (int(jid),))
            if not j or j["module"] != module:
                raise EffectError(403, "not_owner", f"job {jid}")
            if j["state"] in ("pending", "leased"):
                core.cancel_job(db, int(jid), actor)
                n += 1
        rec["cancelled"] = n
    elif kind == "store.write":
        coll, key = a.get("collection", ""), str(a.get("key", ""))
        if not STORE_NAME.match(coll) or not key or len(key) > 200:
            raise EffectError(422, "bad_store_key", f"{coll}/{key}")
        doc = a.get("doc")
        if not isinstance(doc, dict):
            raise EffectError(422, "bad_store_doc", "doc must be an object")
        data = json.dumps(doc)
        if len(data) > 256 * 1024:
            raise EffectError(422, "doc_too_large", f"{len(data)} bytes")
        db.x("INSERT INTO module_store(module,collection,key,doc_json,updated_at) VALUES(?,?,?,?,?) "
             "ON CONFLICT(module,collection,key) DO UPDATE SET doc_json=excluded.doc_json, updated_at=excluded.updated_at",
             (module, coll, key, data, clock.now()))
        rec.update(collection=coll, key=key)
    elif kind == "store.delete":
        db.x("DELETE FROM module_store WHERE module=? AND collection=? AND key=?",
             (module, a.get("collection", ""), str(a.get("key", ""))))
        rec.update(collection=a.get("collection"), key=a.get("key"))
    elif kind == "datasets.create":
        rec.update(_datasets_create(db, module, a, actor))
    elif kind == "datasets.update":
        rec.update(_datasets_update(db, module, a, actor))
    elif kind == "datasets.delete":
        rec.update(_datasets_delete(db, module, a, actor))
    elif kind in ("files.write", "files.put", "files.delete"):
        from . import modfiles
        try:
            if kind == "files.write":
                r = modfiles.write(db, module, a.get("path"), a.get("content_b64"))
            elif kind == "files.put":
                r = modfiles.put(db, module, a.get("path"), str(a.get("digest") or ""))
            else:
                r = modfiles.delete(db, module, a.get("path"), a.get("prefix"))
        except modfiles.FileError as fe:
            raise EffectError(422, fe.code, fe.detail)
        rec.update({k: v for k, v in r.items() if k != "content_b64"})
    else:
        raise EffectError(501, "effect_not_implemented", str(kind))
    return rec


# ---------------------------------------------------------------------------- datasets (module protocol "Effects")

def _own_dataset(db: DB, module: str, did: str) -> dict:
    d = db.one("SELECT * FROM datasets WHERE dataset_id=?", (did,))
    if not d:
        raise EffectError(404, "unknown_dataset", did)
    if d["module"] != module:
        raise EffectError(403, "not_owner", f"dataset {did} belongs to {d['module'] or 'the operator'}")
    return d


def _datasets_create(db: DB, module: str, a: dict, actor: str) -> dict:
    """A dataset of a kind the module declares (short kinds: the owning module scopes them), every file with its digest
    and size: a blob the module can reach, or one its `origins` give (the coordinator need not hold it: nodes fetch it,
    and the coordinator only when every origin failed for a node). A pinned id only with its pinned contents. An existing
    id of the module's with the same kind, meta, files and platform is skipped; anything else fails."""
    from oarbank_sdk.origins import file_problem
    from . import blobstore, modfiles
    did, kind, meta = a.get("dataset_id", ""), a.get("kind"), a.get("meta") or {}
    kinds = modcalls.info(module).manifest.datasets.kinds
    if kind not in kinds:
        raise EffectError(422, "undeclared_kind", f"{did}: kind {kind!r} is not in [datasets].kinds {kinds}")
    files = []
    for f in a.get("files") or []:
        why = file_problem(f)
        if why:
            raise EffectError(422, "bad_dataset_file", f"{did}: {why}")
        files.append({"path": f["path"], "digest": f["digest"], "size": f["size"], **({"origins": list(f["origins"])} if f.get("origins") else {})})
    for f in files:
        b = db.one("SELECT size FROM blobs WHERE digest=?", (f["digest"],))
        if b and b["size"] is not None and b["size"] != f["size"]:
            raise EffectError(422, "size_mismatch", f"{did}: {f['path']} is {b['size']} bytes, not {f['size']}")
        if not f.get("origins") and (not b or not modfiles.visible_blob(db, module, f["digest"])):
            raise EffectError(422, "unknown_blob", f"{did}: {f['path']} ({f['digest']}): name origins for a blob the "
                              "coordinator does not hold")
    why = blobstore.check_origins(db, files)
    if why:
        raise EffectError(422, "origin_refused", f"{did}: {why}")
    plat = placement.dataset_platform(module, kind, a.get("platform"))
    pin = modcalls.info(module).manifest.datasets.pin(did)
    if pin is not None:                                 # a pinned id: only its pinned contents (bootstrap-stages.md)
        got = sorted(({k: f.get(k) for k in ("path", "digest", "size")} for f in files), key=lambda f: str(f["path"]))
        if (kind, got, plat) != (pin.kind, pin.dataset_files(), pin.platform) or (pin.meta and meta != pin.meta):
            raise EffectError(422, "pin_mismatch", f"{did} is pinned ([[datasets.pinned]]): it is registered only with its pinned "
                              "kind, files, platform and meta")
    ex = db.one("SELECT * FROM datasets WHERE dataset_id=?", (did,))
    if ex and ex["module"] != module:                   # never another module's or the operator's dataset
        raise EffectError(409, "dataset_owned", f"{did} belongs to {ex['module'] or 'the operator'}")
    if ex:
        if (ex["kind"], jl(ex["meta_json"], {}), jl(ex["files_json"], []), ex["platform"]) == (kind, meta, files, plat):
            return {"dataset_id": did, "skipped": True}  # a repeat: harmless
        raise EffectError(409, "dataset_exists", f"{did} exists with other contents: datasets.update changes its meta, and "
                          "new files need a new id")
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at,platform) VALUES(?,?,?,?,?,?,?)",
         (did, kind, module, json.dumps(meta), json.dumps(files), clock.now(), plat))
    db.event("dataset_imported", actor=actor, reason=did, module=module)
    return {"dataset_id": did}


def _datasets_update(db: DB, module: str, a: dict, actor: str) -> dict:
    """Merge `meta` into one of the module's datasets, key by key at the top level (None removes a key). Kind, files and
    platform never change: nodes stage a dataset's files by id."""
    did = a.get("dataset_id", "")
    fixed = sorted({"kind", "files", "platform"} & set(a))
    if fixed:
        raise EffectError(422, "dataset_immutable", f"{did}: {', '.join(fixed)} never change; new files need a new id")
    meta = a.get("meta")
    if not isinstance(meta, dict) or not meta:
        raise EffectError(422, "bad_dataset_meta", f"{did}: meta must be a non-empty object")
    d = _own_dataset(db, module, did)
    cur = jl(d["meta_json"], {}) or {}
    for k, v in meta.items():
        if v is None:
            cur.pop(k, None)
        else:
            cur[k] = v
    db.x("UPDATE datasets SET meta_json=? WHERE dataset_id=?", (json.dumps(cur), did))
    db.event("dataset_updated", actor=actor, reason=did, module=module)
    return {"dataset_id": did, "keys": sorted(meta)}


def _datasets_delete(db: DB, module: str, a: dict, actor: str) -> dict:
    """Remove one of the module's datasets (an unknown id is a no-op). Refused while open work names it, and for the
    host's artifact datasets, which stage chains and the result cache read. Blobs stay."""
    did = a.get("dataset_id", "")
    if not db.one("SELECT 1 FROM datasets WHERE dataset_id=?", (did,)):
        return {"dataset_id": did, "missing": True}
    d = _own_dataset(db, module, did)
    if d["kind"] == "artifact":
        raise EffectError(422, "host_dataset", f"{did} is a job's artifact dataset, which the host keeps")
    if db.one("SELECT 1 FROM jobs WHERE state IN ('pending','leased') AND (dataset_id=? OR EXISTS "
              "(SELECT 1 FROM json_each(jobs.datasets_json) WHERE value=?)) LIMIT 1", (did, did)):
        raise EffectError(409, "dataset_in_use", f"{did}: pending or leased jobs name it")
    db.x("DELETE FROM datasets WHERE dataset_id=?", (did,))
    db.event("dataset_deleted", actor=actor, reason=did, module=module)
    return {"dataset_id": did}
