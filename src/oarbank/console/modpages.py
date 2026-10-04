"""Module pages in the console (PLAN D23, D41): the console's implementation of the published renderer's Host.

Reads only: host queries go through the console's read pool and are always filtered to the module's own rows (and,
for datasets, the operator's unowned ones of the module's kinds); module views are read from oarbankd's `module_views`
table (a module is never on the render path); operation metadata comes from oarbankd's registry (/api/v1/ops, cached),
so buttons show registry titles. No query selects a secret's value or ciphertext.

One link mapping (`link_url`) serves rendered links and the bridge's `navigate`; one operation check (`op_allowed`)
serves rendered buttons and the bridge's `request.operation`.
"""
import json
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from oarbank_sdk import manifest as mf, portable, ui as U
from oarbank_sdk.render import ROLE_RANK, Host, filter_params, interpolate, shape

from ..coordinator import folders as F, nodeservices, placement, platforms as P
from .views import OFFLINE_AFTER, gpu_view, jl


class ModuleCatalog:
    """Module bundles known to oarbankd (paths from /api/v1/modules), with manifests and pages loaded lazily."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self._man: dict[str, mf.Manifest] = {}

    def update(self, rows: list[dict]):
        self.rows = {r["name"]: r for r in rows}

    def manifest(self, name: str) -> mf.Manifest | None:
        r = self.rows.get(name)
        if not r or not r.get("path"):
            return None
        key = f"{name}@{r.get('version')}"
        if key not in self._man:
            self._man[key] = mf.load(Path(r["path"]) / "oarbank-module.toml")
        return self._man[key]

    def page(self, name: str, decl: U.PageDecl) -> U.Page:
        return U.Page.model_validate(json.loads((Path(self.rows[name]["path"]) / decl.file).read_text()))

    def path(self, name: str) -> Path:
        return Path(self.rows[name]["path"])


# ------------------------------------------------------------------------------------------ host queries

def _where(p: dict, cols: dict) -> tuple[str, list]:
    """' AND col=?' clauses for the params a query filters on (`cols`: param -> SQL column)."""
    keys = [k for k in cols if k in p]
    return "".join(f" AND {cols[k]}=?" for k in keys), [p[k] for k in keys]


def _online(n: dict, now: float) -> bool:
    return bool(n["last_heartbeat_at"] and now - n["last_heartbeat_at"] < OFFLINE_AFTER)


def _node_row(n: dict, module: str, man: mf.Manifest, now: float) -> dict:
    facts = jl(n["facts_json"], {}) or {}
    gpu = gpu_view(facts, jl(n["doctor_json"]))
    cont = facts.get("containers") or {}
    missing = [m for m in cont.get("missing") or [] if isinstance(m, dict)]
    svcs = nodeservices.rows(n, module)
    rep = F.report(n)
    mine = {f.id: rep.get(f.id) or {"access": f.access, "status": "not mapped on this node"} for f in man.sandbox.folders}
    enf = P.enforcement(facts)
    need = P.sandbox_needs(man)
    return {"node_id": n["node_id"], "hostname": n["hostname"], "lifecycle": n["lifecycle"], "desired_state": n["desired_state"],
            "last_heartbeat_at": n["last_heartbeat_at"], "online": _online(n, now),
            "module_state": (jl(n["modules_json"], {}) or {}).get(module, {}).get("state"),
            "platform": n["platform"], "os": n["os"], "arch": n["arch"], "os_version": n["os_version"],
            "gpu_apis_host": gpu["host"], "gpu_apis_containers": gpu["containers"], "container_gpu": gpu["mechanism"],
            "container_runtime": cont.get("runtime"), "container_state": cont.get("state"), "container_missing": missing,
            "container_fixes": [m.get("fix") for m in missing if m.get("fix")],
            "services": svcs, "service_health": ", ".join(f"{s['service']}: {s['state']}" + (f" ({s['stopped_reason']})"
                                                                                            if s["stopped_reason"] else "")
                                                           for s in svcs) or None,
            "folders": mine, "folders_ok": not F.missing(man, n),
            "enforcement": {c: enf.get(c, "unreported") for c in need}, "sandbox_gaps": [c for c in need if enf.get(c) != "enforced"]}


def _nodes(r, module, man, p, now):
    w, a = _where(p, {"node_id": "node_id"})
    return [_node_row(n, module, man, now) for n in
            r.q("SELECT * FROM nodes WHERE lifecycle!='retired'" + w + " ORDER BY hostname", tuple(a))]


def _datasets(r, module: str, man: mf.Manifest, p: dict) -> list[dict]:
    """The module's datasets and the operator's of its kinds (as host.datasets.query): never another module's."""
    kinds = list(man.datasets.kinds)
    w, a = _where(p, {"dataset_id": "dataset_id", "kind": "kind"})
    rows = r.q("SELECT dataset_id, kind, module, meta_json, files_json, created_at, platform FROM datasets WHERE "
               "(module=? OR ((module IS NULL OR module='') AND kind IN (%s)))" % (",".join("?" * len(kinds)) or "NULL") + w +
               " ORDER BY created_at DESC LIMIT 2000", (module, *kinds, *a))
    pinned = {x.dataset_id for x in man.datasets.pinned}
    out = []
    for d in rows:
        files = jl(d["files_json"], []) or []
        meta = {k: v for k, v in (jl(d["meta_json"], {}) or {}).items() if not isinstance(v, (dict, list))}
        hosts = sorted({o.split("/")[2] for f in files for o in f.get("origins") or [] if o.count("/") >= 2})
        out.append({**meta, "dataset_id": d["dataset_id"], "kind": d["kind"], "owner": "module" if d["module"] else "operator",
                    "module": d["module"] or None, "platform": d["platform"], "created_at": d["created_at"],
                    "files": len(files), "size": sum(int(f.get("size") or 0) for f in files), "origins": hosts,
                    "pinned": d["dataset_id"] in pinned})
    return out


def _events(r, module: str, p: dict) -> list[dict]:
    """Events about the module, or about one of its jobs or campaigns."""
    w, a = _where(p, {"kind": "e.kind", "job_id": "e.job_id", "campaign": "e.campaign_id"})
    return r.q("SELECT e.event_id, e.ts, e.kind, e.reason, e.node_id, e.job_id, e.campaign_id FROM events e WHERE "
               "(e.module=? OR EXISTS(SELECT 1 FROM jobs j WHERE j.job_id=e.job_id AND j.module=?) OR "
               "EXISTS(SELECT 1 FROM campaigns c WHERE c.campaign_id=e.campaign_id AND c.module=?))" + w +
               " ORDER BY e.event_id DESC LIMIT 200", (module, module, module, *a))


def _open_alerts(r, rules: list[str]) -> set[str]:
    """Which of these alert rules are open."""
    return {x["rule"] for x in r.q("SELECT rule FROM alerts WHERE state IN ('open','pending') AND rule IN (%s)"
                                   % (",".join("?" * len(rules)) or "NULL"), tuple(rules))}


def _secrets(r, module: str, man: mf.Manifest, p: dict) -> list[dict]:
    """Per declared secret: set or not, its keyed fingerprint, when and by whom it changed. Never a value."""
    unreadable = _open_alerts(r, [f"secret_unreadable:{module}/{s.name}" for s in man.secrets])
    out = []
    for s in man.secrets:
        if p.get("name") not in (None, s.name):
            continue
        rows = r.q("SELECT node_id, fingerprint, set_at, set_by FROM secrets WHERE module=? AND name=?", (module, s.name))
        mod = next((x for x in rows if not x["node_id"]), None)
        out.append({"name": s.name, "description": s.description, "set": mod is not None,
                    "fingerprint": mod["fingerprint"] if mod else None, "changed_at": mod["set_at"] if mod else None,
                    "changed_by": mod["set_by"] if mod else None, "node_values": sum(1 for x in rows if x["node_id"]),
                    "stages": [st.name for st in man.stages if s.name in st.secrets],
                    "coordinator": "secrets:read:self" in man.coordinator.permissions,
                    "unreadable": f"secret_unreadable:{module}/{s.name}" in unreadable})
    return out


def _pins(r, module: str, man: mf.Manifest, p: dict) -> list[dict]:
    """Each pinned dataset of the module's bootstrap stages: registered as pinned, missing, or held by something else."""
    conflicts = _open_alerts(r, [f"pinned_dataset_conflict:{x.dataset_id}" for x in man.datasets.pinned])
    out = []
    for pin in man.datasets.pinned:
        if p.get("dataset_id") not in (None, pin.dataset_id):
            continue
        want = pin.dataset_files()
        ex = r.one("SELECT kind, module, files_json, platform FROM datasets WHERE dataset_id=?", (pin.dataset_id,))
        have = sorted(({k: f.get(k) for k in ("path", "digest", "size")} for f in jl(ex["files_json"], []) or []),
                      key=lambda f: f["path"]) if ex else None
        same = ex is not None and (ex["module"], ex["kind"], have, ex["platform"]) == (module, pin.kind, want, pin.platform)
        out.append({"dataset_id": pin.dataset_id, "kind": pin.kind, "platform": pin.platform, "files": len(want),
                    "size": sum(f["size"] for f in want),
                    "state": "missing" if ex is None else "registered" if same else "conflict",
                    "conflict": None if ex is None or same else f"{ex['module'] or 'the operator'} (kind {ex['kind']})",
                    "alert": f"pinned_dataset_conflict:{pin.dataset_id}" in conflicts})
    return out


def _images(r, module: str, man: mf.Manifest, p: dict) -> list[dict]:
    sets = {cs.name: cs for cs in man.sandbox.container_sets}
    w, a = _where(p, {"set_name": "set_name"})
    rows = r.q("SELECT digest, image, set_name, key_sha256, first_run_at, node_id, attempt_id FROM module_images WHERE module=?"
               + w + " ORDER BY first_run_at DESC LIMIT 2000", (module, *a))
    return [{**x, "registry": getattr(sets.get(x["set_name"]), "registry", None),
             "repository": getattr(sets.get(x["set_name"]), "repository", None),
             "platform": getattr(sets.get(x["set_name"]), "platform", None)} for x in rows]


def _platforms(r, module: str, man: mf.Manifest, p: dict, now: float) -> list[dict]:
    """The module's per-platform support matrix: what it declares and refuses, beside what the fleet has."""
    req = man.requires
    nodes = r.q("SELECT node_id, platform, last_heartbeat_at, modules_json FROM nodes WHERE lifecycle!='retired'")
    plats = set(req.platforms) | {k for k in req.unsupported.runner if "-" in k} | {n["platform"] for n in nodes if n["platform"]}

    def reason(table: dict, plat: str) -> str | None:
        return table.get(plat) or table.get(portable.split_platform(plat)[0] if "-" in plat else plat)
    out = []
    for plat in sorted(plats):
        if p.get("platform") not in (None, plat):
            continue
        mine = [n for n in nodes if n["platform"] == plat]
        states = [(jl(n["modules_json"], {}) or {}).get(module, {}).get("state") for n in mine]
        coord = req.coordinator_platforms
        out.append({"platform": plat,
                    "runner": "supported" if plat in req.platforms else "unsupported" if reason(req.unsupported.runner, plat)
                    else "undeclared", "reason": reason(req.unsupported.runner, plat),
                    "coordinator": "any" if coord is None else "supported" if plat in coord else "unsupported",
                    "coordinator_reason": None if coord is None or plat in coord else reason(req.unsupported.coordinator, plat),
                    "nodes": len(mine), "online": sum(_online(n, now) for n in mine),
                    "certified": states.count("certified"), "doctor_failed": states.count("doctor_failed")})
    return out


def _campaigns(r, module, p):
    w, a = _where(p, {"campaign": "campaign_id", "state": "state"})
    out = []
    for c in r.q("SELECT campaign_id, name, state, priority, weight, labels_json, created_at, finished_at FROM campaigns "
                 "WHERE module=?" + w + " ORDER BY created_at DESC LIMIT 500", (module, *a)):
        pl = placement.summary(r, c["campaign_id"]) or {}
        top = r.one("SELECT source, stranded_since FROM placement_bindings WHERE unit=?", (f"c:{c['campaign_id']}",))
        out.append({**c, "labels": jl(c.pop("labels_json"), {}) or {}, "placement_mix": pl.get("mix"),
                    "placement_unit": pl.get("unit"), "placement_pin": pl.get("pin"), "bound_class": pl.get("class"),
                    "binding_state": pl.get("state"), "binding_source": top["source"] if top else None,
                    "stranded_since": top["stranded_since"] if top else None})
    return out


def rows_for(r, module: str, man: mf.Manifest, src: U.Source, now: float | None = None) -> list[dict]:
    """A host query's rows for `module`, before shaping (render.shape)."""
    now = now or time.time()
    p, q = filter_params(src), src.query
    if q == "results":
        w, a = _where(p, {"job_id": "job_id", "node_id": "node_id"})
        rows = r.q("SELECT result_id, job_id, node_id, value, at, digest, fields_json FROM results WHERE module=? AND accepted=1"
                   + w + " ORDER BY result_id DESC LIMIT 2000", (module, *a))
        for x in rows:
            x.update({k: v for k, v in (jl(x.pop("fields_json"), {}) or {}).items()
                      if not isinstance(v, (dict, list)) and k not in x})
        return rows
    if q == "jobs":
        w, a = _where(p, {"job_id": "job_id", "state": "state", "kind": "kind", "dataset_id": "dataset_id",
                          "campaign": "campaign_id"})
        return r.q("SELECT job_id, state, kind, stage, dataset_id, campaign_id, priority, created_at, done_at, exec_failures "
                   "FROM jobs WHERE module=?" + w + " ORDER BY job_id DESC LIMIT 2000", (module, *a))
    if q == "attempts":
        w, a = _where(p, {"attempt_id": "a.attempt_id", "job_id": "a.job_id", "node_id": "a.node_id", "state": "a.state"})
        rows = r.q("SELECT a.attempt_id, a.job_id, a.node_id, a.state, a.phase, a.cpu_s, a.rss_gb, a.granted_at, a.ended_at, "
                   "a.end_reason, a.module_version, a.resume_json FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                   "WHERE j.module=?" + w + " ORDER BY a.attempt_id DESC LIMIT 2000", (module, *a))
        for x in rows:
            res = jl(x.pop("resume_json"), {}) or {}
            x.update(resumed_from_attempt=res.get("from_attempt"), resumed_from_node=res.get("node_id"),
                     resume_digest=res.get("digest"))
        return rows
    if q == "datasets":
        return _datasets(r, module, man, p)
    if q == "module_settings":
        return [r.get_setting(f"module_settings:{module}", {}) or {}]
    if q == "module_events":
        return _events(r, module, p)
    if q == "nodes":
        return _nodes(r, module, man, p, now)
    if q == "services":
        w, a = _where(p, {"node_id": "node_id"})
        return [s for n in r.q("SELECT node_id, hostname, services_json, services_at FROM nodes WHERE lifecycle!='retired'" + w
                               + " ORDER BY hostname", tuple(a))
                for s in nodeservices.rows(n, module) if p.get("service") in (None, s["service"])]
    if q == "node_metrics":
        if not p.get("node_id"):
            return []
        return [{"ts": s["ts"], **(jl(s["telemetry_json"], {}) or {})} for s in
                r.q("SELECT ts, telemetry_json FROM node_samples WHERE node_id=? ORDER BY ts DESC LIMIT 720", (p["node_id"],))]
    if q == "campaigns":
        return _campaigns(r, module, p)
    if q == "store":
        if not p.get("collection"):
            return []
        cid = p.get("campaign")
        return [{**json.loads(d["doc_json"]), "_key": d["key"]} for d in
                r.q("SELECT key, doc_json FROM module_store WHERE module=? AND collection=?" +
                    (" AND json_extract(doc_json, '$.campaign_id')=?" if cid else "") + " ORDER BY key LIMIT 2000",
                    (module, p["collection"], *([cid] if cid else [])))]
    if q == "secrets":
        return _secrets(r, module, man, p)
    if q == "checkpoints":
        w, a = _where(p, {"job_id": "c.job_id", "node_id": "c.node_id"})
        rows = r.q("SELECT c.job_id, c.attempt_id, c.node_id, c.generation, c.seq, c.size, c.at, c.digest, c.files_json "
                   "FROM checkpoints c JOIN jobs j ON j.job_id=c.job_id WHERE j.module=?" + w + " ORDER BY c.at DESC LIMIT 2000",
                   (module, *a))
        for x in rows:
            x["files"] = len(jl(x.pop("files_json"), []) or [])
        return rows
    if q == "pins":
        return _pins(r, module, man, p)
    if q == "images":
        return _images(r, module, man, p)
    if q == "platforms":
        return _platforms(r, module, man, p, now)
    return []


def resolve(r, module: str, man: mf.Manifest, src: U.Source) -> dict:
    if src.view:
        decl = man.ui.views.get(src.view)
        scope = str(src.params.get("campaign") or "") if decl is not None and "campaign" in decl.params else ""
        row = r.one("SELECT doc_json, computed_at, error, error_at FROM module_views WHERE module=? AND view_id=? AND params_hash=?",
                    (module, src.view, scope))
        if not row or not row["doc_json"]:
            return {"error": "not computed yet"} if not row or not row["error"] else {"error": row["error"]}
        doc = json.loads(row["doc_json"])
        stale = bool(row["error_at"] and (row["error_at"] or 0) > (row["computed_at"] or 0))
        return {**doc, "computed_at": row["computed_at"], "stale": stale}
    return {"rows": shape(rows_for(r, module, man, src), src)}


def resolve_in(r, module: str, man: mf.Manifest, src: U.Source, ctx: dict) -> dict:
    """A frame's read: its source's $-params interpolated from the frame's context, then resolved like a page's."""
    params = {k: interpolate(v, ctx) for k, v in src.params.items()}
    return resolve(r, module, man, src.model_copy(update={"params": params}))


# ------------------------------------------------------------------------------------------ links and operations

def link_url(module: str, man: mf.Manifest, link: U.Link, return_to: str = "") -> str | None:
    """The console URL of a typed reference, or None (rendered as text)."""
    if link.job is not None:
        return f"/jobs/{int(link.job)}"
    if link.node:
        return f"/nodes/{quote(link.node, safe='')}"
    if link.dataset:
        return f"/datasets/{quote(link.dataset, safe=':+')}" + ("/download.zip" if link.download else "")
    if link.campaign:
        return f"/campaigns/{quote(link.campaign, safe='')}" + ("/artifacts.zip" if link.download else "")
    if link.page:
        return f"/m/{module}/{link.page}" if any(d.id == link.page for d in man.ui.pages) else None
    if link.tab == "secrets":
        return f"/modules/{module}/secrets" if man.secrets else None
    if link.tab == "health":
        return f"/modules/{module}/health"
    if link.upload:
        if link.upload.kind not in man.datasets.kinds:
            return None
        q = {"module": module, "kind": link.upload.kind}
        if link.upload.then:
            q["then"] = f"mod.{module.replace('-', '_')}.{link.upload.then[5:]}"
        if return_to:
            q["return_to"] = return_to
        return "/datasets/upload?" + urlencode(q)
    if link.url and any(link.url.startswith(u) for u in man.ui.external_urls):
        return link.url
    return None


def op_id_of(module: str, op: str) -> str:
    return f"mod.{module.replace('-', '_')}.{op[5:]}" if op.startswith("self.") else op


def op_allowed(module: str, meta: dict | None, role: str | None) -> str | None:
    """Why the viewer may not run an operation a module page or frame names (None: allowed): it must be registered, its
    min_role met, and a module operation must be this module's."""
    if not meta:
        return "unknown operation"
    if meta["id"].startswith("mod.") and not meta["id"].startswith(f"mod.{module.replace('-', '_')}."):
        return "another module's operation"
    if ROLE_RANK.get(role or "", -1) < ROLE_RANK.get(meta.get("min_role") or "operator", 1):
        return f"needs the {meta.get('min_role')} role"
    return None


OWNED_TARGETS = {"jobs": ("jobs", "job_id"), "campaigns": ("campaigns", "campaign_id"), "datasets": ("datasets", "dataset_id")}


def target_owned(r, module: str, op_id: str, target: str) -> bool:
    """A core job, campaign or dataset operation a frame requests must name one of the module's own."""
    area = op_id.split(".", 1)[0]
    if op_id.startswith("mod.") or area not in OWNED_TARGETS or not target:
        return True
    table, col = OWNED_TARGETS[area]
    return bool(r.one(f"SELECT 1 FROM {table} WHERE {col}=? AND module=?", (target, module)))


def frame_of(man: mf.Manifest, view: str) -> U.IframeDecl | None:
    return next((f for f in man.ui.iframes if f.id == view), None)


def build_host(catalog: ModuleCatalog, module: str, context: dict, ops_meta, module_origin: str, reader,
               tokens=None) -> Host:
    man = catalog.manifest(module)

    def schema(path: str) -> dict:
        f = (catalog.path(module) / path).resolve()
        if catalog.path(module) not in f.parents:
            return {}
        return json.loads(f.read_text())

    def frame(view: str) -> dict | None:
        decl = frame_of(man, view)
        return None if decl is None else {"src": f"{module_origin}/f/{module}/{view}/", "bridge": list(decl.bridge),
                                          "base": f"/m/{module}/_bridge/{view}"}

    from . import media

    def media_urls(ref, kind):
        return media.urls(reader, tokens, module, module_origin, ref, kind) if tokens is not None else None
    return Host(resolve=lambda src, ctx: resolve(reader, module, man, src), operation=ops_meta, media=media_urls,
                op_url=lambda op: f"/do/{op}", link_url=lambda link: link_url(module, man, link, context.get("return_to", "")),
                frame=frame, schema=schema, module=module, context=context, return_to=context.get("return_to", ""))
