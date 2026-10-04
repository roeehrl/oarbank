"""Module pages in the console (PLAN D23): the console's implementation of the published renderer's Host.

Reads only: host queries go through the console's read pool and are always filtered to the module's own
rows; module views are read from oarbankd's `module_views` table (a module is never on the render path);
operation metadata comes from oarbankd's registry (/api/v1/ops, cached), so buttons show registry titles.
"""
import json
import statistics as st
import time
from pathlib import Path

from oarbank_sdk import manifest as mf, ui as U
from oarbank_sdk.render import Host

from .views import jl

AGG = {"count": len, "mean": lambda v: st.mean(v) if v else None, "median": lambda v: st.median(v) if v else None,
       "min": lambda v: min(v) if v else None, "max": lambda v: max(v) if v else None, "sum": lambda v: sum(v) if v else 0,
       "p95": lambda v: sorted(v)[min(len(v) - 1, int(0.95 * len(v)))] if v else None}
FILTERABLE = {"job_id", "node_id", "state", "kind", "dataset_id", "attempt_id"}


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


def _rows_for(r, module: str, man: mf.Manifest, src: U.Source) -> list[dict]:
    p = {k: v for k, v in src.params.items() if k in FILTERABLE and v is not None}
    where, args = [], []
    for k, v in p.items():
        where.append(f"{k}=?")
        args.append(v)
    extra = (" AND " + " AND ".join(where)) if where else ""
    q = src.query
    if q == "results":
        rows = r.q("SELECT result_id, job_id, node_id, value, at, digest, fields_json FROM results "
                   "WHERE module=? AND accepted=1" + extra.replace("dataset_id", "job_id") + " ORDER BY result_id DESC LIMIT 2000",
                   (module, *args))
        for x in rows:
            x.update({k: v for k, v in (jl(x.pop("fields_json"), {}) or {}).items() if not isinstance(v, (dict, list))})
        return rows
    if q == "jobs":
        return r.q("SELECT job_id, state, kind, dataset_id, priority, created_at, done_at, exec_failures FROM jobs "
                   "WHERE module=?" + extra + " ORDER BY job_id DESC LIMIT 2000", (module, *args))
    if q == "attempts":
        return r.q("SELECT a.attempt_id, a.job_id, a.node_id, a.state, a.phase, a.cpu_s, a.granted_at, a.ended_at, a.end_reason "
                   "FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE j.module=?"
                   + extra.replace("job_id=", "a.job_id=").replace("node_id=", "a.node_id=").replace("state=", "a.state=")
                   + " ORDER BY a.attempt_id DESC LIMIT 2000", (module, *args))
    if q == "datasets":
        kinds = list(man.datasets.kinds)
        if not kinds:
            return []
        return [{**d, **(jl(d.pop("meta_json"), {}) or {})} for d in
                r.q("SELECT dataset_id, kind, meta_json, created_at FROM datasets WHERE kind IN (%s) ORDER BY created_at DESC LIMIT 2000"
                    % ",".join("?" * len(kinds)), tuple(kinds))]
    if q == "module_settings":
        return [r.get_setting(f"module_settings:{module}", {}) or {}]
    if q == "module_events":
        return r.q("SELECT event_id, ts, kind, reason FROM events WHERE reason LIKE ? ORDER BY event_id DESC LIMIT 200",
                   (f"%{module}%",))
    if q == "nodes":
        out = []
        for n in r.q("SELECT node_id, hostname, lifecycle, desired_state, last_heartbeat_at, modules_json FROM nodes WHERE lifecycle!='retired'"):
            state = (jl(n.pop("modules_json"), {}) or {}).get(module, {}).get("state")
            out.append({**n, "module_state": state, "online": bool(n["last_heartbeat_at"] and time.time() - n["last_heartbeat_at"] < 30)})
        return out
    if q == "node_metrics":
        nid = src.params.get("node_id") or src.params.get("node")
        return [{"ts": s["ts"], **(jl(s["telemetry_json"], {}) or {})} for s in
                r.q("SELECT ts, telemetry_json FROM node_samples WHERE node_id=? ORDER BY ts DESC LIMIT 720", (nid,))] if nid else []
    if q == "campaigns":
        return [{**c, "labels": jl(c.pop("labels_json"), {}) or {}} for c in
                r.q("SELECT campaign_id, name, state, priority, weight, labels_json, created_at, finished_at FROM campaigns "
                    "WHERE module=?" + (" AND campaign_id=?" if src.params.get("campaign") else "") + " ORDER BY created_at DESC LIMIT 500",
                    (module, *([src.params["campaign"]] if src.params.get("campaign") else [])))]
    if q == "store":
        coll = src.params.get("collection")
        if not coll:
            return []
        cid = src.params.get("campaign")
        return [{**json.loads(d["doc_json"]), "_key": d["key"]} for d in
                r.q("SELECT key, doc_json FROM module_store WHERE module=? AND collection=?" +
                    (" AND json_extract(doc_json, '$.campaign_id')=?" if cid else "") + " ORDER BY key LIMIT 2000",
                    (module, coll, *([cid] if cid else [])))]
    return []


def _shape(rows: list[dict], src: U.Source) -> list[dict]:
    if src.agg:
        groups = {}
        for x in rows:
            groups.setdefault(x.get(src.group_by) if src.group_by else None, []).append(x)
        out = []
        for g, xs in groups.items():
            rec = {src.group_by: g} if src.group_by else {}
            for f, fn in src.agg.items():
                vals = [x.get(f) for x in xs if isinstance(x.get(f), (int, float))] if fn != "count" else xs
                rec[f] = AGG[fn](vals)
            out.append(rec)
        rows = out
    if src.order_by:
        rows = sorted(rows, key=lambda x: (x.get(src.order_by) is None, x.get(src.order_by)), reverse=src.descending)
    if src.fields:
        keep = set(src.fields) | ({src.group_by} if src.group_by else set()) | set(src.agg)
        rows = [{k: v for k, v in x.items() if k in keep} for x in rows]
    return rows[:src.limit]


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
    return {"rows": _shape(_rows_for(r, module, man, src), src)}


def build_host(state, catalog: ModuleCatalog, module: str, context: dict, ops_meta, module_origin: str, reader,
               tokens=None) -> Host:
    man = catalog.manifest(module)

    def link_url(l: U.Link) -> str:
        if l.job is not None:
            return f"/jobs/{int(l.job)}"
        if l.node:
            return f"/nodes/{l.node}"
        if l.page:
            return f"/m/{module}/{l.page}"
        if l.url and any(l.url.startswith(u) for u in man.ui.external_urls):
            return l.url
        return "#"

    def schema(path: str) -> dict:
        f = (catalog.path(module) / path).resolve()
        if catalog.path(module) not in f.parents:
            return {}
        return json.loads(f.read_text())

    from . import media

    def media_urls(ref, kind):
        return media.urls(reader, tokens, module, module_origin, ref, kind) if tokens is not None else None
    return Host(resolve=lambda src, ctx: resolve(reader, module, man, src), operation=ops_meta, media=media_urls,
                op_url=lambda op: f"/do/{op}", link_url=link_url,
                frame_url=lambda view: f"{module_origin}/f/{module}/{view}/", schema=schema, module=module,
                context={**context, "bridge_base": f"/m/{module}/_bridge"}, return_to=context.get("return_to", ""))
