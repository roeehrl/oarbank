"""oarbankd's only way into module code (D1): typed wrappers over module protocol verbs, served by the module host out
of process, plus the static facts read from each module's manifest.

Rules for callers:
- never call from inside `db.tx()` or while holding the DB lock: module IPC must not extend the write
  lock, and a module's host callbacks read only committed data;
- `ModuleUnavailable` / `ModuleError` are module faults: never charge them to a node or a job (S15).
"""
import atexit
import json
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path

from oarbank_sdk import manifest as mf

from .modulehost import ModuleError, ModuleHost, ModuleSpec, ModuleUnavailable  # noqa: F401  (re-exported)

_hosts: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_lock = threading.Lock()
_all_hosts: list = []


# ------------------------------------------------------------------ catalog (manifest facts)

@dataclass(frozen=True)
class ModuleInfo:
    name: str                       # short name: the last part of the module id
    manifest: mf.Manifest
    path: Path
    version: str = ""
    digest: str = ""

    @property
    def stages(self) -> tuple[str, ...]:
        return tuple(s.name for s in self.manifest.stages)

    @property
    def chain(self) -> tuple[str, str] | None:
        """(head, tail) when a stage runs `after` another: the job can run as the chain head -> tail."""
        for s in self.manifest.stages:
            if s.after:
                return (s.after, s.name)
        return None

    @property
    def single_stage(self) -> str | None:
        """The default stage: what a job that names no stage runs in one go (oarbank_sdk Manifest.default_stage)."""
        return self.manifest.default_stage()

    @property
    def splittable(self) -> bool:
        return self.chain is not None and self.single_stage is not None

    def stage_resources(self, stage: str | None) -> dict:
        """Resources a stage reserves, from the manifest; `by_platform` holds its per-platform cpu and mem_gb
        (stages[].variants, keyed by token or OS), which resources_on resolves for a node."""
        st = next((s for s in self.manifest.stages if s.name == (stage or self.single_stage)), None) or self.manifest.stages[0]
        num = lambda v: int(v) if float(v).is_integer() else v
        out = {"cpu": num(st.requires.resources.cpu), "mem_gb": num(st.requires.resources.mem_gb)}
        if st.requires.pools:
            out["pools"] = dict(st.requires.pools)
        if st.requires.needs_pools:
            out["needs_pools"] = list(st.requires.needs_pools)
        by = {k: {f: num(x) for f, x in v.requires.resources.model_dump(exclude_none=True).items()}
              for k, v in st.variants.items() if v.requires and v.requires.resources}
        if any(by.values()):
            out["by_platform"] = {k: p for k, p in sorted(by.items()) if p}
        return out

    def stage_timeout(self, stage: str | None, platform: str | None) -> float:
        """The stage's timeout on a node of `platform` (its variant applied)."""
        st = next((s for s in self.manifest.stages if s.name == (stage or self.single_stage)), None)
        if st is None:
            return 1800.0
        return float((st.for_platform(platform) if platform else st).timeout_s)


# the catalog of the database this process serves (oarbankd serves one; tests switch with use()):
# CATALOG = each enabled module's current version; VERSIONS = every active (name, version)
CATALOG: dict[str, ModuleInfo] = {}
VERSIONS: dict[tuple[str, str], ModuleInfo] = {}
_active = {"db": None}


def _load_info(name: str, version: str, path: str, digest: str) -> ModuleInfo:
    return ModuleInfo(name, mf.load(Path(path) / "oarbank-module.toml"), Path(path), version, digest)


def use(db) -> dict:
    """(Re)load the catalog from this database's module store, register the modules' operations, and
    point the module host at the current bundle directories. Called at oarbankd start, by tests, and after
    every lifecycle change."""
    from . import modstore
    _active["db"] = weakref.ref(db) if db is not None else None
    cat, vers = {}, {}
    if db is not None:
        recs = {(r["name"], r["version"]): r for r in db.q("SELECT name, version, path, content_digest FROM modules")}
        for name, ver in modstore.active_versions(db):
            r = recs.get((name, ver))
            if r and db.abs(r["path"]).exists():
                vers[(name, ver)] = _load_info(name, ver, str(db.abs(r["path"])), r["content_digest"])
        for name, ch in modstore.channels(db).items():
            if ch["current"] and (name, ch["current"]) in vers:
                cat[name] = vers[(name, ch["current"])]
    CATALOG.clear()
    CATALOG.update(cat)
    VERSIONS.clear()
    VERSIONS.update(vers)
    from . import ops
    for name in CATALOG:
        ops.register_module(name)
    if db is not None:
        h = _hosts.get(db)
        if h is not None:
            _sync_host(db, h)
    return CATALOG


def host_key(name: str, version: str | None) -> str:
    """The module-host process name: the module's own name for its current version, name@version otherwise."""
    cur = CATALOG.get(name)
    return name if version is None or (cur and cur.version == version) else f"{name}@{version}"


def info_for(name: str, version: str | None) -> ModuleInfo:
    if version is None or (CATALOG.get(name) and CATALOG[name].version == version):
        return info(name)
    i = VERSIONS.get((name, version))
    if i is None:
        raise KeyError(f"{name} {version} is not active")
    return i


def info(name: str) -> ModuleInfo:
    if name not in CATALOG:
        raise KeyError(f"unknown module {name!r}; have {sorted(CATALOG)}")
    return CATALOG[name]


def enabled(db) -> list[str]:
    """Names of the enabled modules: a current version, not disabled (the kill switch)."""
    if db is None:
        return list(CATALOG)
    from . import modstore
    off = modstore.disabled_names(db)
    return [n for n in CATALOG if n not in off]


def version_of(name: str) -> str | None:
    """The current module version (stored with every result: generic provenance)."""
    i = CATALOG.get(name)
    return i.version or i.manifest.module.version if i else None


def data_dir(db, name: str) -> Path:
    """A module's coordinator-side data directory: the only place its process may write (spec/sandbox.md)."""
    from . import modsandbox
    return modsandbox.data_dir(Path(db.path).parent, name)


def compares(name: str, stage: str | None, version: str | None = None) -> bool:
    """Whether the host compares results of this stage (replicas, disputes, the result cache, goldens): not when its
    effective determinism is `none` (oarbank-sdk stages[].determinism), judged by the module version that produced the
    result, else the current one."""
    try:
        i = info_for(name, version)
    except KeyError:
        i = CATALOG.get(name)
    return i is None or i.manifest.compares(stage)


def tick_results(name: str, version: str | None) -> bool:
    """Whether that module version declares campaign.tick.results (it validates and delivers structured results)."""
    from oarbank_sdk import module_protocol as mp
    try:
        return mp.CAP_TICK_RESULTS in info_for(name, version).manifest.coordinator.capabilities
    except KeyError:
        return False


_VALIDATORS: dict = {}


def payload_problem(name: str, version: str | None, payload) -> str | None:
    """Why a result payload is unfit for campaign.tick (None: it is fit): over results.max_inline_kb as compact UTF-8
    JSON, or invalid against results.schema (the version's bundle file)."""
    import jsonschema
    i = info_for(name, version)
    res = i.manifest.results
    size = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    if size > res.max_inline_kb * 1024:
        return f"payload of {size} bytes > results.max_inline_kb {res.max_inline_kb}"
    path = i.path / res.schema_
    v = _VALIDATORS.get(str(path))
    if v is None:
        schema = json.loads(path.read_text(encoding="utf-8"))
        v = _VALIDATORS[str(path)] = jsonschema.validators.validator_for(schema)(schema)
    err = next(iter(v.iter_errors(payload)), None)
    return f"results.schema: {'/'.join(map(str, err.absolute_path)) or '(payload)'}: {err.message}"[:300] if err else None


def split_enabled(db, name: str) -> bool:
    return name in CATALOG and info(name).splittable and db.get_setting(f"pipeline:{name}", "single") == "split"


# ------------------------------------------------------------------ host per database

def host(db) -> ModuleHost:
    """The module host serving this database (one process per module, spawned on first use)."""
    h = _hosts.get(db)
    if h is not None:
        return h
    with _lock:
        h = _hosts.get(db)
        if h is None:
            home = Path(db.path).parent
            h = ModuleHost([], home=home, on_state=_alerting(db), callbacks=host_callbacks(db))
            _sync_host(db, h)
            _hosts[db] = h
            _all_hosts.append(weakref.ref(h))
            weakref.finalize(db, h.close)
    return h


def close_host(db) -> None:
    """Stop this database's module processes now rather than when the database is collected: for callers that open
    many databases in one process (the property tests open one per example). oarbankd's single host lives until exit."""
    with _lock:
        h = _hosts.pop(db, None)
    if h is not None:
        h.close()


def _spec(db, key: str, i: ModuleInfo) -> ModuleSpec:
    from . import modsandbox
    return modsandbox.coordinator_spec(Path(db.path).parent, i.name, i.manifest, i.path, key)


def _sync_host(db, h: ModuleHost):
    """Register a process spec per active version; restart processes whose bundle directory changed."""
    want = {host_key(n, v): i for (n, v), i in VERSIONS.items()}
    for key, i in want.items():
        old = h.specs.get(key)
        if old is None or old.cwd != str(i.path):
            h.register(_spec(db, key, i))
            if old is not None:
                h.stop(key)
    for key in list(h.specs):
        if key not in want:
            h.stop(key)
            h.specs.pop(key, None)


def host_callbacks(db) -> dict:
    """Host callbacks (module -> host), bound to this database. Each answers only the calling module's
    own rows; the module host has already checked the manifest permission. Reads only (writes are effects)."""
    ref = weakref.ref(db)

    def _db():
        d = ref()
        if d is None:
            raise RuntimeError("database closed")
        return d

    def datasets_query(module, p):
        d, kind, ids = _db(), p.get("kind"), p.get("ids")
        lim = min(int(p.get("limit") or 100), 5000)
        if ids:
            ids = [str(x) for x in ids][:5000]
            rows = d.q(f"SELECT dataset_id, kind, meta_json, files_json FROM datasets WHERE dataset_id IN ({','.join('?' * len(ids))}) "
                       "AND (module=? OR module IS NULL OR module='') ORDER BY dataset_id", (*ids, module))
        else:
            rows = d.q("SELECT dataset_id, kind, meta_json, files_json FROM datasets WHERE (? IS NULL OR kind=?) "
                       "AND (module=? OR module IS NULL OR module='') ORDER BY dataset_id LIMIT ?", (kind, kind, module, lim * 10))
        out = []
        for r in rows:
            meta = json.loads(r["meta_json"] or "{}")
            if all(meta.get(k) == v for k, v in (p.get("attrs") or {}).items()):
                out.append({"id": r["dataset_id"], "kind": r["kind"], "attrs": meta,
                            "files": json.loads(r["files_json"] or "[]") if p.get("with_files") else []})
        return {"datasets": out if ids else out[:lim]}

    def blobs_stat(module, p):
        from . import modfiles
        d = _db()
        r = d.one("SELECT size FROM blobs WHERE digest=?", (p.get("digest"),))
        if r and not modfiles.visible_blob(d, module, str(p.get("digest") or "")):
            r = None                                       # another module's blob does not exist for this one
        return {"exists": bool(r), "size": r["size"] if r else None}

    def settings_get(module, p):
        return {"value": (_db().get_setting(f"module_settings:{module}", {}) or {}).get(p.get("key"))}

    def store_get(module, p):
        r = _db().one("SELECT doc_json FROM module_store WHERE module=? AND collection=? AND key=?",
                      (module, p.get("collection"), str(p.get("key"))))
        return {"doc": json.loads(r["doc_json"]) if r else None}

    def store_query(module, p):
        where = p.get("where") or {}
        out = []
        for r in _db().q("SELECT key, doc_json FROM module_store WHERE module=? AND collection=? ORDER BY key",
                         (module, p.get("collection"))):
            doc = json.loads(r["doc_json"])
            if all(doc.get(k) == v for k, v in where.items()):
                out.append({**doc, "_key": r["key"]})
                if len(out) >= int(p.get("limit") or 500):
                    break
        return {"docs": out}

    def nodes_query(module, p):
        import time as _t
        from oarbank_sdk import platform as pf
        out, want = [], list(p.get("platforms") or [])
        for n in _db().q("SELECT node_id, hostname, modules_json, last_heartbeat_at, platform, os, arch, os_version "
                         "FROM nodes WHERE lifecycle='ready'"):
            st = (json.loads(n["modules_json"] or "{}").get(module) or {}).get("state")
            if p.get("certified_for_self", True) and st != "certified":
                continue
            if want and not (n["platform"] and pf.matches(n["platform"], want)):
                continue
            out.append({"node_id": n["node_id"], "hostname": n["hostname"], "module_state": st,
                        "online": bool(n["last_heartbeat_at"] and _t.time() - n["last_heartbeat_at"] < 60),
                        "platform": n["platform"], "os": n["os"], "arch": n["arch"], "os_version": n["os_version"]})
        return {"nodes": out}

    def jobs_query(module, p):
        d = _db()
        cid = p.get("campaign_id")
        c = d.one("SELECT module FROM campaigns WHERE campaign_id=?", (cid,))
        if not c or c["module"] != module:
            return {"jobs": []}
        states = p.get("states") or []
        rows = d.q("SELECT j.job_id, j.job_key, j.state, j.kind, j.stage, j.dataset_id, j.labels_json, j.target_node, j.group_key, "
                   "r.value, r.digest, r.fields_json, r.node_id, r.platform FROM jobs j "
                   "LEFT JOIN results r ON r.result_id=j.canonical_result_id "
                   "WHERE j.campaign_id=? AND j.module=? ORDER BY j.job_id LIMIT ?",
                   (cid, module, min(int(p.get("limit") or 5000), 50000)))
        out = []
        for r in rows:
            if states and r["state"] not in states:
                continue
            out.append({"job_id": r["job_id"], "job_key": r["job_key"], "state": r["state"], "kind": r["kind"],
                        "stage": r["stage"], "dataset_id": r["dataset_id"], "labels": json.loads(r["labels_json"] or "{}"),
                        "target_node": r["target_node"], "value": r["value"], "digest": r["digest"],
                        "fields": json.loads(r["fields_json"] or "{}") if r["fields_json"] else None, "node_id": r["node_id"],
                        "platform": r["platform"], "group": r["group_key"]})
        return {"jobs": out}

    def files_list(module, p):
        from . import modfiles
        return {"files": modfiles.listing(_db(), module, p.get("prefix") or "", int(p.get("limit") or 1000))}

    def files_stat(module, p):
        from . import modfiles
        f = modfiles.stat(_db(), module, p.get("path"))
        return {"exists": bool(f), "file": f}

    def files_read(module, p):
        from . import modfiles
        return modfiles.read(_db(), module, p.get("path"), int(p.get("offset") or 0), int(p.get("length") or modfiles.READ_MAX))

    return {"host.jobs.query": jobs_query, "host.datasets.query": datasets_query, "host.blobs.stat": blobs_stat, "host.settings.get": settings_get,
            "host.store.get": store_get, "host.store.query": store_query, "host.nodes.query": nodes_query,
            "host.files.list": files_list, "host.files.stat": files_stat, "host.files.read": files_read}


def _alerting(db):
    """Module host state -> the alert inbox: a crash or fault opens the P4 alert `module_host_down`, resolved on the
    next successful call. Weak reference: the host never keeps the database alive."""
    ref = weakref.ref(db)

    def hook(module: str, what: str, detail: str | None):
        d = ref()
        if d is None:
            return
        from . import core
        rule, subject = f"module_host_down:{module}", f"module:{module}"
        if what == "recovered":
            core._resolve_alert(d, rule, subject)
        else:
            core._alert(d, rule, subject, f"module {module} {what}: {detail or ''}"[:300], priority="high")
    return hook


@atexit.register
def _close_all():
    for r in _all_hosts:
        h = r()
        if h is not None:
            h.close()


def job_key(name: str, key_inputs: dict, stage: str | None = None, version: str | None = None) -> str:
    """The protocol job key H(module_id, compat, key_inputs) (oarbank_sdk.keys.job_key)."""
    from oarbank_sdk.keys import job_key as _k
    m = info_for(name, version).manifest.module
    return _k(m.id, m.compat, key_inputs, stage)


# ------------------------------------------------------------------ verbs

def call(db, name: str, method: str, params: dict, version: str | None = None):
    return host(db).call(host_key(name, version), method, params)


def spec_build(db, name: str, items: list[dict], version: str | None = None) -> list[dict]:
    """PlanItems -> BuiltSpecs. Raises ValueError for invalid input."""
    try:
        return call(db, name, "spec.build", {"jobs": items, "target_spec_version": 1}, version)["specs"]
    except ModuleError as e:
        if e.code == -32602:
            raise ValueError(e.message) from e
        raise


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str
    value: float | None
    digest: str | None
    digest_version: int | None
    fields: dict            # the module's typed result fields (its summary merged in), stored as fields_json
    verdict: str = "accept"


def evaluate(db, name: str, spec: dict, result: dict, stage: str | None = None, version: str | None = None) -> Verdict:
    r = call(db, name, "result.evaluate", {"spec": spec, "result": result, "stage": stage}, version)
    return Verdict(r["verdict"] == "accept", r.get("reason") or "ok", r.get("value"), r.get("digest"),
                   r.get("digest_version"), {**(r.get("summary") or {}), **(r.get("fields") or {})}, r["verdict"])


def merge(db, name: str, stages: dict, version: str | None = None) -> dict:
    """result.merge over a chain's stage results {head: envelope, tail: envelope}."""
    return call(db, name, "result.merge", {"stages": stages}, version)["result"]


def pools_of_disabled(disabled: list[str]) -> set[str]:
    """Pools that only disabled services provide (from the catalogued manifests)."""
    on, off = set(), set()
    for mname, i in CATALOG.items():
        for s in i.manifest.services:
            is_off = f"{mname}/{s.name}" in disabled or f"*/{s.name}" in disabled
            (off if is_off else on).update(s.provides.pools)
    return off - on


def node_class(node: dict | None, name: str) -> dict:
    """What golden.list may know about a node (NodeClass): platform, OS version, CPU, GPUs, capabilities and pools,
    never its identity. Pools: those the node reports (its agent's own, such as `containers` from its container runtime,
    and running services') and those its services provide, which count as available although an on-demand service may
    not run yet, unless the owner disabled every service that provides it here. Capabilities: those its doctor report
    names for the module (services and healthy probes, such as a tool probe) and its enabled services'."""
    import json as _json
    from .predicates import node_capabilities
    disabled = (_json.loads((node or {}).get("policy_json") or "{}") or {}).get("disabled_services") or [] if node else []
    facts = _json.loads((node or {}).get("facts_json") or "{}") or {} if node else {}
    reported = (_json.loads((node or {}).get("capacity_json") or "{}") or {}).get("pools") or {} if node else {}
    off = pools_of_disabled(disabled)
    pools = {p: 1 for p, k in reported.items() if isinstance(k, (int, float)) and k > 0 and p not in off}
    caps = node_capabilities(node, name) if node else set()
    for mname, i in CATALOG.items():
        for s in i.manifest.services:
            for p in s.provides.pools:
                pools[p] = 0 if p in off else 1
            if not (f"{mname}/{s.name}" in disabled or f"*/{s.name}" in disabled):
                caps.update(s.provides.capabilities)
    return {"platform": (node or {}).get("platform"), "os_version": (node or {}).get("os_version"),
            "cpu": dict(facts.get("cpu") or {}), "gpus": list(facts.get("gpus") or []),
            "capabilities": sorted(caps), "pools": pools}


def goldens(db, name: str, node: dict | None = None, version: str | None = None) -> list[dict]:
    """The module's golden jobs for a node class, each built into its stage payload:
    [{name, stage, key, payload, spec_version, datasets, mounts, expected}]. A golden limited to other platforms is
    dropped, and `expected` is the one for the node's platform (Golden.platforms, Golden.expected_by_platform)."""
    from oarbank_sdk import module_protocol as mp
    plat = (node or {}).get("platform")
    r = call(db, name, "golden.list", {"node_class": node_class(node, name)}, version)
    gs = [g.for_platform(plat).model_dump(mode="json") for g in map(mp.Golden.model_validate, r["goldens"]) if g.runs_on(plat)]
    if not gs:
        return []
    built = spec_build(db, name, [{"key_inputs": g["key_inputs"], "datasets": g.get("datasets") or [],
                                   "stages": g.get("stages") or []} for g in gs], version)
    i = info_for(name, version)
    out = []
    for g, b in zip(gs, built):
        want = (g.get("stages") or [None])[0]
        st = next((x for x in b["stages"] if want is None or x.get("stage") == want), None)
        if st is None or (want is None and len(b["stages"]) != 1):
            raise ModuleError(name, "golden.list", _rpc_error(f"golden {g['name']}: spec.build gave no single stage to run"))
        stage = st.get("stage") if st.get("stage") in i.stages else None
        stage = None if stage == i.single_stage else stage           # single-stage jobs carry no stage, as eval jobs
        if not i.manifest.compares(stage):
            raise ModuleError(name, "golden.list", _rpc_error(f"golden {g['name']}: stage {stage or i.single_stage!r} has "
                                                               "determinism none, so its results are never golden-tested"))
        out.append({"name": g["name"], "stage": stage,
                    "key": job_key(name, g["key_inputs"], stage, version), "payload": st["payload"],
                    "spec_version": b.get("spec_version") or 1, "datasets": st.get("datasets") or g.get("datasets") or [],
                    "mounts": st.get("mounts") or {}, "expected": g["expected"]})
    return out


def _rpc_error(msg: str):
    from oarbank_sdk.rpc import RpcError
    return RpcError(-32603, msg)


def golden_ok(db, name: str, expected: dict, result: dict, digest: str | None = None, version: str | None = None) -> bool:
    """golden.compare when the module offers it; otherwise the evaluated digest must equal expected.digest."""
    if has_capability(name, "golden.compare"):
        return bool(call(db, name, "golden.compare", {"expected": expected, "result": result}, version)["ok"])
    return bool(digest) and digest == expected.get("digest")


def tick(db, name: str, campaign: dict, jobs: list[dict], now: float) -> dict:
    """campaign.tick for one running campaign: {effects, message}."""
    return call(db, name, "campaign.tick", {"campaign": campaign, "jobs": jobs, "now": now})


def runner_gpu(name: str, platform: str | None) -> str:
    """The module runner's declared GPU use on `platform` (its variant applied): none | shared | exclusive."""
    i = CATALOG.get(name)
    if i is None:
        return "none"
    run = i.manifest.runner
    return (run.for_platform(platform) if platform else run).gpu.use


def job_uses_gpu(module: str, resources: dict | None, platform: str | None) -> bool:
    """A GPU job: its resources say so, its runner uses a GPU, or it reserves a pool of a service that uses one (a warm
    model server: oarbank-sdk 1.5 `services[].gpu`)."""
    if bool((resources or {}).get("gpu")) or runner_gpu(module, platform) != "none":
        return True
    i = CATALOG.get(module)
    return bool(i and set((resources or {}).get("pools") or {}) & i.manifest.gpu_pools())


def stage_platforms(name: str, stage: str | None) -> list[str]:
    """The platforms a job's stage is limited to (stages[].requires.platforms; empty: every declared platform)."""
    i = CATALOG.get(name)
    if i is None:
        return []
    st = next((s for s in i.manifest.stages if s.name == (stage or i.single_stage)), None)
    return list(st.requires.platforms) if st else []


def stage_capabilities(name: str, stage: str | None) -> list[str]:
    """The node capabilities a job's stage needs (stages[].requires.capabilities: healthy services or probes of the node,
    or the module doctor's own)."""
    i = CATALOG.get(name)
    st = next((s for s in i.manifest.stages if s.name == (stage or i.single_stage)), None) if i else None
    return sorted(st.requires.capabilities) if st else []


def stage_retry(name: str, stage: str | None) -> dict:
    """How many execution attempts a job's stage allows before it is quarantined (stages[].retry.max_attempts): `max`, and
    `by_platform` from its variants (keyed by token or OS; predicates.retry_max resolves them for a node)."""
    i = CATALOG.get(name)
    st = next((s for s in i.manifest.stages if s.name == (stage or i.single_stage)), None) if i else None
    if st is None:
        return {"max": mf.Retry().max_attempts, "by_platform": {}}
    return {"max": st.retry.max_attempts, "by_platform": {k: v.retry.max_attempts for k, v in st.variants.items() if v.retry}}


def stage_bootstrap(name: str, stage: str | None) -> bool:
    """Whether a job of this stage is a bootstrap job (oarbank-sdk stages[].bootstrap): it runs where the module's doctor is
    healthy before its goldens pass, with the bootstrap grants, and its result must be exactly pinned datasets."""
    i = CATALOG.get(name)
    return bool(i and i.manifest.is_bootstrap(stage))


def resources_on(res: dict, platform: str | None) -> dict:
    """A job's stored resources on a node of `platform`: its stage's per-platform overrides applied (by_platform: the
    OS's entry, then the token's)."""
    from oarbank_sdk import platform as pf
    by = res.get("by_platform") or {}
    out = {k: v for k, v in res.items() if k != "by_platform"}
    for key in pf.variant_keys(platform) if platform else ():
        out.update(by.get(key) or {})
    return out


def has_capability(name: str, cap: str) -> bool:
    i = CATALOG.get(name)
    return bool(i and cap in i.manifest.coordinator.capabilities)


def platform_matrix(db, name: str) -> dict:
    """Where a module runs (the console's module page, `oarbank module show`): for each known platform, the fleet's and
    this coordinator's, whether its runner and its coordinator side support it, the module's own reason when not
    (requires.unsupported), and the fleet's nodes and certified nodes there; and why its coordinator side does not run
    on this coordinator, if it does not."""
    from oarbank_sdk import platform as pf, portable
    from . import modstore
    req, here = info(name).manifest.requires, portable.host_platform()
    nodes = db.q("SELECT platform, modules_json FROM nodes WHERE lifecycle!='retired'")
    rows = []
    for p in sorted(set(portable.KNOWN_PLATFORMS) | {n["platform"] for n in nodes if n["platform"]} | {here}):
        on = [n for n in nodes if n["platform"] == p]
        runner, coord = p in req.platforms, req.coordinator_platforms is None or p in req.coordinator_platforms
        rows.append({"platform": p, "here": p == here,
                     "runner": runner, "runner_reason": None if runner else pf.resolve(req.unsupported.runner, p),
                     "coordinator": coord, "coordinator_reason": None if coord else pf.resolve(req.unsupported.coordinator, p),
                     "nodes": len(on), "certified": sum(1 for n in on if (json.loads(n["modules_json"] or "{}").get(name) or {})
                                                       .get("state") == "certified")})
    return {"platforms": rows, "coordinator_unsupported": modstore.coordinator_unsupported(info(name).manifest)}


def catalog_rows(db, with_goldens: bool = False) -> list[dict]:
    """Module rows for the console and /api/v1/modules: manifest facts plus host health."""
    out = []
    enabled_names = set(enabled(db))
    health = host(db).health() if db is not None else {}
    for name, i in CATALOG.items():
        m = i.manifest
        row = {"name": name, "id": m.module.id, "version": m.module.version, "compat": m.module.compat, "path": str(i.path),
               "has_ui": bool(m.ui.pages or m.ui.panels), "icon": m.ui.icon, "description": m.module.description,
               "stages": list(i.stages), "requires": sorted({s.name for s in m.services} | {p.name for p in m.probes}),
               "enabled": name in enabled_names, "host": health.get(name, {}), **platform_matrix(db, name)}
        if with_goldens:
            try:
                row["goldens"] = [g["name"] for g in goldens(db, name)]
            except (ModuleUnavailable, ModuleError) as e:
                row["goldens"] = [f"(module unavailable: {e.__class__.__name__})"]
        out.append(row)
    return out
