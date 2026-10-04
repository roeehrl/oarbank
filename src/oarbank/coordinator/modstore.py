"""The coordinator's module store (oarbank-sdk spec/bundles.md): a bundle is a digest, a lock pins it, and a canary
proves it.

A module arrives as a bundle (`oarbank-sdk bundle build`), is verified and unpacked into
`<OARBANKD_HOME>/modules/store/<name>/<version>-<digest12>/`, and is recorded in `modules`. Nothing is
enabled implicitly. Which version runs where is the `module_channels` row of each module:

- `current`: the version every node runs, and the one whose coordinator process serves the module;
- `previous`: kept for `rollback`, which flips the pointer back (in-flight jobs finish or are cancelled,
  never silently re-bound);
- `canary` + `canary_nodes`: a version staged on a few nodes first (their release carries it; they
  re-doctor and re-certify on its goldens), then `promote`d;
- `disabled`: the kill switch: no dispatch fleet-wide from the next claim, live attempts revoked.

`module_pins` pins one node to a version. The release a node installs is composed from these facts
(releases.compose_for); certification is keyed by the module's content digest, so any digest change
re-certifies that module on that node and nothing else.
"""
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from oarbank_sdk import bundle as B
from oarbank_sdk import manifest as mf
from oarbank_sdk import platform as pf
from oarbank_sdk import portable

from . import config as C
from .db import DB, jl

CORE_VERSION = "2.5.0"
MODULE_PROTOCOLS = {1}
RUNNER_PROTOCOLS = {1}
FEATURES = ("placement",)                  # requires.features this core implements (must-understand)


class InstallError(ValueError):
    pass


def store_dir(db: DB | None = None) -> Path:
    """Next to the database (production: <OARBANKD_HOME>/modules/store)."""
    return (Path(db.path).parent if db is not None else C.HOME) / "modules" / "store"


# ------------------------------------------------------------------ version ranges

def _ver(s: str) -> tuple:
    core = re.split(r"[-+]", s)[0]
    parts = [int(x) for x in core.split(".")[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def in_range(version: str, spec: str) -> bool:
    """`>=2.0,<3`-style ranges (comma = and; operators >=, >, <=, <, ==, !=, ~=, ^ or a bare version)."""
    v = _ver(version)
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        m = re.match(r"^(>=|<=|==|!=|~=|>|<|\^)?\s*([0-9][0-9A-Za-z.+-]*)$", part)
        if not m:
            raise InstallError(f"unparseable version range {spec!r}")
        op, want = m.group(1) or "==", _ver(m.group(2))
        ok = {">=": v >= want, "<=": v <= want, ">": v > want, "<": v < want, "==": v == want, "!=": v != want,
              "~=": v >= want and v[:2] == want[:2], "^": v >= want and v[0] == want[0]}[op]
        if not ok:
            return False
    return True


# ------------------------------------------------------------------ records

def installed(db: DB, name: str | None = None) -> list[dict]:
    rows = db.q("SELECT * FROM modules WHERE (? IS NULL OR name=?) ORDER BY name, installed_at", (name, name))
    for r in rows:
        r["manifest"] = jl(r.pop("manifest_json"), {})
        r["path"] = str(db.abs(r["path"]))
    return rows


def record(db: DB, name: str, version: str) -> dict | None:
    """An installed version (its `path` absolute)."""
    r = db.one("SELECT * FROM modules WHERE name=? AND version=?", (name, version))
    return {**r, "path": str(db.abs(r["path"]))} if r else None


def channel(db: DB, name: str) -> dict:
    r = db.one("SELECT * FROM module_channels WHERE name=?", (name,))
    if not r:
        return {"name": name, "current": None, "previous": None, "canary": None, "canary_nodes": [], "disabled": 0}
    return {**{k: v for k, v in r.items() if k != "canary_nodes_json"}, "canary_nodes": jl(r["canary_nodes_json"], []) or []}


def channels(db: DB) -> dict:
    return {r["name"]: channel(db, r["name"]) for r in db.q("SELECT name FROM module_channels ORDER BY name")}


def pins(db: DB, name: str | None = None) -> dict:
    return {(r["name"], r["node_id"]): r["version"]
            for r in db.q("SELECT * FROM module_pins WHERE (? IS NULL OR name=?)", (name, name))}


def _save_channel(db: DB, ch: dict):
    db.x("INSERT INTO module_channels(name,current,previous,canary,canary_nodes_json,disabled,updated_at) VALUES(?,?,?,?,?,?,?) "
         "ON CONFLICT(name) DO UPDATE SET current=excluded.current, previous=excluded.previous, canary=excluded.canary, "
         "canary_nodes_json=excluded.canary_nodes_json, disabled=excluded.disabled, updated_at=excluded.updated_at",
         (ch["name"], ch["current"], ch["previous"], ch["canary"], json.dumps(ch["canary_nodes"] or []),
          int(bool(ch["disabled"])), time.time()))


def version_for_node(db: DB, name: str, node_id: str | None) -> str | None:
    """Which version of a module a node runs: its pin, else the canary if it is a canary node, else current."""
    ch = channel(db, name)
    if node_id:
        p = db.one("SELECT version FROM module_pins WHERE name=? AND node_id=?", (name, node_id))
        if p:
            return p["version"]
        if ch["canary"] and node_id in ch["canary_nodes"]:
            return ch["canary"]
    return ch["current"]


def active_versions(db: DB) -> set[tuple[str, str]]:
    """Every (name, version) some node or the coordinator runs: current, canary and pinned versions."""
    out = set()
    for name, ch in channels(db).items():
        for v in (ch["current"], ch["canary"]):
            if v:
                out.add((name, v))
    out |= {(n, v) for (n, _), v in pins(db).items()}
    return out


# ------------------------------------------------------------------ install

def _field_types(man: dict) -> dict:
    return {f["name"]: f.get("type") for f in ((man.get("results") or {}).get("fields") or [])}


def _check_compatible(db: DB, info: B.BundleInfo):
    """A result field keeps its type within a major version (history stays comparable)."""
    new = _field_types(info.manifest.model_dump(mode="json"))
    major = _ver(info.version)[0]
    for r in installed(db, info.name):
        if r["module_id"] != info.module_id:
            raise InstallError(f"{info.name} is already installed as {r['module_id']}; module ids are not reused")
        if _ver(r["version"])[0] != major:
            continue
        old = _field_types(r["manifest"])
        changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])
        if changed:
            raise InstallError(f"result field type changed without a major version bump: {changed} "
                               f"({r['version']} -> {info.version})")


def coordinator_unsupported(man: mf.Manifest, platform: str | None = None) -> str | None:
    """Why the module's coordinator side does not run on `platform` (default: this coordinator's), or None
    (requires.coordinator_platforms; absent: every platform)."""
    platform = platform or portable.host_platform()
    plats = man.requires.coordinator_platforms
    if plats is None or platform in plats:
        return None
    why = pf.resolve(man.requires.unsupported.coordinator, platform)
    return f"its coordinator side does not run on {platform}: " + (why or f"requires.coordinator_platforms is {', '.join(plats)}")


def coordinator_blockers(db: DB, platform: str | None = None) -> dict:
    """{module: reason} for the enabled modules with an active version (current, canary, pinned: each runs a coordinator
    process) whose coordinator side does not run on `platform` (default: this coordinator's)."""
    on, out = set(enabled_names(db)), {}
    for name, ver in sorted(active_versions(db)):
        why = coordinator_unsupported(mf.load(Path(record(db, name, ver)["path"]) / "oarbank-module.toml"), platform) \
            if name in on and name not in out else None
        if why:
            out[name] = why
    return out


def _check_requires(man: mf.Manifest):
    req = man.requires
    if req.core and not in_range(CORE_VERSION, req.core):
        raise InstallError(f"needs core {req.core}; this is {CORE_VERSION}")
    if not set(req.module_protocol) & MODULE_PROTOCOLS:
        raise InstallError(f"speaks module protocol {req.module_protocol}; the core speaks {sorted(MODULE_PROTOCOLS)}")
    if not set(req.runner_protocol) & RUNNER_PROTOCOLS:
        raise InstallError(f"speaks runner protocol {req.runner_protocol}; the agent speaks {sorted(RUNNER_PROTOCOLS)}")
    unknown = [f for f in req.features if f not in FEATURES]
    if unknown:
        raise InstallError(f"requires features {unknown}, which core {CORE_VERSION} does not implement (it implements {list(FEATURES)})")
    why = coordinator_unsupported(man)
    if why:
        raise InstallError(why)


def _build_runtime(path: Path, man: "mf.Manifest | None" = None) -> str | None:
    """Coordinator dependencies (oarbank-sdk spec/bundles.md, "Dependencies"): the bundle's hash-pinned
    requirements.txt, installed from its own wheels/ into an overlay venv that sees the host's site packages (the SDK,
    pydantic). Offline, wheels only, every hash checked, nothing resolved, and inside the module sandbox (the bundle and
    the interpreter read-only, only the new venv writable, no network), so installing a module runs none of its code.
    Returns what was done, for the record."""
    from oarbank_sdk import deps
    from ..platform import files
    from . import modsandbox
    req = path / "requirements.txt"
    if not req.exists():
        return None
    man = man or mf.load(path / "oarbank-module.toml")
    try:
        deps.parse_requirements(req.read_text(encoding="utf-8"))
    except deps.DepsError as e:
        raise InstallError(f"requirements.txt: {e}")
    issues = [i for i in deps.check(path, man) if i.startswith("requirements.txt") or i.startswith("wheels/")]
    if issues:
        raise InstallError("dependencies: " + "; ".join(issues))
    uv = shutil.which("uv")
    if not uv:
        raise InstallError("uv is not available on this coordinator; it installs module dependencies")
    venv = path / ".venv"
    r = subprocess.run([uv, "venv", "--quiet", "--python", sys.executable, "--system-site-packages", "--no-config",
                        str(venv)], capture_output=True, text=True, timeout=300, env=_uv_env(path))
    if r.returncode != 0:
        raise InstallError(f"coordinator environment: {(r.stderr or r.stdout)[-800:]}")
    _link_host_env(venv)
    argv = [uv, "pip", "install", "--quiet", "--no-config", "--python", str(files.venv_python(venv)),
            *deps.install_args(path, req)]
    tmp = path.parent / f".{path.name}.install-tmp"
    files.private_dir(tmp)
    try:
        if modsandbox.backend() is None:
            raise InstallError("no module sandbox backend on this OS: dependencies are not installed unconfined")
        argv = _sandboxed_install(argv, path, venv, tmp, man.module.id, uv)
        r = subprocess.run(argv, capture_output=True, text=True, timeout=900, env=_uv_env(tmp), cwd=str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if r.returncode != 0:
        shutil.rmtree(venv, ignore_errors=True)
        raise InstallError(f"coordinator dependencies failed: {(r.stderr or r.stdout)[-800:]}")
    return "venv+wheels"


def _link_host_env(venv: Path):
    """The module environment overlays the coordinator's own (the SDK, pydantic): a .pth that adds the coordinator's
    site directories, processed like any site directory (editable installs included). The module's wheels come first."""
    import sysconfig
    site_dir = next(venv.glob("lib/python*/site-packages"), None) or venv / "Lib" / "site-packages"
    host = []
    for k in ("purelib", "platlib"):
        d = sysconfig.get_paths()[k]
        if d not in host and Path(d).resolve() != site_dir.resolve():
            host.append(d)
    (site_dir / "_oarbank_host.pth").write_text("".join(f"import site; site.addsitedir({d!r})\n" for d in host))


def _uv_env(home: Path) -> dict:
    """A clean environment for uv: no user configuration, no index, no inherited proxy or credentials."""
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home) + "/", "UV_NO_CONFIG": "1",
            "UV_OFFLINE": "1", "UV_NO_CACHE": "1", "UV_PYTHON_DOWNLOADS": "never", "LANG": "C.UTF-8"}


def _sandboxed_install(argv: list[str], bundle: Path, venv: Path, tmp: Path, module_id: str, uv: str) -> list[str]:
    from oarbank_sdk import sandbox as S
    from ..platform import files
    # the venv's interpreter is a symlink chain into the host's Python: listing it gives each hop a metadata rule
    pol = S.Policy(module=module_id, ro=[str(bundle), *S.interpreter_roots(), str(Path(uv).resolve().parent),
                                         str(files.venv_python(venv))],
                   rw=[str(venv), str(tmp)], kind="install", exe=uv)
    from . import sandboxexec
    return sandboxexec.wrap(pol, tmp / "install.sb", argv)


def _self_test(info: B.BundleInfo, path: Path):
    """Spawn the coordinator once and complete the initialize handshake (a module that cannot start is refused)."""
    from . import modsandbox
    from .modulehost import ModuleHost, ModuleUnavailable
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        h = ModuleHost([modsandbox.coordinator_spec(Path(td), info.name, info.manifest, path)], home=Path(td))
        try:
            h._ensure(info.name)
        except ModuleUnavailable as e:
            raise InstallError(f"self-test failed: {e}")
        finally:
            h.close()


def install(db: DB, bundle_path, actor: str = "oarbank", self_test: bool = True) -> dict:
    """Verify and unpack a bundle into the store. Idempotent for the same bytes; a version is immutable
    (the same version with a different digest is refused). Enables nothing."""
    bundle_path = Path(bundle_path)
    try:
        info = B.verify(bundle_path)
    except B.BundleError as e:
        raise InstallError(f"bundle rejected: {e}")
    prev = record(db, info.name, info.version)
    if prev:
        if prev["content_digest"] != info.content_digest:
            raise InstallError(f"{info.name} {info.version} is installed with digest {prev['content_digest']}; "
                               f"versions are immutable (bump the version)")
        return {"name": info.name, "version": info.version, "content_digest": info.content_digest, "path": prev["path"],
                "already_installed": True}
    _check_requires(info.manifest)
    _check_compatible(db, info)
    dest = store_dir(db) / info.name / f"{info.version}-{info.short_digest}"
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    B.verify(bundle_path, dest)
    bad = B.check_sdk_only(dest)
    if bad:
        shutil.rmtree(dest)
        raise InstallError("module code imports the core:\n  " + "\n  ".join(bad))
    try:
        runtime = _build_runtime(dest, info.manifest)
        if self_test:
            _self_test(info, dest)
    except InstallError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    size = sum((dest / f["path"]).stat().st_size for f in info.files)
    with db.tx():
        db.x("INSERT INTO modules(name,version,module_id,compat,content_digest,path,manifest_json,installed_at,installed_by,runtime,"
             "bundle_files,bundle_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
             (info.name, info.version, info.module_id, info.compat, info.content_digest, db.rel(dest),
              json.dumps(info.manifest.model_dump(mode="json", by_alias=True)), time.time(), actor, runtime,
              len(info.files), size))
        db.event("module_installed", actor=actor, reason=f"{info.name} {info.version}", digest=info.content_digest)
    return {"name": info.name, "version": info.version, "content_digest": info.content_digest, "path": str(dest)}


def verify_installed(db: DB, name: str | None = None) -> list[dict]:
    """Re-verify every installed bundle directory against its recorded digest (tamper check)."""
    out = []
    for r in installed(db, name):
        try:
            info = B.verify_dir(r["path"])
            ok = info.content_digest == r["content_digest"]
            out.append({"name": r["name"], "version": r["version"], "ok": ok,
                        "detail": "ok" if ok else f"digest {info.content_digest} != recorded {r['content_digest']}"})
        except (B.BundleError, OSError, ValueError) as e:
            out.append({"name": r["name"], "version": r["version"], "ok": False, "detail": str(e)[:300]})
    return out


# ------------------------------------------------------------------ lifecycle

class LifecycleError(ValueError):
    pass


def _need(db, name, version):
    if not record(db, name, version):
        raise LifecycleError(f"{name} {version} is not installed")


def _may_run(db: DB, name: str, version: str):
    """A version may run (enable, canary, promote, pin): its sandbox grants are approved and its coordinator side runs
    on this coordinator's platform (every active version has a coordinator process)."""
    from . import modsandbox
    try:
        modsandbox.require_approved(db, name, version)
    except modsandbox.GrantError as e:
        raise LifecycleError(str(e))
    _runs_here(db, name, version)


def _runs_here(db: DB, name: str, version: str):
    why = coordinator_unsupported(mf.load(Path(record(db, name, version)["path"]) / "oarbank-module.toml"))
    if why:
        raise LifecycleError(f"{name} {version}: {why}")


def enable(db: DB, name: str, version: str) -> dict:
    """First enable of a module (no current version yet), or re-enable after `disable`."""
    ch = channel(db, name)
    if version is None:
        version = ch["current"]
    _need(db, name, version)
    _may_run(db, name, version)
    if ch["current"] and ch["current"] != version:
        raise LifecycleError(f"{name} runs {ch['current']}; stage {version} with a canary, then promote")
    ch.update(current=version, disabled=0)
    _save_channel(db, ch)
    return ch


def canary(db: DB, name: str, version: str, nodes: list[str]) -> dict:
    ch = channel(db, name)
    _need(db, name, version)
    if not ch["current"]:
        raise LifecycleError(f"{name} has no current version; enable one first")
    if version == ch["current"]:
        raise LifecycleError(f"{name} {version} is already current")
    if not nodes:
        raise LifecycleError("a canary needs at least one node")
    _may_run(db, name, version)
    ch.update(canary=version, canary_nodes=sorted(set(nodes)))
    _save_channel(db, ch)
    return ch


def promote(db: DB, name: str) -> dict:
    ch = channel(db, name)
    if not ch["canary"]:
        raise LifecycleError(f"{name} has no canary to promote")
    _may_run(db, name, ch["canary"])
    ch.update(previous=ch["current"], current=ch["canary"], canary=None, canary_nodes=[])
    _save_channel(db, ch)
    return ch


def rollback(db: DB, name: str) -> dict:
    ch = channel(db, name)
    if ch["canary"]:                                     # abandoning a canary: its nodes return to current
        ch.update(canary=None, canary_nodes=[])
    elif ch["previous"]:
        _runs_here(db, name, ch["previous"])
        ch.update(current=ch["previous"], previous=ch["current"])
    else:
        raise LifecycleError(f"{name} has no previous version or canary to roll back")
    _save_channel(db, ch)
    return ch


def disable(db: DB, name: str) -> dict:
    ch = channel(db, name)
    if not ch["current"]:
        raise LifecycleError(f"{name} is not enabled")
    ch["disabled"] = 1
    _save_channel(db, ch)
    return ch


def pin(db: DB, name: str, node_id: str, version: str | None) -> dict:
    if version is None:
        db.x("DELETE FROM module_pins WHERE name=? AND node_id=?", (name, node_id))
    else:
        _need(db, name, version)
        _may_run(db, name, version)
        db.x("INSERT INTO module_pins(name,node_id,version) VALUES(?,?,?) ON CONFLICT(name,node_id) DO UPDATE SET "
             "version=excluded.version", (name, node_id, version))
    return {"name": name, "node_id": node_id, "version": version}


def disabled_names(db: DB) -> set[str]:
    return {r["name"] for r in db.q("SELECT name FROM module_channels WHERE disabled=1")}


def enabled_names(db: DB) -> list[str]:
    return [r["name"] for r in db.q("SELECT name FROM module_channels WHERE current IS NOT NULL AND disabled=0 ORDER BY name")]


def bundle_path(db: DB, name: str, version: str) -> Path | None:
    r = record(db, name, version)
    return Path(r["path"]) if r else None


def dev_install_dir(db: DB, src_dir, actor: str = "dev", enable_now: bool = True) -> dict:
    """Build a bundle from a module source directory and install (and enable) it: tests and local development."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out, _ = B.build(src_dir, Path(td) / "m.mfb")
        r = install(db, out, actor=actor, self_test=False)
    if enable_now and not channel(db, r["name"])["current"]:
        enable(db, r["name"], r["version"])
    return r

