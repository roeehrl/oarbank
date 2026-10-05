"""oarbank-console: the admin console as its own read-only process (PLAN D10, D11, D14, D15).

Reads come from its own SQLite snapshot (state.ConsoleState) and drill-down pool; computed module views
(module rows, operation metadata) come from oarbankd's admin API. Every change is an operation forwarded to
oarbankd (POST /api/v1/ops/<op>) with the viewer's identity, so the console can do nothing the API
cannot, and oarbankd audits the real actor with source=gui. T0/T1 apply directly (T1 confirms in the
browser), T2/T3 go through a plan page and apply the reviewed plan id.

Security (access.py): loopback bind by default; a Host allowlist; Funnel traffic refused; every page needs a signed-in
session (password + TOTP, a passkey, or a one-time link from `oarbank console login`), an HttpOnly SameSite=Strict
cookie whose CSRF token every form and htmx request carries; strict CSP (no inline script); Fetch Metadata and Origin
checks; no CORS. Identity headers are never trusted.
"""
import asyncio
import contextlib
import hmac
import json
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import anyio
import httpx
import jinja2
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..contracts import operations as registry
from . import forms, views
from .state import ConsoleState

HERE = Path(__file__).parent
# a download is never rendered in the console origin: an attachment, nosniff, and a sandbox if a browser opens it anyway
DOWNLOAD_HEADERS = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'"}


class _ZipSink:
    """A write-only file object for zipfile (no seek: zipfile then writes data descriptors), drained by zip_chunks."""

    def __init__(self):
        self.buf = bytearray()

    def write(self, b) -> int:
        self.buf += b
        return len(b)

    def flush(self):
        pass

    def take(self) -> bytes:
        out = bytes(self.buf)
        self.buf.clear()
        return out


def zip_chunks(files: list[tuple[str, Path]]):
    """A stored (uncompressed) ZIP64 archive of `files` ((name in the archive, file)), produced as it streams."""
    import zipfile
    sink = _ZipSink()
    with zipfile.ZipFile(sink, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
        for name, path in files:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            with open(path, "rb") as src, zf.open(info, "w", force_zip64=True) as dst:
                while b := src.read(1 << 20):
                    dst.write(b)
                    if len(sink.buf) >= 1 << 20:
                        yield sink.take()
            yield sink.take()
    yield sink.take()


def zip_response(files, filename: str):
    return StreamingResponse(zip_chunks(files), media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"', **DOWNLOAD_HEADERS})


SSE_PING_S, SSE_HEARTBEAT_S, SSE_MAX_CLIENTS = 15, 5, 16


def _secs(s):
    if s is None:
        return "–"
    s = float(s)
    if s < 90:
        return f"{s:.0f}s"
    if s < 5400:
        return f"{s / 60:.0f}m"
    if s < 172800:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"


def _num(v, digits=0):
    try:
        if v is None or v != v:
            return "–"
        v = float(v)
    except Exception:
        return "–"
    return f"{v:.{digits}f}"


def templates() -> Jinja2Templates:
    t = Jinja2Templates(directory=str(HERE / "templates"))
    t.env.filters.update(
        num=_num, secs=_secs, ts=lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "–", ago=lambda ts: (_secs(time.time() - ts) + " ago") if ts else "never",
        hm=lambda ts: time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "",
        fromjson=lambda s: json.loads(s) if s else {},
    )
    t.env.tests["known"] = lambda v: v is not None and not isinstance(v, jinja2.Undefined)   # reported, not missing or null
    t.env.globals.update(new_key=lambda: uuid.uuid4().hex, OPS=registry.REGISTRY, CAMPAIGN_OPS=registry.CAMPAIGN_OPS)
    return t


class Forbidden(Exception):
    pass


class NeedLogin(Exception):
    pass


SESSION_COOKIE = "oarbank_session"
TOUCH_EVERY_S = 60
SESSION_PATHS = ("/login", "/logout", "/static/", "/static-ui/", "/healthz")


def console_app(state: ConsoleState, attempt_log_dir: Path | None = None,
                module_origin: str = "http://127.0.0.1:7402") -> FastAPI:
    from oarbank_sdk.render import CSS_PATH, HERE as RENDER_HERE, console_csp, render_page
    from oarbank_sdk import ui as U
    from . import modpages
    http = httpx.AsyncClient(base_url=state.coordinator_url, timeout=3600)
    catalog = modpages.ModuleCatalog()
    from .media import Tokens
    tokens = Tokens()
    caches = {"ops": ({}, 0.0), "mods": 0.0}
    policy = console_csp(module_origin)
    @contextlib.asynccontextmanager
    async def lifespan(app):
        state.bind_loop(asyncio.get_running_loop())
        yield
        await http.aclose()

    app = FastAPI(title="Oarbank console", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def refresh_catalog_sync():
        r = httpx.get(state.coordinator_url + "/api/v1/modules", headers=state.coordinator_headers("console"), timeout=5)
        if r.status_code == 200:
            catalog.update(r.json())
    app.state.catalog, app.state.refresh_catalog_sync, app.state.media_tokens = catalog, refresh_catalog_sync, tokens

    @app.get("/static-ui/ui.css")
    async def ui_css():
        return Response(CSS_PATH.read_text(), media_type="text/css")

    @app.get("/static-ui/ui.js")
    async def ui_js():
        return Response((RENDER_HERE / "static" / "ui.js").read_text(), media_type="text/javascript")
    T = templates()
    limiter = anyio.CapacityLimiter(3)
    clients = {"n": 0}
    log_dir = Path(attempt_log_dir) if attempt_log_dir else Path(state.db_path).parent / "attempt-logs"

    # ------------------------------------------------------------------ security
    from ..coordinator import access as A

    def session(request: Request) -> dict | None:
        return A.session_for(state.reader, request.cookies.get(SESSION_COOKIE))

    touching: set = set()

    async def touch(sid: str):
        """A session in use stays signed in: oarbankd restarts its idle timeout, at most once a minute (the console
        cannot write the database)."""
        try:
            await http.post("/api/v1/access/touch", json={"sid": sid}, headers=state.coordinator_headers("console"))
        except httpx.HTTPError:
            pass
        finally:
            touching.discard(sid)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if A.via_funnel(request.headers):
            return JSONResponse({"error": "forbidden", "detail": "requests from Tailscale Funnel are refused"}, status_code=403)
        port = (request.scope.get("server") or (None, None))[1]
        if not A.host_ok(request.headers.get("host"), A.allowed_hosts(port, state.reader.get_setting("console_hosts") or [])
                         | A.TEST_HOSTS):
            return JSONResponse({"error": "bad_host", "detail": "this host name is not allowed (setting console_hosts)"},
                                status_code=421)
        path = request.url.path
        sid = request.cookies.get(SESSION_COOKIE)
        if sid and sid not in touching and (s := session(request)) and time.time() - s["last_seen"] > TOUCH_EVERY_S:
            touching.add(sid)
            asyncio.get_running_loop().create_task(touch(sid))
        if request.method not in ("GET", "HEAD", "OPTIONS") and not path.startswith(("/do/", "/apply/", "/api/")) \
                and not path.startswith(SESSION_PATHS) and not path.startswith("/login") and not path.startswith("/account/passkey"):
            sess = session(request)
            if not sess or request.headers.get("x-csrf-token") != sess["csrf"]:
                return JSONResponse({"error": "csrf", "detail": "missing or wrong CSRF token"}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            site = request.headers.get("sec-fetch-site")
            origin = request.headers.get("origin")
            host = request.headers.get("host")
            if site and site not in ("same-origin", "none"):
                return JSONResponse({"error": "csrf", "detail": f"sec-fetch-site {site}"}, status_code=403)
            if not site and origin and origin.split("://", 1)[-1] != host:
                return JSONResponse({"error": "csrf", "detail": f"origin {origin}"}, status_code=403)
        resp = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", policy)
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if not request.url.path.startswith("/static/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(Forbidden)
    async def _forbidden(request, e):
        return JSONResponse({"error": "forbidden", "detail": str(e)}, status_code=403)

    @app.exception_handler(NeedLogin)
    async def _need_login(request, e):
        if request.method == "GET" and not request.headers.get("hx-request") \
                and not request.url.path.startswith(("/frag/", "/sse", "/api/")):
            return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)
        return JSONResponse({"error": "unauthenticated", "detail": "sign in to the console"}, status_code=401,
                            headers={"HX-Redirect": "/login"})

    def who(request: Request) -> str:
        """The signed-in account (a session cookie); never an identity header, never "local"."""
        sess = session(request)
        if not sess:
            raise NeedLogin()
        request.state.session = sess
        return sess["account"]

    def csrf_ok(request: Request, form) -> bool:
        sess = getattr(request.state, "session", None) or session(request)
        got = (form.get("csrf") if form is not None else None) or request.headers.get("x-csrf-token")
        return bool(sess and got and hmac.compare_digest(str(got), sess["csrf"]))

    def page_context(request, ctx: dict) -> dict:
        """What every template gets, a full page or a fragment alike (the fragments the pages refresh carry forms, whose
        csrf field must be the session's): the session's account, role and CSRF token, the console's meta, the flash
        message and the coordinator banner, then `ctx`."""
        sess = getattr(request.state, "session", None)
        base = {"actor": sess["account"] if sess else "", "meta": state.meta(),
                "flash": request.query_params.get("flash"), "flash_kind": request.query_params.get("kind", "ok"),
                "csrf": sess["csrf"] if sess else "", "role": sess["role"] if sess else ""}
        try:
            with state.pool.get() as r:                   # a pending coordinator move is never silent
                base["coord"] = views.coordinator_banner(r)
        except Exception:
            base["coord"] = None
        return {**base, **{k: v for k, v in ctx.items() if not (k == "actor" and not v)}}

    def render(request, name, ctx, status=200):
        return T.TemplateResponse(request, name, page_context(request, ctx), status_code=status)

    async def drill(fn, *args):
        def run():
            with state.pool.get() as r:
                return fn(r, *args)
        try:
            return await anyio.to_thread.run_sync(run, limiter=limiter)
        except TimeoutError:
            return None

    def fragment(request, name: str, ctx: dict) -> str:
        """Render a hot fragment once per snapshot version and session, and share it between that session's requests
        (the console gate): its forms carry the session's CSRF token and what it shows depends on its role."""
        full = page_context(request, ctx)
        key = (name, state.version, json.dumps(sorted(ctx.get("_key", {}).items())), full["csrf"], full["role"], full["actor"])
        html = state.render_cache.get(key)
        if html is None:
            html = T.get_template(name).render({**full, "request": request})
            state.render_cache[key] = html
            state.renders += 1
        return html

    async def coordinator_json(method, path, actor, headers_extra=None, **kw):
        """A call to oarbankd's admin API; a coordinator that is down answers 503 instead of raising."""
        try:
            return await http.request(method, path, headers={**state.coordinator_headers(actor), **(headers_extra or {})}, **kw)
        except httpx.HTTPError as e:
            return httpx.Response(503, json={"error": "coordinator_unreachable", "detail": type(e).__name__})

    # ------------------------------------------------------------------ sign-in (access.py; ceremonies run in oarbankd)
    def _cookie(resp: Response, request: Request, sess: dict):
        resp.set_cookie(SESSION_COOKIE, sess["sid"], httponly=True, samesite="strict", path="/",
                        secure=request.url.scheme == "https", max_age=int(A.SESSION_TTL_S))
        return resp

    def _next(request: Request, nxt: str | None) -> str:
        nxt = nxt or "/"
        return nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"

    async def _ceremony(path: str, request: Request, body: dict, actor: str | None = None):
        h = state.coordinator_headers(actor or "console")
        h["x-oarbank-user-agent"] = (request.headers.get("user-agent") or "")[:200]
        try:
            return await http.post(path, json=body, headers=h)
        except httpx.HTTPError as e:
            return httpx.Response(503, json={"error": "coordinator_unreachable", "detail": type(e).__name__})

    def _login_page(request: Request, error: str = "", status: int = 200):
        accounts = state.reader.q("SELECT COUNT(*) n FROM accounts")[0]["n"]
        return T.TemplateResponse(request, "login.html", {"error": error, "next": _next(request, request.query_params.get("next")),
                                                          "no_accounts": accounts == 0, "meta": state.meta()}, status_code=status)

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return _login_page(request)

    @app.post("/login")
    async def login(request: Request):
        form = await request.form()
        r = await _ceremony("/api/v1/access/login", request, {"name": form.get("name"), "password": form.get("password"),
                                                               "code": form.get("code")})
        if r.status_code != 200:
            return _login_page(request, "Wrong account, password or code, or the account is locked.", 401)
        return _cookie(RedirectResponse(_next(request, form.get("next")), status_code=303), request, r.json())

    @app.get("/login/link")
    async def login_link(request: Request):
        """A one-time link from `oarbank console login`: it signs in once, then the URL is dead."""
        r = await _ceremony("/api/v1/access/link", request, {"t": request.query_params.get("t") or ""})
        if r.status_code != 200:
            return _login_page(request, "This sign-in link is used or expired. Run `oarbank console login` again.", 401)
        return _cookie(RedirectResponse("/", status_code=303), request, r.json())

    @app.post("/login/passkey/options")
    async def passkey_login_options(request: Request):
        r = await _ceremony("/api/v1/access/passkey/options", request,
                            {"purpose": "login", "host": request.headers.get("host"), "scheme": request.url.scheme})
        return JSONResponse(r.json(), status_code=r.status_code)

    @app.post("/login/passkey")
    async def passkey_login(request: Request):
        b = await request.json()
        r = await _ceremony("/api/v1/access/passkey/login", request,
                            {"challenge_id": b.get("challenge_id"), "credential": b.get("credential"),
                             "host": request.headers.get("host"), "scheme": request.url.scheme})
        if r.status_code != 200:
            return JSONResponse({"error": "bad_login", "detail": "the passkey was not accepted"}, status_code=401)
        return _cookie(JSONResponse({"ok": True, "next": _next(request, b.get("next"))}), request, r.json())

    @app.post("/logout")
    async def logout(request: Request):
        form = await request.form()
        sess = session(request)
        if sess and hmac.compare_digest(str(form.get("csrf") or ""), sess["csrf"]):
            await _ceremony("/api/v1/access/logout", request, {"sid": request.cookies.get(SESSION_COOKIE)})
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.post("/account/passkey/options")
    async def passkey_register_options(request: Request):
        actor = who(request)
        if request.headers.get("x-csrf-token") != request.state.session["csrf"]:
            return JSONResponse({"error": "csrf"}, status_code=403)
        r = await _ceremony("/api/v1/access/passkey/options", request,
                            {"purpose": "register", "account": actor, "host": request.headers.get("host"),
                             "scheme": request.url.scheme})
        return JSONResponse(r.json(), status_code=r.status_code)

    @app.post("/account/passkey")
    async def passkey_register(request: Request):
        actor = who(request)
        if request.headers.get("x-csrf-token") != request.state.session["csrf"]:
            return JSONResponse({"error": "csrf"}, status_code=403)
        b = await request.json()
        r = await _ceremony("/api/v1/access/passkey/register", request,
                            {"challenge_id": b.get("challenge_id"), "credential": b.get("credential"), "label": b.get("label"),
                             "host": request.headers.get("host"), "scheme": request.url.scheme}, actor=actor)
        return JSONResponse(r.json(), status_code=r.status_code)

    @app.get("/account", response_class=HTMLResponse)
    async def account_page(request: Request):
        actor = who(request)
        r = await coordinator_json("GET", "/api/v1/access", actor)
        v = r.json() if r.status_code == 200 else {"accounts": [], "tokens": [], "passkeys": [], "me": {"account": actor}}
        return render(request, "account.html", {**v, "actor": actor, "host": request.headers.get("host") or ""})

    @app.get("/access", response_class=HTMLResponse)
    async def access_page(request: Request):
        actor = who(request)
        r = await coordinator_json("GET", "/api/v1/access", actor)
        v = r.json() if r.status_code == 200 else {"accounts": [], "tokens": [], "passkeys": []}
        return render(request, "access.html", {**v, "actor": actor})

    # ------------------------------------------------------------------ pages
    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        actor = who(request)
        body = fragment(request, "_fleet_body.html", {**state.snapshot, "actor": actor})
        return render(request, "fleet.html", {"body": body, "actor": actor})

    @app.get("/frag/fleet", response_class=HTMLResponse)
    async def frag_fleet(request: Request):
        actor = who(request)
        return HTMLResponse(fragment(request, "_fleet_body.html", {**state.snapshot, "actor": actor}))

    @app.get("/nodes/{nid}", response_class=HTMLResponse)
    async def node(nid: str, request: Request):
        actor = who(request)
        d = await drill(views.node_page, nid, time.time())
        if d is None:
            return render(request, "error.html", {"message": f"node {nid} not found (or the database is busy)", "actor": actor}, 404)
        d["panels"] = await panels("node.detail.panel", request, actor,
                                   {"node": {"id": nid, "node_id": nid, "online": d["n"]["online"]}})
        return render(request, "node.html", {**d, "actor": actor})

    @app.get("/nodes/{nid}/protection", response_class=HTMLResponse)
    async def node_protection(nid: str, request: Request):
        actor = who(request)
        d = await drill(views.protection_page, nid, time.time())
        if d is None:
            return render(request, "error.html", {"message": f"node {nid} not found (or the database is busy)", "actor": actor}, 404)
        return render(request, "protection.html", {**d, "actor": actor})

    @app.get("/frag/nodes/{nid}/protection/preview", response_class=HTMLResponse)
    async def node_protection_preview(nid: str, request: Request):
        """Live preview while editing: pure computation over a read connection (a GET: the console has no
        write path, and nothing here writes)."""
        who(request)
        try:
            cfg = json.loads(request.query_params.get("pj.config") or "{}")
            p = await drill(views.protection_preview, nid, cfg)
            ctx = {"p": p} if p is not None else {"error": "the database is busy; retrying on the next keystroke"}
        except (ValueError, TypeError) as e:
            ctx = {"error": str(e)[:600]}
        # rendered per request (depends on the typed text), never through the shared fragment cache
        return HTMLResponse(T.get_template("_protection_preview.html").render({**page_context(request, ctx), "request": request}))

    @app.get("/campaigns", response_class=HTMLResponse)
    async def campaigns(request: Request, module: str = "", state_: str = ""):
        actor = who(request)
        st = request.query_params.get("state", state_)
        return render(request, "campaigns.html", {**(await drill(views.campaigns_page, module, st) or {}), "actor": actor})

    async def campaign_ctx(cid, request, actor):
        d = await drill(views.campaign_page, cid, time.time())
        if d is None:
            return None
        await refresh_catalog(actor)
        man = catalog.manifest(d["c"]["module"])
        d["result_cols"] = views.result_columns(d["results"], man.results.fields if man else None)
        # the owning module's campaign panel (its own view of what the campaign means)
        d["panels"] = [p for p in await panels("campaign.panel", request, actor,
                                               {"campaign": {"id": cid, "campaign_id": cid, "module": d["c"]["module"],
                                                             "state": d["c"]["state"]}})
                       if p["module"] == d["c"]["module"]]
        return d

    @app.get("/campaigns/{cid}", response_class=HTMLResponse)
    async def campaign(cid: str, request: Request):
        actor = who(request)
        d = await campaign_ctx(cid, request, actor)
        if d is None:
            return render(request, "error.html", {"message": f"campaign {cid} not found (or the database is busy)", "actor": actor}, 404)
        return render(request, "campaign.html", {**d, "actor": actor})

    @app.get("/frag/campaign/{cid}", response_class=HTMLResponse)
    async def frag_campaign(cid: str, request: Request):
        actor = who(request)
        d = await campaign_ctx(cid, request, actor)
        if d is None:
            return HTMLResponse('<p class="mut">campaign unavailable</p>', status_code=503)
        return render(request, "_campaign_body.html", {**d, "actor": actor})

    @app.get("/jobs", response_class=HTMLResponse)
    async def jobs(request: Request, state_: str = "", campaign: str = "", node: str = ""):
        actor = who(request)
        st = request.query_params.get("state", state_)
        return render(request, "jobs.html", {**(await drill(views.jobs_page, st, campaign, node, time.time()) or {}), "actor": actor})

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    async def job(jid: int, request: Request):
        actor = who(request)
        d = await drill(views.job_page, jid, log_dir)
        if d is None:
            return render(request, "error.html", {"message": f"job {jid} not found", "actor": actor}, 404)
        d["panels"] = await panels("job.detail.panel", request, actor,
                                   {"job": {"id": jid, "job_id": jid, "module": d["j"]["module"], "state": d["j"]["state"]}})
        return render(request, "job.html", {**d, "actor": actor})

    # ------------------------------------------------------------------ datasets: browse, download, upload
    home = Path(state.db_path).parent

    @app.get("/datasets", response_class=HTMLResponse)
    async def datasets_list(request: Request, kind: str = "", module: str = ""):
        actor = who(request)
        return render(request, "datasets.html", {**(await drill(views.datasets_page, kind, module) or {"datasets": []}),
                                                 "actor": actor})

    @app.get("/datasets/upload", response_class=HTMLResponse)
    async def dataset_upload_page(request: Request, module: str = "", kind: str = "", then: str = "", return_to: str = ""):
        """The folder upload; a module page's upload link fills in its module and kind, and names the importer operation
        to offer once the dataset is registered (`then`, checked again by /m/<module>/_import)."""
        actor = who(request)
        await refresh_catalog(actor)
        kinds = {n: list(catalog.manifest(n).datasets.kinds) for n in catalog.rows if catalog.manifest(n)}
        kinds = {n: k for n, k in kinds.items() if k}
        pre = {"module": module, "kind": kind} if kind in kinds.get(module, []) else {}
        if pre and then.startswith(f"mod.{module.replace('-', '_')}."):
            pre["next"] = f"/m/{module}/_import?" + urlencode({"op": then, "return_to": return_to if return_to.startswith("/")
                                                                  and not return_to.startswith("//") else f"/modules/{module}"})
        return render(request, "dataset_upload.html", {"module_kinds": kinds, "pre": pre, "actor": actor})

    @app.get("/datasets/{did:path}/files/{path:path}")
    async def dataset_file(did: str, path: str, request: Request):
        who(request)
        files = await drill(views.dataset_files, home, did)
        hit = next((f for name, f in files or [] if name == path), None)
        if hit is None:
            return render(request, "error.html", {"message": f"{did} has no file {path} on the coordinator"}, 404)
        return FileResponse(hit, media_type="application/octet-stream", filename=Path(path).name, headers=DOWNLOAD_HEADERS)

    @app.get("/datasets/{did:path}/download.zip")
    async def dataset_zip(did: str, request: Request):
        who(request)
        files = await drill(views.dataset_files, home, did)
        if files is None:
            return render(request, "error.html", {"message": f"dataset {did} not found"}, 404)
        return zip_response(files, did.replace(":", "_").replace("/", "_") + ".zip")

    @app.get("/datasets/{did:path}", response_class=HTMLResponse)
    async def dataset_detail(did: str, request: Request):
        actor = who(request)
        d = await drill(views.dataset_page, did)
        if d is None:
            return render(request, "error.html", {"message": f"dataset {did} not found", "actor": actor}, 404)
        return render(request, "dataset.html", {**d, "actor": actor})

    @app.get("/campaigns/{cid}/artifacts.zip")
    async def campaign_zip(cid: str, request: Request):
        who(request)
        return zip_response(await drill(views.campaign_files, home, cid) or [], f"{cid}-artifacts.zip")

    @app.post("/datasets/uploads/{digest}")
    async def stage_begin(digest: str, request: Request):
        """A browser upload's blob staging (static/upload.js): forwarded to oarbankd with the account's identity."""
        actor = who(request)
        r = await coordinator_json("POST", f"/api/v1/uploads/{digest}", actor, content=await request.body(),
                                   headers_extra={"content-type": "application/json"})
        return Response(r.content, status_code=r.status_code, media_type="application/json",
                        headers={k: v for k, v in r.headers.items() if k.lower().startswith("upload-")})

    @app.patch("/datasets/uploads/{digest}")
    async def stage_append(digest: str, request: Request):
        actor = who(request)
        r = await coordinator_json("PATCH", f"/api/v1/uploads/{digest}", actor, content=request.stream(),
                                   headers_extra={"upload-offset": request.headers.get("upload-offset") or "",
                                                  "content-type": "application/offset+octet-stream"})
        return Response(r.content, status_code=r.status_code, media_type=r.headers.get("content-type"),
                        headers={k: v for k, v in r.headers.items() if k.lower().startswith("upload-")})

    @app.get("/events", response_class=HTMLResponse)
    async def events(request: Request, kind: str = "", before: int | None = None):
        actor = who(request)
        return render(request, "events.html", {**(await drill(views.events_page, kind, before) or {}), "actor": actor})

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request, op: str = "", target: str = "", before: int | None = None):
        actor = who(request)
        return render(request, "audit.html", {**(await drill(views.audit_page, op, target, before) or {}), "actor": actor})

    @app.get("/settings", response_class=HTMLResponse)
    async def settings(request: Request):
        actor = who(request)
        d = await drill(views.settings_page) or {"s": {}, "releases": [], "dscount": []}
        mods = await coordinator_json("GET", "/api/v1/modules", actor)
        d["modules"] = mods.json() if mods.status_code == 200 else []
        return render(request, "settings.html", {**d, "actor": actor})

    @app.get("/explain/{kind}/{ident}", response_class=HTMLResponse)
    async def explain_page(kind: str, ident: str, request: Request):
        actor = who(request)
        r = await coordinator_json("GET", f"/api/v1/explain/{kind}/{ident}", actor)
        if r.status_code != 200:
            return render(request, "error.html", {"message": f"explain {kind} {ident}: {r.text[:200]}", "actor": actor}, r.status_code)
        return render(request, "explain.html", {"doc": r.json(), "actor": actor})

    @app.get("/verify", response_class=HTMLResponse)
    async def verify(request: Request):
        actor = who(request)

        def load(r):
            return {"conds": r.get_setting("invariant_conditions") or [],
                    "alerts": r.q("SELECT * FROM alerts WHERE rule LIKE 'invariant:%' ORDER BY opened_at DESC LIMIT 50")}
        return render(request, "verify.html", {**(await drill(load) or {"conds": [], "alerts": []}), "actor": actor})

    async def refresh_catalog(actor, force=False):
        if force or time.time() - caches["mods"] > 30 or not catalog.rows:
            try:
                r = await coordinator_json("GET", "/api/v1/modules", actor)
            except httpx.HTTPError:
                return                                   # coordinator down: keep the last catalogue
            if r.status_code == 200:
                catalog.update(r.json())
                caches["mods"] = time.time()

    async def ops_meta(actor):
        ops, at = caches["ops"]
        if time.time() - at > 30 or not ops:
            try:
                r = await coordinator_json("GET", "/api/v1/ops", actor)
            except httpx.HTTPError:
                return ops
            if r.status_code == 200:
                ops = {o["id"]: {"id": o["id"], "title": o["summary"], "tier": o["tier"], "summary": o["summary"],
                                 "min_role": o["min_role"]} for o in r.json()}
                caches["ops"] = (ops, time.time())
        return ops

    # ------------------------------------------------------------------ module pages, panels and frames (D23, D41)
    async def render_module(name, decl, request, actor, context, page=None):
        """A module page or panel (`decl`), or a page the host composes for the module (`page`), as the viewer sees it."""
        ops = await ops_meta(actor)
        ctx = {"return_to": str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""), **context,
               "user": {"role": request.state.session["role"]}}

        def run(r):
            return render_page(page or catalog.page(name, decl),
                               modpages.build_host(catalog, name, ctx, ops.get, module_origin, r, tokens))
        try:
            return await drill(run) or '<p class="mut">module page unavailable (database busy)</p>'
        except (ValueError, OSError) as e:
            return f'<p class="mut">module page {decl.id if decl else name} cannot be rendered ({type(e).__name__})</p>'

    def ctx_for(request):
        return {"var": {k[4:]: v for k, v in request.query_params.items() if k.startswith("var.")}}

    @app.get("/modules", response_class=HTMLResponse)
    async def modules_list(request: Request):
        actor = who(request)
        await refresh_catalog(actor, force=True)
        store = await drill(views.module_store) or {"store": [], "nodes": []}
        return render(request, "modules.html", {"modules": list(catalog.rows.values()), **store, "actor": actor})

    @app.get("/coordinator", response_class=HTMLResponse)
    async def coordinator_page(request: Request):
        actor = who(request)
        d = await drill(views.coordinator) or {"s": {"role": "?", "epoch": 0, "phase": "?", "cik_fingerprint": "", "fleet_id": ""},
                                               "nodes": [], "fp": ""}
        return render(request, "coordinator.html", {**d, "actor": actor})

    @app.get("/agent", response_class=HTMLResponse)
    async def agent_page(request: Request):
        actor = who(request)
        d = await drill(views.agent_builds) or {"builds": [], "channel": {}, "versions": {}, "nodes": [], "canary_ready": False}
        return render(request, "agent.html", {**d, "actor": actor})

    @app.get("/modules/{name}", response_class=HTMLResponse)
    async def module_overview(name: str, request: Request):
        actor = who(request)
        await refresh_catalog(actor)
        man = catalog.manifest(name)
        if man is None:
            return render(request, "error.html", {"message": f"no module {name}", "actor": actor}, 404)
        over = next((d for d in man.ui.pages if d.slot == "module.overview"), None)
        body = await render_module(name, over, request, actor, ctx_for(request)) if over else \
            '<p class="mut">This module declares no overview page.</p>'
        return render(request, "module_page.html", {"name": name, "man": man, "body": body, "tab": "overview", "actor": actor})

    @app.get("/m/{name}/_import", response_class=HTMLResponse)
    async def module_import(name: str, request: Request, op: str = "", dataset: str = "", return_to: str = ""):
        """After an upload link's dataset is registered: the module's importer operation offered on it, drawn by the host
        (registry title, tier, confirmation), returning to the module page."""
        actor = who(request)
        await refresh_catalog(actor)
        man = catalog.manifest(name)
        prefix = f"mod.{name.replace('-', '_')}."
        decl = next((o for o in (man.operations if man else []) if op == prefix + o.verb and o.target == "dataset"), None)
        seen = await drill(lambda r: r.one("SELECT 1 FROM datasets WHERE dataset_id=? AND (module=? OR module IS NULL OR "
                                           "module='')", (dataset, name)))
        if decl is None or not seen:
            return render(request, "error.html", {"message": f"{name} has no importer {op} for dataset {dataset}", "actor": actor}, 404)
        back = return_to if return_to.startswith("/") and not return_to.startswith("//") else f"/modules/{name}"
        page = U.Page.model_validate({"title": "Upload registered", "body": [
            {"type": "text", "text": f"Dataset {dataset} is registered. {name} has not seen it yet: run its importer to use it."},
            {"type": "action", "action": {"op": f"self.{decl.verb}", "target": dataset}},
            {"type": "link", "text": f"Dataset {dataset}", "to": {"dataset": dataset}}]})
        body = await render_module(name, None, request, actor, {"return_to": back}, page=page)
        return render(request, "module_page.html", {"name": name, "man": man, "body": body, "tab": "import", "actor": actor})

    @app.get("/m/{name}/{page_id}", response_class=HTMLResponse)
    async def module_subpage(name: str, page_id: str, request: Request):
        actor = who(request)
        await refresh_catalog(actor)
        man = catalog.manifest(name)
        decl = next((d for d in (man.ui.pages if man else []) if d.id == page_id), None)
        if decl is None:
            return render(request, "error.html", {"message": f"no page {page_id} in module {name}", "actor": actor}, 404)
        body = await render_module(name, decl, request, actor, ctx_for(request))
        return render(request, "module_page.html", {"name": name, "man": man, "body": body, "tab": page_id, "actor": actor})

    # The sandboxed frames' bridge (oarbank_sdk render/static/ui.js). Every route names the frame, and the frame must
    # declare the capability ([[ui.iframes]].bridge): ui.js checks it too, this is the host's own check.
    async def bridge_frame(name: str, frame: str, cap: str, request: Request):
        """(manifest, frame declaration) for a bridge call, or the JSONResponse refusing it."""
        actor = who(request)
        await refresh_catalog(actor)
        man = catalog.manifest(name)
        decl = modpages.frame_of(man, frame) if man else None
        if decl is None:
            return None, JSONResponse({"error": "unknown frame"}, status_code=404)
        if cap not in decl.bridge:
            return None, JSONResponse({"error": "capability", "detail": f"frame {frame} does not declare {cap}"}, status_code=403)
        return man, None

    def frame_ctx(request: Request) -> dict:
        try:
            ctx = json.loads(request.query_params.get("ctx") or "{}")
        except ValueError:
            ctx = {}
        return ctx if isinstance(ctx, dict) else {}

    @app.get("/m/{name}/_bridge/{frame}/view/{view_id}")
    async def bridge_view(name: str, frame: str, view_id: str, request: Request):
        man, refused = await bridge_frame(name, frame, "read.view", request)
        if refused:
            return refused
        if view_id not in man.ui.views:
            return JSONResponse({"error": "unknown view"}, status_code=404)
        campaign = frame_ctx(request).get("campaign")
        src = U.Source(view=view_id, params={"campaign": campaign} if campaign else {})
        return JSONResponse(await drill(lambda r: modpages.resolve(r, name, man, src)) or {"error": "busy"})

    @app.get("/m/{name}/_bridge/{frame}/query")
    async def bridge_query(name: str, frame: str, spec: str, request: Request):
        man, refused = await bridge_frame(name, frame, "read.query", request)
        if refused:
            return refused
        try:
            src = U.Source.model_validate(json.loads(spec))
        except ValueError:
            return JSONResponse({"error": "invalid query"}, status_code=400)
        if src.view:
            return JSONResponse({"error": "invalid query", "detail": "views are read with read.view"}, status_code=400)
        ctx = frame_ctx(request)
        return JSONResponse(await drill(lambda r: modpages.resolve_in(r, name, man, src, ctx)) or {"error": "busy"})

    @app.get("/m/{name}/_bridge/{frame}/media")
    async def bridge_media(name: str, frame: str, ref: str, kind: str, request: Request):
        man, refused = await bridge_frame(name, frame, "read.media", request)
        if refused:
            return refused
        try:
            ref_doc = json.loads(ref)
        except ValueError:
            return JSONResponse({"error": "not an artifact reference"}, status_code=400)
        from . import media
        hit = await drill(lambda r: media.urls(r, tokens, name, module_origin, ref_doc, kind))
        return JSONResponse(hit) if hit else JSONResponse({"error": "not this module's artifact"}, status_code=404)

    @app.get("/m/{name}/_bridge/{frame}/link")
    async def bridge_link(name: str, frame: str, to: str, request: Request):
        man, refused = await bridge_frame(name, frame, "navigate", request)
        if refused:
            return refused
        try:
            link = U.Link.model_validate(json.loads(to))
        except ValueError:
            return JSONResponse({"error": "not a typed reference"}, status_code=400)
        ref = urlsplit(request.headers.get("referer") or "")
        back = (ref.path + (f"?{ref.query}" if ref.query else "")) if ref.netloc == request.headers.get("host") else ""
        href = None if link.url else modpages.link_url(name, man, link, back)        # typed references only
        return JSONResponse({"href": href}) if href else JSONResponse({"error": "no such page"}, status_code=404)

    @app.get("/m/{name}/_bridge/{frame}/op/{op_id}")
    async def bridge_op(name: str, frame: str, op_id: str, request: Request, target: str = ""):
        """What a page action may name, as the viewer may run it: registry metadata for the host's confirmation."""
        man, refused = await bridge_frame(name, frame, "request.operation", request)
        if refused:
            return refused
        meta = (await ops_meta(request.state.session["account"])).get(op_id)
        why = modpages.op_allowed(name, meta, request.state.session["role"])
        if why:
            return JSONResponse({"error": why}, status_code=404 if why == "unknown operation" else 403)
        if not await drill(lambda r: modpages.target_owned(r, name, op_id, target)):
            return JSONResponse({"error": "not this module's", "detail": f"{target} is not {name}'s"}, status_code=403)
        return JSONResponse(meta)

    async def panels(slot: str, request: Request, actor: str, context: dict) -> list[dict]:
        from oarbank_sdk.render import when_ok
        await refresh_catalog(actor)
        context = {**context, "user": {"role": request.state.session["role"]}}
        out = []
        for name in catalog.rows:
            man = catalog.manifest(name)
            for d in (man.ui.panels if man else []):
                if d.slot == slot and when_ok(d.when, {**context, "self": name}):
                    out.append({"module": name, "title": d.title, "html": await render_module(name, d, request, actor, context)})
        return out

    @app.get("/modules/{name}/secrets", response_class=HTMLResponse)
    async def module_secrets(name: str, request: Request):
        """The module's secrets: set or not, fingerprints, scopes, and the write-only forms. No value ever reaches here."""
        actor = who(request)
        await refresh_catalog(actor)
        man = catalog.manifest(name)
        if man is None:
            return render(request, "error.html", {"message": f"no module {name}", "actor": actor}, 404)
        r = await coordinator_json("GET", f"/api/v1/modules/{name}/secrets", actor)
        nodes = await drill(lambda rd: rd.q("SELECT node_id, hostname FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")) or []
        return render(request, "module_secrets.html", {"name": name, "man": man, "tab": "secrets", "nodes": nodes,
                                                        "secrets": (r.json() if r.status_code == 200 else {}).get("secrets") or [],
                                                        "actor": actor})

    @app.get("/modules/{name}/health", response_class=HTMLResponse)
    async def module_page(name: str, request: Request):
        actor = who(request)
        r = await coordinator_json("GET", "/api/v1/modules", actor)
        rows = {m["name"]: m for m in (r.json() if r.status_code == 200 else [])}
        log = Path(state.db_path).parent / "logs" / "modules" / f"{name}.log"
        tail = log.read_bytes()[-16000:].decode(errors="replace") if log.exists() else ""

        def load(rd):
            return {"events": rd.q("SELECT * FROM events WHERE kind IN ('module_fault','module_restarted','module_disabled',"
                                   "'module_enabled') AND module=? ORDER BY event_id DESC LIMIT 40", (name,)),
                    "alerts": rd.q("SELECT * FROM alerts WHERE rule=? ORDER BY opened_at DESC LIMIT 20", (f"module_host_down:{name}",))}
        extra = await drill(load) or {"events": [], "alerts": []}
        return render(request, "module_health.html", {"mod": rows.get(name), "name": name, "tail": tail, **extra, "actor": actor})

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, **{k: v for k, v in state.meta().items() if k != "oarbankd"}, "renders": state.renders}

    # ------------------------------------------------------------------ SSE (resync-first)
    @app.get("/sse")
    async def sse(request: Request):
        who(request)
        if clients["n"] >= SSE_MAX_CLIENTS:
            return JSONResponse({"error": "too_many_streams"}, status_code=429, headers={"Retry-After": "5"})
        q = state.subscribe()
        clients["n"] += 1

        def hb():
            m = state.meta()
            return json.dumps({"built_at": m["built_at"], "snapshot_version": m["version"], "server_boot_id": m["boot_id"],
                               "coordinator_ok": m["coordinator_ok"], "coordinator_down_since": m["coordinator_down_since"]})

        async def gen():
            try:
                yield "retry: 3000\n\n"
                yield f"event: resync\ndata: {state.version}\n\n"       # always resync on (re)connect
                yield f"event: heartbeat\ndata: {hb()}\n\n"
                last_ping = time.monotonic()
                while not await request.is_disconnected():
                    if getattr(q, "dropped", False):
                        return
                    try:
                        v = await asyncio.wait_for(q.get(), timeout=SSE_HEARTBEAT_S)
                        while not q.empty():                            # coalesce to the latest version
                            v = q.get_nowait()
                        yield f"event: tick\ndata: {v}\n\n"
                    except asyncio.TimeoutError:
                        pass
                    yield f"event: heartbeat\ndata: {hb()}\n\n"
                    if time.monotonic() - last_ping > SSE_PING_S:
                        yield ": ping\n\n"
                        last_ping = time.monotonic()
            finally:
                state.unsubscribe(q)
                clients["n"] -= 1
        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    # ------------------------------------------------------------------ operations
    def back(url: str, msg: str, kind: str = "ok"):
        sep = "&" if "?" in url else "?"
        return RedirectResponse(f"{url}{sep}flash={quote(msg)}&kind={kind}", status_code=303)

    @app.post("/do/{op}")
    async def do(op: str, request: Request):
        actor = who(request)
        entry = registry.REGISTRY.get(op)
        if entry is None and op.startswith("mod."):
            meta = (await ops_meta(actor)).get(op)                 # a module operation: registered in oarbankd at install
            entry = registry.Operation.model_validate({**{k: meta[k] for k in ("id", "tier", "summary")}, "area": "modules",
                                                       "category": "modify", "idempotency": "natural", "preview": meta["tier"] in ("T2", "T3"),
                                                       "routes": registry.OPR(op)}) if meta else None
        if entry is None:
            return render(request, "error.html", {"message": f"unknown operation {op}", "actor": actor}, 404)
        form = await request.form()
        if not csrf_ok(request, form):
            return JSONResponse({"error": "csrf", "detail": "missing or wrong CSRF token (reload the page)"}, status_code=403)
        target = form.get("target_input") or form.get("target") or None      # a typed target (e.g. a setting's key)
        return_to = form.get("return_to") or request.headers.get("referer") or "/"
        if op == "agent.upload" and getattr(form.get("binary"), "read", None):
            data = await form["binary"].read()
            up = await http.post("/api/v1/agent/builds", content=data, headers=state.coordinator_headers(actor))
            if up.status_code != 200:
                return back(return_to, f"upload failed: {up.text[:200]}", "bad")
            form = {**{k: form.get(k) for k in form.keys() if k != "binary"}, "p.sha256": up.json()["sha256"]}
        if op == "coordinator.builds.upload" and getattr(form.get("archive"), "read", None):
            data = await form["archive"].read()
            up = await http.post("/api/v1/coordinator/builds", content=data, headers=state.coordinator_headers(actor))
            if up.status_code != 200:
                return back(return_to, f"upload failed: {up.text[:200]}", "bad")
            form = {**{k: form.get(k) for k in form.keys() if k != "archive"}, "p.sha256": up.json()["sha256"]}
        if op == "vendor.metadata.upload" and hasattr(form, "getlist"):
            files = {}
            for f in form.getlist("metadata"):
                if getattr(f, "read", None) and f.filename:
                    files[Path(f.filename).name] = (await f.read()).decode("utf-8", "replace")
            form = {**{k: form.get(k) for k in form.keys() if k != "metadata"}, "params": json.dumps({"files": files})}
        if op == "modules.install" and getattr(form.get("bundle"), "read", None):
            data = await form["bundle"].read()
            up = await http.post("/api/v1/modules/bundles", content=data, headers=state.coordinator_headers(actor))
            if up.status_code != 200:
                return back(return_to, f"upload failed: {up.text[:200]}", "bad")
            form = {**{k: form.get(k) for k in form.keys() if k != "bundle"}, "p.sha256": up.json()["sha256"]}
        try:
            params = forms.params_for(op, form, {})
        except ValueError as e:                      # e.g. malformed JSON in an object/array field
            return back(return_to, f"{op}: invalid input: {e}", "bad")
        reason = (form.get("reason") or "").strip() or None
        headers = state.coordinator_headers(actor)
        if form.get("idem"):
            headers["idempotency-key"] = form["idem"]
        if entry.tier in ("T2", "T3"):
            r = await http.post(f"/api/v1/ops/{op}", json={"target": target, "params": params, "dry_run": True}, headers=headers)
            if r.status_code != 200:
                return back(return_to, f"{op}: {r.json().get('detail') or r.text}", "bad")
            return render(request, "plan.html", {"plan": r.json()["plan"], "entry": entry, "return_to": return_to,
                                                 "reason": reason or "", "actor": actor})
        body = {"target": target, "params": params, "reason": reason}
        if op == "secrets.set":
            body["secret"] = form.get("secret") or ""        # beside params: never in a plan, the audit or a log
        r = await http.post(f"/api/v1/ops/{op}", json=body, headers=headers)
        return _result(op, r, return_to, request)

    SECRET_RESULTS = {"access.accounts.create": ("totp_secret", "otpauth"), "access.accounts.reset_totp": ("totp_secret", "otpauth"),
                      "access.tokens.create": ("token",), "access.login_link": ("url",), "modules.cli_token": ("token",),
                      "nodes.join_code": ("code", "command")}

    def _result(op, r, return_to, request=None):
        body = r.json() if r.text else {}
        if r.status_code != 200:
            return back(return_to, f"{op}: {body.get('error')}: {body.get('detail')}", "bad")
        res = body.get("result") or {}
        if op in SECRET_RESULTS and request is not None:          # shown once, never put in a URL or a flash
            return render(request, "secret.html", {"op": op, "result": res, "keys": SECRET_RESULTS[op], "return_to": return_to})
        inner = res.get("result") if isinstance(res.get("result"), dict) else {}
        if res.get("response") == "redirect" and inner.get("campaign_id"):
            return back(f"/campaigns/{inner['campaign_id']}", res.get("message") or f"{op} ok")
        if res.get("message"):
            return back(return_to, res["message"])
        return back(return_to, f"{op} ok" + (" (already done)" if body.get("replayed") else ""))

    @app.post("/apply/{op}")
    async def apply(op: str, request: Request):
        actor = who(request)
        entry = registry.REGISTRY.get(op)
        if entry is None and op.startswith("mod."):
            meta = (await ops_meta(actor)).get(op)
            entry = registry.Operation.model_validate({**{k: meta[k] for k in ("id", "tier", "summary")}, "area": "modules",
                                                       "category": "modify", "idempotency": "natural", "preview": True,
                                                       "routes": registry.OPR(op)}) if meta else None
        form = await request.form()
        if not csrf_ok(request, form):
            return JSONResponse({"error": "csrf", "detail": "missing or wrong CSRF token (reload the page)"}, status_code=403)
        return_to = form.get("return_to") or "/"
        body = {"plan_id": form.get("plan_id"), "reason": (form.get("reason") or "").strip() or None,
                "confirm": form.get("confirm") or None}
        headers = state.coordinator_headers(actor)
        if form.get("idem"):
            headers["idempotency-key"] = form["idem"]
        r = await http.post(f"/api/v1/ops/{op}", json=body, headers=headers)
        if r.status_code == 409 and (r.json() or {}).get("plan"):
            return render(request, "plan.html", {"plan": r.json()["plan"], "entry": entry, "return_to": return_to,
                                                 "reason": body["reason"] or "", "actor": actor,
                                                 "drift": "The fleet changed since you previewed; here is the new plan."}, 409)
        if r.status_code in (400, 428) and r.json().get("error") in ("reason_required", "confirmation_required"):
            plan = {"plan_id": body["plan_id"], "op": op, "impact": {}, "confirm_required": entry.tier == "T3",
                    "confirm_name": form.get("confirm_name"), "tier": entry.tier, "target": form.get("target")}
            return render(request, "plan.html", {"plan": plan, "entry": entry, "return_to": return_to, "actor": actor,
                                                 "reason": body["reason"] or "", "drift": r.json().get("detail")}, 400)
        return _result(op, r, return_to, request)

    # ------------------------------------------------------------------ /api/* passthrough (oarbank via tailscale serve)
    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def api_proxy(path: str, request: Request):
        """The remote CLI's path to oarbankd (OARBANKD_URL = the console's https address): it carries its own personal
        access token, which oarbankd checks; the console adds no identity of its own. Bodies stream both ways (uploads,
        downloads of large blobs)."""
        if not (request.headers.get("authorization") or "").lower().startswith("bearer "):
            return JSONResponse({"error": "unauthenticated", "detail": "send a personal access token (OARBANK_TOKEN)"},
                                status_code=401)
        headers = {"authorization": request.headers["authorization"]}
        for h in ("if-match", "idempotency-key", "x-request-id", "content-type", "range", "upload-offset"):
            if request.headers.get(h):
                headers[h] = request.headers[h]
        headers["x-oarbank-source"] = request.headers.get("x-oarbank-source", "cli")
        req = http.build_request(request.method, f"/api/{path}", params=request.query_params, content=request.stream(),
                                 headers=headers)
        r = await http.send(req, stream=True)
        keep = ("retry-after", "etag", "content-length", "content-range", "accept-ranges", "content-disposition",
                "x-content-type-options", "content-security-policy", "upload-offset", "upload-complete")
        return StreamingResponse(r.aiter_raw(), status_code=r.status_code, media_type=r.headers.get("content-type"),
                                 headers={k: v for k, v in r.headers.items() if k.lower() in keep}, background=BackgroundTask(r.aclose))

    return app
