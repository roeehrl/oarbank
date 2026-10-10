"""oarbankd HTTP: the agent API (the mTLS agent listener) and the admin API (loopback and the local socket; the console
publishes it to the tailnet through `tailscale serve`). Both share one DB and background loops."""
import asyncio
import hmac
import os
import json
import sqlite3
import uuid
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import config as C
from . import clock
from . import modcalls
from . import (agentbuilds, audit, blobstore, campaigns, coordmove, core, datasets, identity, modstore, movepull, nodepolicy, nodeservices,
               ops, releases)
from ..contracts import operations as registry
from .db import DB, DBBusy, jl



# a download is never rendered: attachment, nosniff, and a sandbox if a browser opens it anyway
DOWNLOAD_HEADERS = {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'"}


def _range_start(header: str | None) -> int:
    """The start of a `Range: bytes=<start>-` request (0 for none): what an agent resuming a download sends."""
    if header and header.startswith("bytes=") and header.endswith("-") and header[6:-1].isdigit():
        return int(header[6:-1])
    return 0


def _blob_call(fn, *a):
    from . import blobstore
    try:
        return fn(*a)
    except blobstore.BlobError as e:
        raise core.ApiError(e.status, e.code, e.detail, headers={"Upload-Offset": str(e.offset)} if e.offset is not None else None)


async def _append(db, uploader: str, digest: str, request):
    """PATCH an upload (after tus 1.0): the body is appended at `Upload-Offset`; answers 204 with the new offset, and
    `Upload-Complete: 1` once the blob is held."""
    from . import blobstore
    raw = request.headers.get("upload-offset") or ""
    if not raw.isdigit():
        raise core.ApiError(400, "bad_offset", "send Upload-Offset: <bytes already sent>")
    try:
        r = await blobstore.append(db, uploader, digest, int(raw), request.stream())
    except blobstore.BlobError as e:
        raise core.ApiError(e.status, e.code, e.detail, headers={"Upload-Offset": str(e.offset)} if e.offset is not None else None)
    return Response(status_code=204, headers={"Upload-Offset": str(r["offset"]), **({"Upload-Complete": "1"} if r["complete"] else {})})


def _err(e: core.ApiError):
    return JSONResponse({"error": e.code, "detail": e.detail}, status_code=e.status, headers=e.headers or None)


def peer(request: Request) -> str:
    return request.client.host if request.client else ""


# ============================================================================ agent API
def agent_app(db: DB, puller=None) -> FastAPI:
    """The agent API, served on the mTLS listener: a node is its client certificate (D29)."""
    app = FastAPI(title="oarbankd agent API", docs_url=None, redoc_url=None)
    app.state.puller = puller

    @app.exception_handler(core.ApiError)
    async def _h(request, e):
        return _err(e)

    @app.exception_handler(DBBusy)
    async def _busy(request, e):
        return JSONResponse({"error": "busy", "detail": str(e)}, status_code=503, headers={"Retry-After": "2"})

    @app.exception_handler(sqlite3.OperationalError)
    async def _sqlite_busy(request, e):
        # another process holds SQLite's write lock past busy_timeout (a backup, a sqlite3 session): shed load
        # explicitly so agents back off and retry, as for the in-process lock (a chaos finding)
        if "locked" in str(e) or "busy" in str(e):
            return JSONResponse({"error": "busy", "detail": str(e)}, status_code=503, headers={"Retry-After": "2"})
        raise e

    async def node_dep(request: Request):
        return await run_in_threadpool(core.auth_cert, db, getattr(request.state, "tls_peer_der", None), peer(request))

    identity.ensure(db)

    @app.middleware("http")
    async def coordinator_fence(request: Request, call_next):
        """Every agent-API answer carries this coordinator's epoch and role (agents refuse a lower epoch).
        A handed-off coordinator only redirects; a standby one serves identity and pairing only."""
        try:
            r, ep = identity.role(db), identity.epoch(db)
            frozen = r == "active" and coordmove.phase(db) in coordmove.FROZEN_PHASES
        except (DBBusy, sqlite3.OperationalError) as e:      # middleware errors never reach the exception handlers
            return JSONResponse({"error": "busy", "detail": str(e)}, status_code=503, headers={"Retry-After": "2"})
        p = request.url.path
        open_paths = ("/v1/identity", "/v1/coordinator/", "/v1/move/", "/healthz")
        if frozen and request.method in ("POST", "PUT") and not p.startswith(open_paths):
            resp = JSONResponse({"error": "coordinator_moving", "detail": "frozen for a coordinator move; retry shortly"},
                                status_code=503, headers={"Retry-After": "5"})
        elif r != "active" and not p.startswith(open_paths):
            if r == "handed_off":
                resp = JSONResponse({"error": "coordinator_moved", "detail": "this coordinator handed off; follow the signed move",
                                     **coordmove.redirect_body(db)}, status_code=410)
            else:
                resp = JSONResponse({"error": "standby", "detail": "this coordinator is a move target and serves no agents yet"},
                                    status_code=503, headers={"Retry-After": "30"})
        else:
            resp = await call_next(request)
        resp.headers["X-Oarbank-Epoch"] = str(ep)
        resp.headers["X-Oarbank-Role"] = r
        return resp

    # ---- coordinator moves (coordmove.py on the old side, movepull.py on the target)
    def move_dep(request: Request):
        try:
            return coordmove.auth_move(db, request.headers.get("x-oarbank-move"), peer(request))
        except coordmove.MoveError as e:
            raise core.ApiError(401, "unauthorized", str(e))

    def _move(fn, *a):
        try:
            return fn(*a)
        except (coordmove.MoveError, movepull.PullError) as e:
            raise core.ApiError(409, "move_refused", str(e))

    @app.get("/v1/coordinator/moves")
    def move_chain(since_epoch: int = 0):
        return {"moves": coordmove.chain(db, since_epoch)}

    @app.post("/v1/move/pair")
    async def move_pair(request: Request):
        return await run_in_threadpool(_move, coordmove.pair, db, await request.json(), peer(request))

    @app.get("/v1/move/manifest")
    def move_manifest(p=Depends(move_dep)):
        return coordmove.manifest(db)

    @app.get("/v1/move/file")
    def move_file(path: str, p=Depends(move_dep)):
        return FileResponse(_move(coordmove.safe_path, db, path), media_type="application/octet-stream")

    @app.post("/v1/move/snapshot")
    def move_seed_snapshot(p=Depends(move_dep)):
        if coordmove.phase(db) not in ("idle", "draining"):
            raise core.ApiError(409, "move_refused", "the final snapshot is taken by the cutover")
        return coordmove.snapshot(db, final=False)

    @app.get("/v1/move/snapshot-file/{name}")
    def move_snapshot_file(name: str, p=Depends(move_dep)):
        return FileResponse(_move(coordmove.snapshot_file, db, name), media_type="application/octet-stream")

    @app.get("/v1/move/status")
    def move_status(p=Depends(move_dep)):
        m = coordmove.move(db)
        out = {"phase": coordmove.phase(db), "role": identity.role(db), "move_state": m["state"] if m else None,
               "move_id": m["move_id"] if m else None}
        if out["phase"] == "final_ready" and m:
            out["snapshot"] = json.loads(m["final_snapshot_json"])
        return out

    @app.post("/v1/move/ready")
    async def move_ready(request: Request, p=Depends(move_dep)):
        return await run_in_threadpool(_move, coordmove.ready, db, await request.json(), p)

    @app.post("/v1/move/commit")
    async def move_commit(request: Request, p=Depends(move_dep)):
        return await run_in_threadpool(_move, coordmove.commit, db, await request.json(), p)

    @app.get("/v1/move/bundle/{sha}")
    def move_bundle(sha: str, node=Depends(node_dep)):
        from . import coordbuilds
        want = (jl(node.get("install_coordinator_json")) or {}).get("bundle_sha256")
        f = coordbuilds.bundle_file(db, sha)
        if not f or want != sha:
            raise core.ApiError(404, "not_found", "no coordinator bundle is assigned to this node")
        return FileResponse(f, media_type="application/gzip")

    # the target, while standby: requests from the old coordinator, signed with the key pinned at pairing
    @app.post("/v1/move/sign-statement")
    async def move_sign_statement(request: Request):
        pl = app.state.puller
        if not pl or identity.role(db) != "standby":
            raise core.ApiError(409, "move_refused", "not a standby coordinator")
        body = _move(pl.verify_from_a, await request.body(), request.headers.get("x-oarbank-move-sig"))
        return {"sig": _move(pl.sign_statement, body["statement"])}

    @app.post("/v1/move/promote")
    async def move_promote(request: Request):
        pl = app.state.puller
        if not pl or identity.role(db) != "standby":
            raise core.ApiError(409, "move_refused", "not a standby coordinator")
        body = _move(pl.verify_from_a, await request.body(), request.headers.get("x-oarbank-move-sig"))
        threading.Thread(target=pl.promote, args=(body,), daemon=True, name="oarbankd-promote").start()
        return {"accepted": True}

    @app.get("/v1/identity")
    def coordinator_identity(nonce: str, request: Request):
        try:
            proof = identity.identity_proof(db, nonce, url=f"{request.url.scheme}://{request.headers.get('host', '')}")
            ca = Path(db.path).parent / "tls" / "ca.pem"
            if ca.exists():
                proof["ca_pem"] = ca.read_text(encoding="utf-8")       # outside the signature: the agent checks it against the signed pin
            return proof
        except ValueError as e:
            raise core.ApiError(400, "bad_nonce", str(e))

    @app.post("/v1/agent/enroll")
    async def enroll(request: Request):
        b = await request.json()
        return await run_in_threadpool(core.enroll, db, b.get("hostname") or "unknown", b.get("facts") or {}, peer(request),
                                       b.get("csr") or "", b.get("join"), b.get("name"), b.get("user_code"))

    @app.post("/v1/agent/cert")
    async def renew_cert(request: Request, node=Depends(node_dep)):
        """A fresh client certificate from a new CSR (the directive `renew_cert` asks for it)."""
        b = await request.json()
        return await run_in_threadpool(core.renew_cert, db, node, b.get("csr") or "")

    @app.get("/v1/agent/enroll/{eid}")
    def enroll_status(eid: str):
        return core.enroll_status(db, eid)

    @app.post("/v1/agent/hello")
    async def hello(request: Request, node=Depends(node_dep)):
        return await run_in_threadpool(core.hello, db, node, await request.json())

    @app.post("/v1/agent/heartbeat")
    async def heartbeat(request: Request, node=Depends(node_dep)):
        return await run_in_threadpool(core.heartbeat, db, node, await request.json())

    @app.post("/v1/agent/claim")
    async def claim(request: Request, node=Depends(node_dep)):
        return await run_in_threadpool(core.claim, db, node, await request.json())

    @app.post("/v1/attempts/{aid}/complete")
    async def complete(aid: int, request: Request, node=Depends(node_dep)):
        return await run_in_threadpool(core.complete, db, node, aid, await request.json())

    @app.post("/v1/attempts/{aid}/release")
    async def release(aid: int, request: Request, node=Depends(node_dep)):
        reason = (await request.json()).get("reason")
        if not reason:
            raise core.ApiError(400, "reason_required", "a release names its end reason")
        return await run_in_threadpool(core.release, db, node, aid, reason)

    @app.post("/v1/attempts/{aid}/fail")
    async def fail(aid: int, request: Request, node=Depends(node_dep)):
        return await run_in_threadpool(core.fail, db, node, aid, await request.json())

    @app.post("/v1/attempts/{aid}/checkpoint")
    async def checkpoint(aid: int, request: Request, node=Depends(node_dep)):
        """Record a checkpoint the agent uploaded for a live attempt (checkpoints.py)."""
        from . import checkpoints
        body = await request.json()
        try:
            return await run_in_threadpool(checkpoints.record, db, node, aid, body)
        except checkpoints.CheckpointError as e:
            raise core.ApiError(e.status, e.code, e.detail)

    @app.post("/v1/attempts/{aid}/log")
    async def log(aid: int, request: Request, node=Depends(node_dep)):
        await run_in_threadpool(core.append_log, aid, node, db, await request.body())
        return {"ok": True}

    @app.get("/v1/datasets/{did:path}")
    def dataset(did: str, node=Depends(node_dep)):
        m = datasets.manifest(db, did)
        if not m:
            raise core.ApiError(404, "not_found", did)
        return m

    @app.get("/v1/blobs/{digest}")
    async def blob(digest: str, request: Request, node=Depends(node_dep)):
        """A blob by digest (ranges). One only a dataset's origins have is fetched from them, once, for a node whose every
        origin failed (blobstore.origin_stream): the bytes stream to the node as they arrive."""
        p = await run_in_threadpool(blobstore.path, db, digest)
        if p is not None:
            return FileResponse(p, media_type="application/octet-stream")
        start = _range_start(request.headers.get("range"))
        stream = await blobstore.origin_stream(db, digest, start)
        if stream is None:
            raise core.ApiError(404, "not_found", digest)
        it = stream.__aiter__()
        try:
            first = await it.__anext__()                    # an origin that never answers is a clean 502
        except StopAsyncIteration:
            first = b""
        except blobstore.OriginError as e:
            raise core.ApiError(502, "origin_failed", str(e)[:500])
        size, _ = blobstore.origins_of(db, digest)

        async def body():
            yield first
            try:
                async for b in it:
                    yield b
            except blobstore.OriginError:
                return                                      # cut short: the node's own digest check refuses what it got
        return StreamingResponse(body(), status_code=206 if start else 200, media_type="application/octet-stream",
                                 headers={"Content-Range": f"bytes {start}-{size - 1}/{size}"} if start else None)

    @app.post("/v1/uploads/{digest}")
    async def upload_begin(digest: str, request: Request, node=Depends(node_dep)):
        """Create or resume an upload of a blob (an artifact, a checkpoint file): {offset, complete}."""
        body = await request.json()
        return await run_in_threadpool(_blob_call, blobstore.begin, db, f"node:{node['node_id']}", digest, body.get("size"))

    @app.patch("/v1/uploads/{digest}")
    async def upload_append(digest: str, request: Request, node=Depends(node_dep)):
        return await _append(db, f"node:{node['node_id']}", digest, request)

    @app.get("/v1/releases/{name}")
    def release_bundle(name: str, node=Depends(node_dep)):
        rid = name.removesuffix(".tar.gz")
        r = db.one("SELECT path FROM releases WHERE release_id=?", (rid,))
        if not r:
            raise core.ApiError(404, "not_found", rid)
        return FileResponse(db.abs(r["path"]), media_type="application/gzip")

    @app.get("/v1/agent/builds/{sha}")
    def agent_build_download(sha: str, node=Depends(node_dep)):
        r = agentbuilds.record(db, sha)
        if not r or agentbuilds.assigned(db, node) != sha:
            raise core.ApiError(404, "not_found", f"agent build {sha[:12]} is not assigned to this node")
        return FileResponse(r["path"], media_type="application/octet-stream")

    @app.get("/v1/tuf/{name}")
    def vendor_tuf(name: str, node=Depends(node_dep)):
        from . import vendortuf
        p = vendortuf.path(Path(db.path).parent, name)
        if not p:
            raise core.ApiError(404, "not_found", f"no vendor metadata {name}")
        return FileResponse(p, media_type="application/json")

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "t": clock.now()}

    return app


# ============================================================================ admin API
LOOPBACK = ("127.0.0.1", "::1")


def identify(request: Request, reader, home, console_secret: str | None) -> tuple[str, str]:
    """(actor, role); a token's scope, if any, is left in request.state.scope."""
    request.state.scope = None
    return _identify(request, reader, home, console_secret)


def _identify(request: Request, reader, home, console_secret: str | None) -> tuple[str, str]:
    """(actor, role) of an admin request (access.py). Nothing is trusted for being local or for an identity header:
    - the console, proven by its per-boot secret (loopback only), forwards the account of its signed-in session;
    - `Authorization: Bearer` carries the local owner's admin token or a personal access token.
    Funnel traffic is refused."""
    from . import access
    if access.via_funnel(request.headers):
        raise core.ApiError(403, "forbidden", "requests from Tailscale Funnel are refused")
    cs = request.headers.get("x-oarbank-console-secret")
    if console_secret and cs and hmac.compare_digest(cs.encode(), console_secret.encode()) and peer(request) in LOOPBACK:
        name = request.headers.get("x-oarbank-actor") or ""
        if name == "console":                     # the console process's own reads (catalog, state): read-only
            return "console", "viewer"
        rows = reader.q("SELECT role, disabled FROM accounts WHERE name=?", (name,))
        if not rows or rows[0]["disabled"]:
            raise core.ApiError(401, "unauthenticated", "sign in to the console")
        return name, rows[0]["role"]
    auth = request.headers.get("authorization") or ""
    if auth[:7].lower() == "bearer ":
        tok = auth[7:].strip()
        if access.check_admin_token(home, tok):
            return "owner", "admin"
        t = access.token_identity(reader, tok)
        if t:
            request.state.scope = t["scope"]
            return t["account"], t["role"]
    raise core.ApiError(401, "unauthenticated", "send the admin token (oarbank on the coordinator reads it) or a "
                        "personal access token as Authorization: Bearer")


def host_guard(app: FastAPI, reader, default_port: int | None = None):
    """Answer only to allowed Host headers (DNS rebinding): loopback names on the listener's port plus the operator's
    `console_hosts`."""
    from . import access

    @app.middleware("http")
    async def _hosts(request: Request, call_next):
        port = (request.scope.get("server") or (None, default_port))[1] or default_port
        allowed = access.allowed_hosts(port, reader.fleet_setting("console_hosts") or []) | access.TEST_HOSTS
        if not access.host_ok(request.headers.get("host"), allowed):
            return JSONResponse({"error": "bad_host", "detail": "this host name is not allowed (Settings → Access: console_hosts)"},
                                status_code=421)
        return await call_next(request)


class ReadSide:
    """oarbankd's read path for the admin listener: its own read-only connection and short caches, so
    identity checks, /internal/state and /metrics never take the writer's lock (the console load gate)."""

    def __init__(self, path, ttl_s: float = 1.0):
        import sqlite3
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only=1")
        self.lock = threading.Lock()
        self.ttl_s = ttl_s
        self._cache: dict = {}

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def cached(self, key, fn):
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < self.ttl_s:
            return hit[1]
        v = fn()
        self._cache[key] = (time.monotonic(), v)
        return v

    def get_state(self, key, default=None):
        """Cached until any connection commits (PRAGMA data_version): an allowlist change applies at once."""
        with self.lock:
            dv = self.conn.execute("PRAGMA data_version").fetchone()[0]
        hit = self._cache.get(("setting", key))
        if hit and hit[0] == dv:
            v = hit[1]
        else:
            rows = self.q("SELECT value_json FROM system_state WHERE key=?", (key,))
            v = json.loads(rows[0]["value_json"]) if rows else None
            self._cache[("setting", key)] = (dv, v)
        return default if v is None else v

    def fleet_setting(self, key):
        """A fleet setting's value (settings.fleet_value), cached the same way."""
        from .settings import fleet_value
        with self.lock:
            dv = self.conn.execute("PRAGMA data_version").fetchone()[0]
        hit = self._cache.get(("fleet", key))
        if hit and hit[0] == dv:
            return hit[1]
        v = fleet_value(self, key)
        self._cache[("fleet", key)] = (dv, v)
        return v


def admin_app(db: DB, bus: "EventBus | None" = None, console_secret: str | None = None, local_channel: bool = False) -> FastAPI:
    """oarbankd's admin listener (127.0.0.1): JSON reads, the operation endpoint, /internal/state and
    /metrics. Pages live in the separate oarbank-console process (D10), which calls this API.

    `local_channel`: the same API on the local admin channel (architecture.md, "Network and access"; a Unix socket in an
    owner-only directory, a named pipe with an owner-only security descriptor on Windows: platform/localchannel.py), so
    reaching it is the credential: the caller is the owner."""
    app = FastAPI(title="Oarbank admin API", docs_url="/api/docs", redoc_url=None)
    boot_id = uuid.uuid4().hex[:12]
    ro = ReadSide(db.path)

    @app.exception_handler(core.ApiError)
    async def _h(request, e):
        return _err(e)

    @app.exception_handler(DBBusy)
    async def _busy(request, e):
        return JSONResponse({"error": "busy", "detail": str(e)}, status_code=503, headers={"Retry-After": "2"})

    @app.exception_handler(sqlite3.OperationalError)
    async def _sqlite_busy(request, e):
        # another process holds SQLite's write lock past busy_timeout (a backup, a sqlite3 session): shed load
        # explicitly so agents back off and retry, as for the in-process lock (a chaos finding)
        if "locked" in str(e) or "busy" in str(e):
            return JSONResponse({"error": "busy", "detail": str(e)}, status_code=503, headers={"Retry-After": "2"})
        raise e

    @app.exception_handler(releases.ReleaseRefused)
    async def _refused(request, e):
        return JSONResponse({"error": "release_refused", "detail": str(e)}, status_code=409)

    @app.middleware("http")
    async def csrf(request: Request, call_next):
        """Tailscale identity is ambient (like a cookie): any mutating request that arrives through
        `tailscale serve` must prove it is same-origin. Local CLI calls (no identity header) pass."""
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            site = request.headers.get("sec-fetch-site")
            via_serve = bool(request.headers.get("tailscale-user-login"))
            if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
                return JSONResponse({"error": "csrf", "detail": f"origin {origin}"}, status_code=403)
            if site and site not in ("same-origin", "none"):
                return JSONResponse({"error": "csrf", "detail": f"sec-fetch-site {site}"}, status_code=403)
            if via_serve and not origin and site != "same-origin":
                return JSONResponse({"error": "csrf", "detail": "missing origin"}, status_code=403)
        return await call_next(request)

    home = Path(db.path).parent
    if not local_channel:                         # a socket or pipe cannot be reached through DNS rebinding
        host_guard(app, ro, C.ADMIN_PORT)

    def who(request: Request):
        if local_channel:
            request.state.scope = None
            request.state.role = "admin"
            return "owner"
        actor, role = identify(request, ro, home, console_secret)
        request.state.role = role
        return actor

    def need_admin(request: Request):
        if getattr(request.state, "role", None) != "admin":
            raise core.ApiError(403, "forbidden_role", "this needs the admin role")

    def console_only(request: Request):
        """Sign-in ceremonies: only the console (its per-boot secret, loopback) may ask, or the owner on the local admin
        channel (the setup wizard proves the new account's authenticator there: the channel is already the owner's
        credential, so it grants nothing new)."""
        if local_channel:
            return
        cs = request.headers.get("x-oarbank-console-secret")
        if not (console_secret and cs and hmac.compare_digest(cs.encode(), console_secret.encode())
                and peer(request) in LOOPBACK):
            raise core.ApiError(403, "forbidden", "sign-in goes through the console")

    def _access_call(fn, *a):
        from . import access
        try:
            return fn(*a)
        except access.AccessError as e:
            raise core.ApiError(e.status, e.code, e.detail)

    def _session_for(request: Request, a: dict, method: str) -> dict:
        from . import access
        sess = access.new_session(db, a["name"], method, request.headers.get("x-oarbank-user-agent") or "")
        audit.append(db, actor=a["name"], source="gui", operation="access.sign_in", category="access",
                     target_type="account", target_id=a["name"], outcome="ok", request_id=audit.request_id(),
                     reason=method, user_agent=request.headers.get("x-oarbank-user-agent"))
        return {**sess, "role": a["role"]}

    def _refused(request: Request, name: str, e: Exception):
        audit.append(db, actor=name or "?", source="gui", operation="access.sign_in", category="access",
                     target_type="account", target_id=name or "?", outcome="denied", request_id=audit.request_id(),
                     error=str(e)[:300], user_agent=request.headers.get("x-oarbank-user-agent"))

    @app.post("/api/v1/access/login")
    async def access_login(request: Request, _=Depends(console_only)):
        from . import access
        b = await request.json()
        try:
            a = await run_in_threadpool(access.password_login, db, b.get("name") or "", b.get("password") or "",
                                        b.get("code") or "")
        except access.AccessError as e:
            _refused(request, b.get("name") or "", e)
            raise core.ApiError(e.status, e.code, e.detail)
        return _session_for(request, a, "password+totp")

    @app.post("/api/v1/access/link")
    async def access_link(request: Request, _=Depends(console_only)):
        from . import access
        b = await request.json()
        try:
            a = access.use_login_link(db, b.get("t") or "")
        except access.AccessError as e:
            _refused(request, "", e)
            raise core.ApiError(e.status, e.code, e.detail)
        return _session_for(request, a, "link")

    @app.post("/api/v1/access/logout")
    async def access_logout(request: Request, _=Depends(console_only)):
        from . import access
        b = await request.json()
        access.end_session(db, b.get("sid") or "")
        return {"ok": True}

    @app.post("/api/v1/access/touch")
    async def access_touch(request: Request, _=Depends(console_only)):
        from . import access
        access.touch_session(db, (await request.json()).get("sid") or "")
        return {"ok": True}

    @app.post("/api/v1/access/passkey/options")
    async def access_passkey_options(request: Request, _=Depends(console_only)):
        """Options for a passkey ceremony: `purpose` login (anyone) or register (the signed-in account)."""
        from . import access
        b = await request.json()
        rp_id, _origin = _access_call(access.rp_for, b.get("host") or "", b.get("scheme") or "http")
        if b.get("purpose") == "register":
            return _access_call(access.passkey_register_options, db, b.get("account") or "", rp_id)
        return _access_call(access.passkey_login_options, db, rp_id)

    @app.post("/api/v1/access/passkey/login")
    async def access_passkey_login(request: Request, _=Depends(console_only)):
        from . import access
        b = await request.json()
        _rp, origin = _access_call(access.rp_for, b.get("host") or "", b.get("scheme") or "http")
        try:
            a = access.passkey_login(db, b.get("challenge_id") or "", b.get("credential") or {}, origin)
        except access.AccessError as e:
            _refused(request, "", e)
            raise core.ApiError(e.status, e.code, e.detail)
        return _session_for(request, a, "passkey")

    @app.post("/api/v1/access/passkey/register")
    async def access_passkey_register(request: Request, _=Depends(console_only)):
        from . import access
        b = await request.json()
        name = request.headers.get("x-oarbank-actor") or ""
        _rp, origin = _access_call(access.rp_for, b.get("host") or "", b.get("scheme") or "http")
        out = _access_call(access.passkey_register, db, name, b.get("challenge_id") or "", b.get("credential") or {},
                           origin, b.get("label") or "")
        audit.append(db, actor=name, source="gui", operation="access.passkey_added", category="access",
                     target_type="account", target_id=name, outcome="ok", request_id=audit.request_id())
        return out

    @app.get("/api/v1/modules/{name}/cli")
    def module_cli_entry(name: str, request: Request, actor=Depends(who)):
        """What `oarbank cli <module>` runs on the coordinator: the current version's [cli] exec and its bundle."""
        ch = modstore.channel(db, name)
        rec = modstore.record(db, name, ch["current"]) if ch["current"] else None
        if not rec:
            raise core.ApiError(404, "not_found", f"{name} has no current version")
        from oarbank_sdk import manifest as mf
        man = mf.load(Path(rec["path"]) / "oarbank-module.toml")
        if not man.cli:
            raise core.ApiError(404, "no_cli", f"{name} {rec['version']} declares no [cli]")
        return {"name": name, "module_id": man.module.id, "version": rec["version"], "exec": list(man.cli.exec),
                "bundle": rec["path"]}

    @app.get("/api/v1/access")
    def access_view(request: Request, actor=Depends(who)):
        from . import access
        mine = request.state.role != "admin"
        return {"me": {"account": actor, "role": request.state.role},
                "accounts": [a for a in access.accounts(db) if not mine or a["name"] == actor],
                "tokens": [t for t in access.tokens(db) if not mine or t["account"] == actor],
                "passkeys": access.passkeys(db, actor if mine else None)}

    @app.get("/internal/state")
    def internal_state(actor=Depends(who)):
        """In-memory facts for the console (cheap: no per-request table scans)."""
        return {"boot_id": boot_id, "now": clock.now(), "fleet_state": ro.get_state("fleet_state", "active"),
                "alive_at": ro.get_state("alive_at"), "writer": db.lock.stats(), "modules": modcalls.host(db).health(),
                "modules_disabled": sorted(modstore.disabled_names(db))}

    # ---------------- view models
    def node_view(n: dict) -> dict:
        t = clock.now()
        hb = n["last_heartbeat_at"] or 0
        tel, cap = jl(n["telemetry_json"], {}), jl(n["capacity_json"], {})
        live = db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='live'", (n["node_id"],))["n"]
        done1h = db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='completed' AND ended_at>?",
                        (n["node_id"], t - 3600))["n"]
        mods = jl(n.get("modules_json"), {}) or {}
        from .settings.apply import flat_values
        facts, policy = jl(n["facts_json"], {}), flat_values(n)
        return {**n, "mods": mods,
                "facts": facts, "tel": tel, "cap": cap, "limits": core.node_limits(n),
                "policy": policy, "doctor": jl(n["doctor_json"]), "online": hb and t - hb < C.OFFLINE_AFTER,
                "hb_age": t - hb if hb else None, "live": live, "done1h": done1h, "services": nodeservices.rows(n),
                "why": nodepolicy.why(cap, tel, facts, policy, n.get("os"), n["node_id"])}

    def fleet_data():
        nodes = [node_view(n) for n in db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")]
        enr = db.q("SELECT * FROM enrollments WHERE status='pending' ORDER BY created_at")
        camps = db.q("SELECT * FROM campaigns WHERE state IN ('running','paused') ORDER BY created_at DESC")
        for c in camps:
            c["jobs"] = db.one("SELECT COUNT(*) n, SUM(state='done') d, SUM(state='leased') l, SUM(state IN ('failed','quarantined')) f "
                               "FROM jobs WHERE campaign_id=? AND kind!='call'", (c["campaign_id"],))
            c["eta_s"] = eta(c["campaign_id"])
        alerts = db.q("SELECT * FROM alerts WHERE state='open' ORDER BY opened_at DESC")
        discovered = db.get_state("discovered", [])
        known = {n["ts_node_id"] for n in nodes if n["ts_node_id"]}
        discovered = [d for d in discovered if d["ts_node_id"] not in known]
        events = db.q("SELECT * FROM events ORDER BY event_id DESC LIMIT 25")
        return {"nodes": nodes, "enrollments": enr, "campaigns": camps, "alerts": alerts, "discovered": discovered,
                "events": events, "now": clock.now()}

    def eta(campaign_id: str):
        rem = db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND kind!='call' AND state IN ('pending','leased')",
                     (campaign_id,))["n"]
        if not rem:
            return 0
        rate = db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND kind!='call' AND state='done' AND done_at>?",
                      (campaign_id, clock.now() - 900))["n"] / 900.0
        return rem / rate if rate > 0 else None

    # ---------------- operations (D14): every mutation goes through ops.execute, audited
    @app.exception_handler(ops.OpError)
    async def _op_error(request, e):
        return JSONResponse({"error": e.code, "detail": e.detail, **e.extra}, status_code=e.status, headers=e.headers or None)

    @app.post("/api/v1/ops/{op}")
    async def api_op(op: str, request: Request, actor=Depends(who)):
        body = await request.json() if (await request.body()) else {}
        im = request.headers.get("if-match")
        req = ops.OpRequest(op=op, actor=actor, role=request.state.role, scope=request.state.scope,
                            source=request.headers.get("x-oarbank-source", "api"),
                            target=body.get("target"), params=body.get("params") or {}, reason=body.get("reason"),
                            dry_run=bool(body.get("dry_run")), plan_id=body.get("plan_id"), confirm=body.get("confirm"),
                            secret=body.get("secret"),
                            if_match=int(im.strip('"')) if im else None,
                            idempotency_key=request.headers.get("idempotency-key"),
                            user_agent=request.headers.get("user-agent"),
                            request_id=request.headers.get("x-request-id") or audit.request_id())
        return await run_in_threadpool(ops.execute, db, req)

    @app.get("/api/v1/alerts")
    def api_alerts(state: str = "open", limit: int = 200, actor=Depends(who)):
        from ..contracts.alert_rules import policy
        rows = db.q("SELECT * FROM alerts WHERE (?='all' OR state=?) ORDER BY opened_at DESC LIMIT ?", (state, state, max(1, min(limit, 2000))))
        return [{**a, "severity": policy(a["rule"])["severity"], "runbook": policy(a["rule"])["runbook"]} for a in rows]

    @app.get("/api/v1/join-codes")
    def api_join_codes(spent: bool = False, id: str | None = None, actor=Depends(who), _=Depends(need_admin)):
        """Join codes with their state and the machines that used them (node-enrollment.md, "Code types")."""
        from . import joincodes
        return joincodes.listing(db, include_spent=spent, code_id=id)

    @app.get("/api/v1/alerts/precision")
    def api_alert_precision(days: float = 7.0, actor=Depends(who)):
        from . import alerting
        return {"days": days, "rules": alerting.precision(db, days)}

    @app.post("/api/v1/modules/bundles")
    async def api_bundle_upload(request: Request, actor=Depends(who), _=Depends(need_admin)):
        """Stage a bundle's bytes for modules.install (content-addressed; installing is the audited operation)."""
        import hashlib
        data = await request.body()
        if not data or len(data) > 512 * 1024 * 1024:
            raise core.ApiError(413 if data else 400, "bad_bundle", "send the bundle bytes (at most 512 MB)")
        sha = hashlib.sha256(data).hexdigest()
        d = C.HOME / "modules" / "incoming"
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{sha}.tmp"
        tmp.write_bytes(data)
        tmp.replace(d / f"{sha}.mfb")
        db.event("module_bundle_staged", actor=actor, reason=sha[:12], size=len(data))
        return {"sha256": sha, "size": len(data), "next": "POST /api/v1/ops/modules.install {params: {sha256}}"}

    def need_operator(request: Request):
        """Blob uploads: an operator or an admin, with a full token (a module CLI's scoped token stages no bytes)."""
        if ops.ROLE_RANK.get(getattr(request.state, "role", None), -1) < ops.ROLE_RANK["operator"] or getattr(request.state, "scope", None):
            raise core.ApiError(403, "forbidden_role", "uploads need the operator role and an unscoped token")

    @app.post("/api/v1/uploads/{digest}")
    async def api_upload_begin(digest: str, request: Request, actor=Depends(who), _=Depends(need_operator)):
        """Create or resume a blob upload ({offset, complete}); datasets.register then names the blobs (the audited
        operation). After tus 1.0, with the digest as the upload's id (docs/design/datasets-media-checkpoints.md)."""
        body = await request.json()
        return await run_in_threadpool(_blob_call, blobstore.begin, db, f"account:{actor}", digest, body.get("size"))

    @app.patch("/api/v1/uploads/{digest}")
    async def api_upload_append(digest: str, request: Request, actor=Depends(who), _=Depends(need_operator)):
        return await _append(db, f"account:{actor}", digest, request)

    @app.get("/api/v1/blobs/{digest}")
    def api_blob(digest: str, actor=Depends(who)):
        """A dataset file or a result artifact, as a download (attachment, ranges); never rendered."""
        p = blobstore.path(db, digest)
        if p is None or not (db.one("SELECT 1 FROM datasets WHERE instr(files_json, ?) > 0 LIMIT 1", (digest,))
                             or db.one("SELECT 1 FROM results WHERE canonical=1 AND instr(result_json, ?) > 0 LIMIT 1", (digest,))):
            raise core.ApiError(404, "not_found", f"no dataset file or result artifact {digest}")
        return FileResponse(p, media_type="application/octet-stream", filename=digest, headers=DOWNLOAD_HEADERS)

    @app.get("/api/v1/datasets/{did:path}")
    def api_dataset(did: str, actor=Depends(who)):
        d = datasets.detail(db, did)
        if not d:
            raise core.ApiError(404, "not_found", f"dataset {did}")
        return d

    @app.get("/api/v1/folders")
    def api_folders(actor=Depends(who)):
        """The folder registry, each node's statement (and whether it is signed) and what each node reports."""
        from . import folders, statements
        return {"registry": folders.registry(db), "statements": statements.statements(db), "signing": C.RELEASE_SIGNING,
                "nodes": {n["node_id"]: {"hostname": n["hostname"], "folders": folders.report(n)}
                          for n in db.q("SELECT node_id, hostname, folders_json FROM nodes WHERE lifecycle!='retired'")}}

    @app.get("/api/v1/statements")
    def api_statements(actor=Depends(who)):
        """Each node's signed statement (statements.py: its folders and added tool paths) and whether it is signed."""
        from . import statements
        return {"statements": statements.statements(db), "signing": C.RELEASE_SIGNING}

    @app.get("/api/v1/tools")
    def api_tools(node: str | None = None, module: str | None = None, actor=Depends(who)):
        """Host tools (docs/design/host-tools.md): the definitions, the paths set where nodes inherit them, and the
        detection and resolution matrix: every node (or `node`) with what it found and each enabled module's resolution
        per tool request, or, with `module`, that module's Nodes matrix."""
        from . import tools
        return tools.api(db, node, module)

    @app.get("/api/v1/campaigns/{cid}/artifacts")
    def api_campaign_artifacts(cid: str, actor=Depends(who)):
        if not db.one("SELECT 1 FROM campaigns WHERE campaign_id=?", (cid,)):
            raise core.ApiError(404, "not_found", f"campaign {cid}")
        return campaigns.artifacts(db, cid)

    @app.post("/api/v1/coordinator/builds")
    async def api_coordinator_build_upload(request: Request, actor=Depends(who), _=Depends(need_admin)):
        """Stage a coordinator build archive for coordinator.builds.upload (registering is the audited operation)."""
        from . import coordbuilds
        try:
            out = coordbuilds.stage(await request.body())
        except coordbuilds.BuildError as e:
            raise core.ApiError(400, "bad_coordinator_build", str(e))
        return {**out, "next": "POST /api/v1/ops/coordinator.builds.upload {params: {sha256}}"}

    @app.get("/api/v1/coordinator/builds")
    def api_coordinator_builds(actor=Depends(who)):
        from . import coordbuilds
        return {"builds": coordbuilds.builds(db), "signing": C.RELEASE_SIGNING}

    @app.post("/api/v1/agent/builds")
    async def api_agent_build_upload(request: Request, actor=Depends(who), _=Depends(need_admin)):
        """Stage a oarbank-agent binary for agent.upload (content-addressed; registering is the audited operation)."""
        try:
            out = agentbuilds.stage(await request.body())
        except agentbuilds.BuildError as e:
            raise core.ApiError(400, "bad_agent_build", str(e))
        db.event("agent_build_staged", actor=actor, reason=out["sha256"][:12], size=out["size"])
        return {**out, "next": "POST /api/v1/ops/agent.upload {params: {sha256}}"}

    @app.get("/api/v1/coordinator")
    def api_coordinator(actor=Depends(who)):
        return coordmove.status(db)

    @app.get("/api/v1/coordinator/statement")
    def api_coordinator_statement(actor=Depends(who)):
        m = coordmove.move(db)
        return {"statement": m["statement"] if m else None, "state": m["state"] if m else None}

    @app.get("/api/v1/owner")
    def api_owner(actor=Depends(who)):
        from . import owner
        a = owner.anchors(db)
        return {"signing": C.RELEASE_SIGNING, "version": a["doc"]["version"] if a else 0, "keys": owner.keys(db),
                "rescue": (a["doc"].get("rescue") or []) if a else [], "required_on_moves": owner.required(db),
                "coordinator_cik": identity.key(Path(db.path).parent).public_b64}

    @app.get("/api/v1/agent/builds")
    def api_agent_builds(actor=Depends(who)):
        return agentbuilds.view(db)

    @app.get("/api/v1/modules/store")
    def api_module_store(actor=Depends(who)):
        return {"installed": [{k: v for k, v in r.items() if k != "manifest"} for r in modstore.installed(db)],
                "channels": modstore.channels(db), "pins": [{"name": n, "node_id": nd, "version": v}
                                                            for (n, nd), v in modstore.pins(db).items()]}

    @app.get("/api/v1/modules/readiness")
    def api_modules_readiness(actor=Depends(who)):
        """Every installed module's readiness checklist (readiness.py): what stands between it and running work."""
        from . import readiness
        return readiness.all_modules(db)

    @app.get("/api/v1/modules/{name}/readiness")
    def api_module_readiness(name: str, actor=Depends(who)):
        from . import readiness
        r = readiness.module(db, name)
        if r is None:
            raise core.ApiError(404, "not_found", f"no module {name} is installed")
        return r

    @app.get("/api/v1/modules/{name}/secrets")
    def api_module_secrets(name: str, actor=Depends(who)):
        """The module's declared secrets: set or not, fingerprints, when and by whom, per scope. Never a value."""
        from . import modsecrets
        return {"module": name, "secrets": modsecrets.listing(db, name)}

    @app.get("/api/v1/ops")
    def api_ops(actor=Depends(who)):
        return [{**o.model_dump(), "reason_policy": o.reason_policy} for o in registry.OPS]

    explain_slots = threading.BoundedSemaphore(2)          # explain has its own limiter (admin-console.md)

    @app.get("/api/v1/explain/{kind}/{ident}")
    def api_explain(kind: str, ident: str, actor=Depends(who)):
        from . import explain as explainer
        if not explain_slots.acquire(timeout=2):
            raise core.ApiError(503, "busy", "explain is at capacity", headers={"Retry-After": "2"})
        try:
            doc = explainer.explain(db, kind, ident)
        finally:
            explain_slots.release()
        if doc is None:
            raise core.ApiError(404, "not_found", f"{kind} {ident}")
        return doc.model_dump(mode="json")

    @app.get("/api/v1/audit")
    def api_audit(before: int | None = None, limit: int = 100, op: str | None = None, target: str | None = None,
                  actor=Depends(who)):
        where, args = [], []
        if before:
            where.append("event_id < ?"); args.append(before)
        if op:
            where.append("operation LIKE ?"); args.append(op.replace("*", "%"))
        if target:
            where.append("target_id = ?"); args.append(target)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY event_id DESC LIMIT ?"
        return db.q(sql, (*args, max(1, min(limit, 500))))

    @app.get("/api/v1/fleet")
    def api_fleet(actor=Depends(who)):
        d = fleet_data()
        return {k: d[k] for k in ("nodes", "enrollments", "campaigns", "alerts", "discovered")}

    @app.get("/api/v1/campaigns")
    def api_campaigns(module: str = "", state: str = "", actor=Depends(who)):
        rows = db.q("SELECT campaign_id FROM campaigns WHERE (?='' OR module=?) AND (?='' OR state=?) ORDER BY created_at DESC LIMIT 500",
                    (module, module, state, state))
        return [campaigns.summary(db, r["campaign_id"]) for r in rows]

    @app.get("/api/v1/campaigns/{cid}")
    def api_campaign(cid: str, actor=Depends(who)):
        c = campaigns.summary(db, cid)
        if not c:
            raise core.ApiError(404, "not_found", f"campaign {cid}")
        return c

    # ---------------- one node, one job, one node's protection: what `oarbank node|job|protection show` print (detail.py,
    # protection.status; the console renders the same documents from its own read connection; docs/design/console-parity.md)
    @app.get("/api/v1/nodes/{nid}")
    def api_node(nid: str, actor=Depends(who)):
        from . import detail
        n = db.one("SELECT node_id FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
        if n is None:
            raise core.ApiError(404, "not_found", f"node {nid}")

        def manifest_for(name: str):                       # the module version this node runs
            try:
                return modcalls.info_for(name, modstore.version_for_node(db, name, n["node_id"])).manifest
            except KeyError:
                return None
        return detail.node(db, nid, clock.now(), manifest_for)

    @app.get("/api/v1/nodes/{nid}/protection")
    def api_node_protection(nid: str, actor=Depends(who)):
        from . import protection
        d = protection.status(db, nid)
        if d is None:
            raise core.ApiError(404, "not_found", f"node {nid}")
        return d

    @app.get("/api/v1/jobs/{jid}")
    def api_job(jid: int, actor=Depends(who)):
        """The job, its attempts, the checkpoint its next attempt resumes from, its results and its explain document."""
        from . import detail, explain as explainer
        d = detail.job(db, jid)
        if d is None:
            raise core.ApiError(404, "not_found", f"job {jid}")
        if not explain_slots.acquire(timeout=2):
            raise core.ApiError(503, "busy", "explain is at capacity", headers={"Retry-After": "2"})
        try:
            d["explain"] = explainer.explain(db, "job", str(jid)).model_dump(mode="json")
        finally:
            explain_slots.release()
        return d

    @app.get("/api/v1/modules/{name}/views/{view_id}")
    def api_module_view(name: str, view_id: str, campaign: str = "", actor=Depends(who)):
        """A materialized module view (oarbankd computes them; nobody waits on the module)."""
        row = db.one("SELECT doc_json, computed_at, error, error_at FROM module_views WHERE module=? AND view_id=? AND params_hash=?",
                     (name, view_id, campaign))
        if not row:
            raise core.ApiError(404, "not_computed", f"{name}/{view_id} {campaign}".strip())
        doc = json.loads(row["doc_json"]) if row["doc_json"] else {}
        return {**doc, "computed_at": row["computed_at"], "error": row["error"],
                "stale": bool(row["error_at"] and row["error_at"] > (row["computed_at"] or 0))}

    @app.get("/api/v1/modules/{name}/store/{collection}")
    def api_module_store(name: str, collection: str, actor=Depends(who)):
        return [{**json.loads(r["doc_json"]), "_key": r["key"]} for r in
                db.q("SELECT key, doc_json FROM module_store WHERE module=? AND collection=? ORDER BY key LIMIT 5000", (name, collection))]

    @app.get("/api/v1/datasets")
    def api_datasets(kind: str = "", actor=Depends(who)):
        return datasets.list_by(db, kind or None)

    @app.get("/api/v1/modules")
    def api_modules(actor=Depends(who)):
        return modcalls.catalog_rows(db)

    # ---------------- settings (docs/design/settings.md): the registry, effective values, the chain, the reverse view
    def _settings_doc(fn):
        from .settings import SettingError
        try:
            out = fn()
        except SettingError as e:
            raise core.ApiError(404 if e.code in ("unknown_setting", "unknown_campaign") else 400, e.code, e.detail)
        if out is None:
            raise core.ApiError(404, "not_found", "no such node")
        return out

    @app.get("/api/v1/settings/schema")
    def api_settings_schema(actor=Depends(who)):
        from .settings import registry, store
        from .settings import resolve as V
        snap = V.snapshot(db)
        return {"settings": registry.schema_doc(snap.defs), "sections": {k: {"title": t, "help": h} for k, (t, h) in registry.SECTIONS.items()},
                "groups": store.groups(db), "scopes": list(registry.SCOPES), "modules": snap.modules,
                "module_core_keys": list(registry.MODULE_CORE_KEYS)}

    @app.get("/api/v1/settings/effective")
    def api_settings_effective(node: str = "", module: str = "", campaign: str = "", actor=Depends(who)):
        from .settings import views
        return _settings_doc(lambda: views.effective_doc(db, node or None, module, campaign))

    @app.get("/api/v1/settings/explain")
    def api_settings_explain(key: str, node: str = "", module: str = "", campaign: str = "", actor=Depends(who)):
        from .settings import views
        return _settings_doc(lambda: views.explain_doc(db, key, node or None, module, campaign))

    @app.get("/api/v1/settings/overrides")
    def api_settings_overrides(key: str, module: str = "", scope: str = "", actor=Depends(who)):
        from .settings import views
        return _settings_doc(lambda: views.overrides_doc(db, key, module, scope))

    # ---------------- node groups and labels (docs/design/settings.md, "Groups and labels")
    @app.get("/api/v1/groups")
    def api_groups(actor=Depends(who)):
        from .settings import groups
        return groups.view(db)

    @app.get("/api/v1/groups/preview")
    def api_group_preview(selector: str = "", members: str = "", actor=Depends(who)):
        """Live member preview while a group is edited: which nodes a selector and members would take in, and why (a
        read: nothing is written)."""
        from .settings import groups, resolve as V
        try:
            sel = json.loads(selector) if selector.strip() else {}
        except ValueError:
            raise core.ApiError(400, "bad_selector", "selector: a JSON object")
        try:
            g = {"selector": groups.check_selector(sel),
                 "members": groups.check_members(db, [x.strip() for x in members.split(",") if x.strip()])}
        except groups.GroupError as e:
            raise core.ApiError(e.status, e.code, e.detail)
        snap = V.snapshot(db)
        rows = db.q("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
        out = []
        for n in rows:
            m = groups.membership(g, n, snap.node_labels(n)["all"])
            out.append({"node_id": n["node_id"], "hostname": n["hostname"], **m})
        return {"rule": groups.describe(g, {n["node_id"]: n["hostname"] for n in rows}), "nodes": out,
                "members": sum(1 for x in out if x["member"])}

    @app.get("/api/v1/groups/{ident}")
    def api_group(ident: str, actor=Depends(who)):
        from .settings import groups
        out = groups.view(db, ident)
        if not out["groups"]:
            raise core.ApiError(404, "unknown_group", f"no group {ident!r}")
        return {"group": out["groups"][0], "labels": out["labels"]}

    @app.get("/api/v1/features")
    def api_features(actor=Depends(who)):
        return {"release_signing": C.RELEASE_SIGNING}

    @app.get("/api/v1/verify")
    def api_verify(actor=Depends(who)):
        from . import invariants
        return invariants.report(db, clock.now())

    @app.get("/api/v1/releases")
    def api_releases(actor=Depends(who)):
        """The latest releases; `awaiting` names, for one the owner must sign before nodes get it, the command that
        lets it through (releases.awaiting)."""
        from . import releases
        wait = {a["release_id"]: a for a in releases.awaiting(db)}
        return [{**{k: v for k, v in r.items() if k != "composition_json"}, "modules": releases.contents(r["composition_json"]),
                 "awaiting": wait.get(r["release_id"])} for r in db.q(
            "SELECT release_id, platform, created_at, sha256, status, seq, signature IS NOT NULL AS signed, composition_json "
            "FROM releases ORDER BY created_at DESC LIMIT 50")]

    @app.get("/api/v1/events")
    def api_events(after: int = 0, actor=Depends(who)):
        return db.q("SELECT * FROM events WHERE event_id>? ORDER BY event_id LIMIT 500", (after,))

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(actor=Depends(who)):
        def build():
            lines = []
            for r in ro.q("SELECT state, COUNT(*) n FROM jobs GROUP BY state"):
                lines.append(f'oarbank_jobs{{state="{r["state"]}"}} {r["n"]}')
            for n in ro.q("SELECT hostname, capacity_json, last_heartbeat_at FROM nodes WHERE lifecycle!='retired'"):
                cap = jl(n["capacity_json"], {})
                lines.append(f'oarbank_node_slots{{node="{n["hostname"]}"}} {cap.get("cpu_slots", 0)}')
                lines.append(f'oarbank_node_heartbeat_age{{node="{n["hostname"]}"}} {clock.now() - (n["last_heartbeat_at"] or 0):.0f}')
            w = db.lock.stats()
            lines.append(f'oarbank_writer_wait_p99_ms {w["wait_p99_ms"] or 0}')
            return "\n".join(lines) + "\n"
        return ro.cached("metrics", build)          # at most one build per second, off the writer lock

    return app


# ============================================================================ background
class EventBus:
    """Wakes SSE generators when a new event is written (thread-safe -> asyncio)."""

    def __init__(self):
        self.loop = None
        self.cond = None

    def bind(self, loop):
        self.loop = loop
        self.cond = asyncio.Event()

    def notify(self, _eid):
        if self.loop:
            self.loop.call_soon_threadsafe(self.cond.set)

    async def wait(self, timeout):
        try:
            await asyncio.wait_for(self.cond.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        self.cond.clear()


def campaign_loop(db: DB, stop: threading.Event):
    """Campaign ticks (module IPC) run on their own thread, so a slow module can never delay lease expiry."""
    from . import modlife
    last_integrity = 0.0
    while not stop.is_set():
        try:
            if coordmove.serving(db):
                if db.get_state("move_postflight_pending"):
                    modlife.postflight(db)               # once, on a coordinator that just took over
                campaigns.tick_all(db)
                if clock.now() - last_integrity > 3600:
                    last_integrity = clock.now()
                    modlife.routine(db)                  # each module at most once a day
        except Exception as e:
            db.event("background_error", reason=f"campaigns: {e!r}"[:300])
        stop.wait(C.REAPER_EVERY)


def _audit_hourly(db: DB):
    """Sign the audit chain head, then verify the whole chain and every digest (D13): a failure is a
    P5 alert (latched until the chain verifies again)."""
    try:
        d = audit.write_digest(db, audit.Signer())
        if d:
            audit.export_digest(db, d)
            c = audit.copy_off_host(db)
            if c and not c["ok"]:
                core._alert(db, "audit_copy_failed", "audit", f"the off-host copy of the audit digests failed: {c['detail']}")
            elif c:
                core._resolve_alert(db, "audit_copy_failed", "audit")
    except Exception as e:                    # no Keychain (e.g. headless test box): verify the chain only
        db.event("audit_digest_error", reason=repr(e)[:300])
    v = audit.verify(db)
    if v["ok"]:
        core._resolve_alert(db, "audit_chain_broken", "audit")
    else:
        core._alert(db, "audit_chain_broken", "audit", f"audit verification failed: {v}", priority="max")


def _check_invariants(db: DB):
    """Latched invariant conditions: a False check opens a P5 alert that stays open until an operator
    resolves it (the condition returning to True does not clear it)."""
    from . import invariants
    conds = invariants.conditions(db, clock.now())
    prev = {c["id"]: c for c in (db.get_state("invariant_conditions") or [])}
    for c in conds:
        c["last_transition_at"] = prev.get(c["id"], {}).get("last_transition_at", c["checked_at"]) \
            if prev.get(c["id"], {}).get("status") == c["status"] else c["checked_at"]
        if c["status"] == "False":
            core._alert(db, f"invariant:{c['id']}", "fleet", f"{c['id']} ({c['name']}): {c['message']}", priority="max")
    db.set_state("invariant_conditions", conds)


def background(db: DB, stop: threading.Event):
    last_disc = last_ckpt = last_audit = last_inv = last_views = 0.0
    while not stop.is_set():
        try:
            coordmove.driver_tick(db)
            if not coordmove.serving(db):               # frozen for a move, a standby, or handed off: no writes
                stop.wait(2)
                continue
            db.set_state("alive_at", clock.now())      # restart outage = now - alive_at
            core.reap(db)            # campaign ticks run on their own thread (campaign_loop) so a slow module
            t = clock.now()          # can never delay lease expiry (bench/README.md bottleneck 4)
            if t - last_disc > 60:
                db.set_state("discovered", core.tailscale_peers())
                last_disc = t
            if t - last_views > 10:
                from . import modviews
                modviews.refresh(db)
                last_views = t
            if t - last_inv > 60:
                _check_invariants(db)
                from . import releases
                releases.ensure_fleet(db)       # each platform's release (and which one waits for the owner)
                last_inv = t
            if t - last_audit > 3600:
                _audit_hourly(db)
                last_audit = t
            if t - last_ckpt > 300:
                busy, frames, done = db.checkpoint()
                if busy:
                    db.event("wal_checkpoint_blocked", reason=f"frames={frames} checkpointed={done}")
                last_ckpt = t
                day = time.strftime("%Y%m%d")
                dest = C.HOME / "backups" / f"fleet-{day}.sqlite3"
                if not dest.exists():
                    db.backup(dest)
                    for old in sorted((C.HOME / "backups").glob("fleet-*.sqlite3"))[:-7]:
                        old.unlink()
                    db.event("backup", reason=str(dest))
                    db.event("pruned", **db.prune(), upload_partials=blobstore.sweep_partials(db))
        except Exception as e:
            db.event("background_error", reason=repr(e)[:300])
        stop.wait(C.REAPER_EVERY)

