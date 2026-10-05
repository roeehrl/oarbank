"""The module origin (PLAN D23): a separate listener that serves module iframe views and media bytes, so module
JavaScript and module media never reach the console origin.

Each response carries a CSP with the `sandbox` directive (scripts and forms only; never same-origin),
`frame-ancestors` limited to the console, no network access (`connect-src 'none'`; data comes only over
the MessagePort bridge), images and media only from this origin (the bridge's `read.media` capability URLs, UI contract
1.2), `nosniff`, and no cookies. Only files under the iframe entry's own directory are
served, with an extension whitelist; paths are resolved and confined.

Media (`/b/<token>`, UI contract 1.1): a capability URL the console minted after it checked that the artifact belongs to
the module (console/media.py). The bytes are served only as an allowed type for the token's kind, sniffed from the file
(oarbank_sdk.media), with `nosniff`, a sandboxing CSP, no cookies and single `Range` requests.
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from oarbank_sdk import media as M
from oarbank_sdk.render import frame_csp, media_csp

ALLOWED = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
           ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2"}


def frames_app(catalog, console_origin: str, refresh=None, tokens=None, reader=None, home: Path | None = None) -> FastAPI:
    """`catalog` is the console's ModuleCatalog; `refresh()` reloads it from oarbankd when a module is unknown. `tokens`
    (console/media.Tokens), `reader` (a read connection) and `home` (the coordinator's home, where blobs live) serve
    media."""
    app = FastAPI(title="Oarbank module origin", docs_url=None, redoc_url=None, openapi_url=None)
    policy = frame_csp(console_origin)

    def deny(status=404, text="not found"):
        return PlainTextResponse(text, status_code=status, headers={"Content-Security-Policy": policy,
                                                                    "X-Content-Type-Options": "nosniff"})

    @app.get("/f/{module}/{view}/{path:path}")
    def serve(module: str, view: str, path: str = ""):
        if module not in catalog.rows and refresh:
            refresh()
        man = catalog.manifest(module)
        decl = next((f for f in (man.ui.iframes if man else []) if f.id == view), None)
        if decl is None:
            return deny()
        root = catalog.path(module).resolve()
        entry = (root / decl.entry).resolve()
        base = entry.parent
        target = entry if not path else (base / path).resolve()
        if base != target.parent and base not in target.parents:
            return deny(403, "outside the frame directory")
        if not target.is_file() or target.suffix not in ALLOWED:
            return deny()
        return Response(target.read_bytes(), media_type=ALLOWED[target.suffix], headers={
            "Content-Security-Policy": policy, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "cross-origin"})

    @app.get("/b/{token}")
    def media(token: str, request: Request):
        doc = tokens.check(token) if tokens is not None else None
        if doc is None:
            return deny(403, "expired or not a media link")
        row = reader.one("SELECT path, size FROM blobs WHERE digest=?", (doc["d"],))
        p = Path(row["path"]) if row and row["path"] else None
        p = p if p is None or p.is_absolute() else Path(home) / p
        if p is None or not p.is_file():
            return deny()
        size = p.stat().st_size
        with open(p, "rb") as f:
            head = f.read(M.HEAD_BYTES)
        why = M.problem(doc["k"], head, size)
        if why:
            return deny(415 if "type" in why else 413, f"refused: {why}")
        rng = M.byte_range(request.headers.get("range"), size)
        if rng == "unsatisfiable":
            return Response(status_code=416, headers={"Content-Range": f"bytes */{size}", "X-Content-Type-Options": "nosniff",
                                                      "Content-Security-Policy": media_csp(console_origin)})
        start, end = rng if rng else (0, size - 1)
        exp = max(0, int(doc["x"] - __import__("time").time()))

        def body():
            with open(p, "rb") as f:
                f.seek(start)
                left = end - start + 1
                while left > 0:
                    b = f.read(min(1 << 20, left))
                    if not b:
                        return
                    left -= len(b)
                    yield b
        headers = {"Content-Length": str(end - start + 1), "Accept-Ranges": "bytes", "X-Content-Type-Options": "nosniff",
                   "Content-Security-Policy": media_csp(console_origin), "Cross-Origin-Resource-Policy": "cross-origin",
                   "Referrer-Policy": "no-referrer", "Cache-Control": f"private, max-age={exp}", "Content-Disposition": "inline"}
        if rng:
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        return StreamingResponse(body(), status_code=206 if rng else 200, media_type=M.sniff(doc["k"], head), headers=headers)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
