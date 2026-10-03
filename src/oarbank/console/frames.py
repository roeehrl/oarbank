"""The module origin (PLAN D23): a separate listener that serves module iframe views, so module
JavaScript never runs in the console origin.

Each response carries a CSP with the `sandbox` directive (scripts and forms only; never same-origin),
`frame-ancestors` limited to the console, no network access (`connect-src 'none'`; data comes only over
the MessagePort bridge), `nosniff`, and no cookies. Only files under the iframe entry's own directory are
served, with an extension whitelist; paths are resolved and confined.
"""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

ALLOWED = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
           ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2"}


def frame_csp(console_origin: str) -> str:
    return ("sandbox allow-scripts allow-forms; default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; "
            f"frame-ancestors {console_origin}")


def frames_app(catalog, console_origin: str, refresh=None) -> FastAPI:
    """`catalog` is the console's ModuleCatalog; `refresh()` reloads it from oarbankd when a module is unknown."""
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

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
