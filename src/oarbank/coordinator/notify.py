"""Push notifications via ntfy (self-hosted or ntfy.sh), configured in the Notifications settings: `ntfy.url` (the
topic, e.g. "https://ntfy.sh/<secret-topic>" or "http://127.0.0.1:8090/oarbank"), `ntfy.click_base` (where a tapped
notification opens) and the write-only core secret `ntfy_token`. No URL = notifications off."""
import threading
import urllib.request


def send(db, title: str, message: str, priority: str = "default", click: str | None = None):
    from . import modsecrets
    from .settings import fleet_value
    url, click_base = fleet_value(db, "ntfy.url"), fleet_value(db, "ntfy.click_base")
    if not url:
        return
    try:
        token = modsecrets.core_value(db, "ntfy_token")
    except Exception:                                      # noqa: BLE001 (no secret store: send without the token)
        token = None

    def _go():
        try:
            req = urllib.request.Request(url, data=message.encode(), method="POST")
            req.add_header("Title", title)
            req.add_header("Priority", {"high": "4", "urgent": "5", "max": "5"}.get(priority, "3"))
            req.add_header("Tags", "computer")
            if click or click_base:
                req.add_header("Click", click or click_base)
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:  # never let notifications break scheduling
            db.event("notify_failed", reason=str(e)[:200])

    threading.Thread(target=_go, daemon=True).start()
