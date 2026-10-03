"""Push notifications via ntfy (self-hosted or ntfy.sh). Configured in settings.ntfy:
{"url": "https://ntfy.sh/<secret-topic>" | "http://127.0.0.1:8090/oarbank", "token": null,
 "click_base": "https://oarbank.<tailnet>.ts.net"}. Unset = notifications off."""
import threading
import urllib.request


def send(db, title: str, message: str, priority: str = "default", click: str | None = None):
    cfg = db.get_setting("ntfy")
    if not cfg or not cfg.get("url"):
        return

    def _go():
        try:
            req = urllib.request.Request(cfg["url"], data=message.encode(), method="POST")
            req.add_header("Title", title)
            req.add_header("Priority", {"high": "4", "urgent": "5", "max": "5"}.get(priority, "3"))
            req.add_header("Tags", "computer")
            if click or cfg.get("click_base"):
                req.add_header("Click", click or cfg["click_base"])
            if cfg.get("token"):
                req.add_header("Authorization", f"Bearer {cfg['token']}")
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:  # never let notifications break scheduling
            db.event("notify_failed", reason=str(e)[:200])

    threading.Thread(target=_go, daemon=True).start()
