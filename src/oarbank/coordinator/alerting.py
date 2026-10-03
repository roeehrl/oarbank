"""Alert policy (admin-console.md "alerts are precise or they are noise"): per rule, a pending period (Alertmanager's
`for:`: a condition that clears within it never notifies), a flap detector (repeated trips of one rule on one subject
become one alert), a runbook line, and the owner's acknowledgement and "useful?" verdict for the precision review.

Calibrated on two days of a small fleet's alert history (19 alerts):
- node_offline fired at 120 s and every one cleared within 2.6 min (sleep and wake), so detection waits 10 min;
- breaker fired 11 times; 8 cleared within 5 min (re-doctor passed) and one node tripped 7 times in 25 min. A 15 min
  pending period plus a 3-trips-per-hour flap alert turns those 11 pushes into 1, the real problem;
- certifying_stuck (3, median 2 h) and doctor_failed (2, ~20 min) were real and stay immediate.
"""
import time

from .db import DB

from ..contracts.alert_rules import policy

RENOTIFY_P5_S = 1800        # a latched safety alert is re-published every 30 min until acknowledged or snoozed


def trips(db: DB, rule: str, subject: str, window_s: float, now: float) -> int:
    return db.one("SELECT COUNT(*) n FROM alerts WHERE rule=? AND subject=? AND opened_at>=?", (rule, subject, now - window_s))["n"]


def promote_pending(db: DB, now: float | None = None) -> int:
    """Pending alerts whose condition outlived the rule's pending period become open (and notify)."""
    from . import notify
    now = now or time.time()
    n = 0
    for a in db.q("SELECT * FROM alerts WHERE state='pending'"):
        if now - (a["opened_at"] or now) >= policy(a["rule"])["pending_s"]:
            db.x("UPDATE alerts SET state='open', last_notified_at=? WHERE alert_id=?", (now, a["alert_id"]))
            db.event("alert_opened", reason=a["rule"], node_id=a["subject"] if (a["subject"] or "").startswith("n_") else None,
                     detail=a["detail"])
            notify.send(db, title=f"Oarbank: {a['rule']}", message=a["detail"])
            n += 1
    for a in db.q("SELECT * FROM alerts WHERE state='open' AND acked_by IS NULL AND (snoozed_until IS NULL OR snoozed_until<?)", (now,)):
        if policy(a["rule"])["severity"] == "P5" and now - (a["last_notified_at"] or 0) >= RENOTIFY_P5_S:
            db.x("UPDATE alerts SET last_notified_at=? WHERE alert_id=?", (now, a["alert_id"]))
            notify.send(db, title=f"Oarbank: {a['rule']} (still open)", message=a["detail"], priority="max")
    # a flap alert clears after a quiet window without new trips
    for a in db.q("SELECT * FROM alerts WHERE state='open' AND rule LIKE '%:flapping'"):
        base = a["rule"].rsplit(":flapping", 1)[0]
        win = (policy(base).get("flap") or (3, 3600))[1]
        last = db.one("SELECT MAX(opened_at) m FROM alerts WHERE rule=? AND subject=?", (base, a["subject"]))["m"] or 0
        if now - last >= win:
            db.x("UPDATE alerts SET state='resolved', resolved_at=?, resolved_how='auto' WHERE alert_id=?", (now, a["alert_id"]))
            db.event("alert_resolved", reason=a["rule"], detail=a["detail"])
    return n


def precision(db: DB, days: float = 7.0, now: float | None = None) -> list[dict]:
    """Per rule over the window: alerts that notified, the owner's verdicts, precision = useful / rated."""
    now = now or time.time()
    out = {}
    for a in db.q("SELECT rule, state, useful, resolved_how, acked_by FROM alerts WHERE opened_at>=? AND state!='dismissed'",
                  (now - days * 86400,)):
        r = a["rule"].split(":", 1)[0] + (":flapping" if a["rule"].endswith(":flapping") else "")
        s = out.setdefault(r, {"rule": r, "severity": policy(r.split(":")[0])["severity"], "fired": 0, "useful": 0,
                               "not_useful": 0, "unrated": 0, "acked": 0, "auto_resolved": 0, "pending": 0})
        if a["state"] == "pending":
            s["pending"] += 1
            continue
        s["fired"] += 1
        s["acked"] += bool(a["acked_by"])
        s["auto_resolved"] += a["resolved_how"] == "auto"
        if a["useful"] is None:
            s["unrated"] += 1
        elif a["useful"]:
            s["useful"] += 1
        else:
            s["not_useful"] += 1
    for s in out.values():
        rated = s["useful"] + s["not_useful"]
        s["precision"] = round(s["useful"] / rated, 3) if rated else None
        s["meets_bar"] = s["severity"] not in ("P4", "P5") or s["precision"] is None or s["precision"] >= 0.5
    return sorted(out.values(), key=lambda s: -s["fired"])
