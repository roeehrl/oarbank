"""Alert calibration: pending periods, flap collapse, the node_offline threshold, P5 re-notification,
acknowledgement with a verdict, and the precision review."""

import pytest

from oarbank.coordinator import alerting, clock, core, ops

from helpers import certify, enrolled_node, make_db


@pytest.fixture
def db(tmp_path):
    clock.set_fake(1_900_000_000.0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    sent = []
    from oarbank.coordinator import notify
    orig = notify.send
    notify.send = lambda db, title, message, priority="default", click=None: sent.append((title, priority))
    d.sent = sent
    yield d
    notify.send = orig
    clock.set_fake(None)


def states(db, rule):
    return [a["state"] for a in db.q("SELECT state FROM alerts WHERE rule=? ORDER BY alert_id", (rule,))]


def test_a_pending_alert_notifies_only_if_it_outlives_its_period(db):
    core._alert(db, "breaker", "n_x", "3 failures")
    assert states(db, "breaker") == ["pending"] and db.sent == []
    clock.advance(600)
    alerting.promote_pending(db, clock.now())
    assert states(db, "breaker") == ["pending"]
    clock.advance(301)
    alerting.promote_pending(db, clock.now())
    assert states(db, "breaker") == ["open"] and db.sent == [("Oarbank: breaker", "default")]
    core._alert(db, "doctor_failed:relay", "n_y", "doctor failed")
    core._resolve_alert(db, "doctor_failed:relay", "n_y")                 # cleared within 5 min: never notified
    assert states(db, "doctor_failed:relay") == ["dismissed"] and len(db.sent) == 1


def test_repeated_trips_collapse_into_one_flapping_alert(db):
    for _ in range(7):                                                     # one node, 7 trips in 25 minutes
        core._alert(db, "breaker", "n_mac", "3 failures (last: exit_nonzero)")
        clock.advance(30)
        core._resolve_alert(db, "breaker", "n_mac")
        clock.advance(180)
    assert states(db, "breaker:flapping") == ["open"]
    assert [t for t, _ in db.sent] == ["Oarbank: breaker:flapping"]      # one push instead of seven
    clock.advance(3600)
    alerting.promote_pending(db, clock.now())
    assert states(db, "breaker:flapping") == ["resolved"]                  # an hour without trips


def test_node_offline_waits_ten_minutes(db):
    n = certify(db, enrolled_node(db)[1])
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (clock.now() - 300, n["node_id"]))
    core.reap(db)
    assert not db.q("SELECT 1 FROM alerts WHERE rule='node_offline'")      # a sleeping Mac, back within minutes
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (clock.now() - 700, n["node_id"]))
    core.reap(db)
    assert states(db, "node_offline") == ["open"]


def test_p5_renotifies_until_acknowledged_and_ack_records_the_verdict(db):
    core._alert(db, "invariant:S7", "fleet", "S7 failed", priority="max")
    a = db.one("SELECT alert_id FROM alerts WHERE rule='invariant:S7'")["alert_id"]
    clock.advance(1801)
    alerting.promote_pending(db, clock.now())
    assert len(db.sent) == 2 and "still open" in db.sent[1][0]
    ops.execute(db, ops.OpRequest(op="alerts.ack", actor="owner", target=str(a), params={"useful": True}))
    clock.advance(3600)
    alerting.promote_pending(db, clock.now())
    assert len(db.sent) == 2
    with pytest.raises(core.ApiError, match="note"):
        ops.execute(db, ops.OpRequest(op="alerts.resolve", actor="owner", target=str(a)))
    ops.execute(db, ops.OpRequest(op="alerts.resolve", actor="owner", target=str(a), reason="bug fixed in claim()"))
    row = db.one("SELECT * FROM alerts WHERE alert_id=?", (a,))
    assert (row["state"], row["resolved_how"], row["useful"], row["acked_by"]) == ("resolved", "manual", 1, "owner")


def test_snooze_and_the_precision_review(db):
    for i in range(4):
        core._alert(db, f"revoked:relay", f"n_{i}", "golden mismatch")
    ids = [r["alert_id"] for r in db.q("SELECT alert_id FROM alerts WHERE rule='revoked:relay'")]
    for i, a in enumerate(ids):
        ops.execute(db, ops.OpRequest(op="alerts.ack", actor="owner", target=str(a), params={"useful": i == 0}))
    ops.execute(db, ops.OpRequest(op="alerts.snooze", actor="owner", target=str(ids[0]), params={"minutes": 30}))
    assert db.one("SELECT snoozed_until FROM alerts WHERE alert_id=?", (ids[0],))["snoozed_until"] == pytest.approx(clock.now() + 1800)
    p = {r["rule"]: r for r in alerting.precision(db, 7, clock.now())}["revoked"]
    assert (p["fired"], p["useful"], p["not_useful"], p["precision"], p["severity"]) == (4, 1, 3, 0.25, "P4")
    assert not p["meets_bar"]                                               # a P4 rule below 50 %: demote or fix it


def test_notifications_and_the_admin_api_name_the_product_oarbank_with_a_capital(tmp_path):
    # push titles said "oarbank: …" and the admin API "oarbank admin API"; lowercase stays only for identifiers
    import ast
    from pathlib import Path
    import oarbank
    from oarbank.coordinator import app as coord_app
    titles = []
    for f in Path(oarbank.__file__).parent.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "send" \
                    and getattr(node.func.value, "id", None) == "notify":
                t = next((k.value for k in node.keywords if k.arg == "title"), node.args[1] if len(node.args) > 1 else None)
                first = t.values[0] if isinstance(t, ast.JoinedStr) else t
                titles.append((f.name, first.value if isinstance(first, ast.Constant) else None))
    assert len(titles) >= 6 and all(isinstance(v, str) and v.startswith("Oarbank: ") for _, v in titles), titles
    assert coord_app.admin_app(make_db(tmp_path / "oarbank.sqlite3")).title == "Oarbank admin API"
    assert oarbank.__doc__.startswith("Oarbank: ") and "Apple Silicon" not in oarbank.__doc__
