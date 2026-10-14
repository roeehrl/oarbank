"""Fleet updates on the coordinator (docs/design/fleet-updates.md; D56, D59-D61; S29-S31): the fleet release manifest,
its signature, import and fetch with their refusals, readiness, each node's assignment (pins, holds, stops, never past
the coordinator), the node_update directive and the agent's report, the artifact route, every rule of the rollout tick
(coordinator first, the fleet-health gate, slots, eligibility, budgets, halt and rollback, bake, catch-up, stuck nodes),
the update policy (auto, notify, the periodic check), the operations and the invariants."""
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

from oarbank import __version__, signing
from oarbank.coordinator import clock, core, fleetupdates as F, invariants, ops, predicates, rollouts as RO
from oarbank.coordinator import config as C

from helpers import agent_client, enrolled_node, facts_for, fresh, make_db, node_headers, run_op, set_fleet, set_node

T0 = 1_800_000_000.0                   # a Friday, 08:00 UTC
OLD, MID, NEW, NEXT = "2.9.0", "2.9.5", __version__, "2.11.0"     # NEW is this coordinator's own version
INSTALL = {"format": "tar", "scope": "system", "updater": True, "why": None}


@pytest.fixture(autouse=True)
def fake_clock():
    clock.set_fake(T0)
    yield
    clock.set_fake(None)


@pytest.fixture(autouse=True)
def no_release_source(monkeypatch):
    """The periodic check never reaches the network here (its own test runs it inline)."""
    monkeypatch.setattr(RO, "_spawn", lambda fn: None)


@pytest.fixture
def db(tmp_path):
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    yield d
    d.conn.close()


@pytest.fixture
def coordself(monkeypatch):
    """A stand-in for coordself (the coordinator's own update, another part of 2.10): records requests, reports a state."""
    import oarbank.coordinator as pkg
    from oarbank.coordinator.coordself import SCHEMA
    fake = types.ModuleType("oarbank.coordinator.coordself")
    fake.calls, fake.current, fake.refuse, fake.SCHEMA = [], None, None, SCHEMA     # a DB opens with its table

    class UpdateError(Exception):
        pass
    fake.UpdateError = UpdateError

    def request(db, version, actor):
        if fake.refuse:
            raise UpdateError(fake.refuse)
        fake.calls.append(version)
        fake.current = {"state": "requested", "version": version}
        return fake.current
    fake.request, fake.state = request, lambda db: fake.current
    monkeypatch.setitem(sys.modules, "oarbank.coordinator.coordself", fake)
    monkeypatch.setattr(pkg, "coordself", fake, raising=False)
    return fake


# ------------------------------------------------------------------ a release on disk

def seq_of(v: str) -> int:
    a, b, c = (int(x) for x in v.split("."))
    return a * 10000 + b * 100 + c


def artifact_bytes(name: str) -> bytes:
    return f"package {name}\n".encode() * 50


# a platform neither the test nodes (darwin-arm64) nor this coordinator run: a release's artifacts nobody needs
SPARE = next(p for p in ("windows-amd64", "linux-arm64") if p != F.coordinator_platform())


def write_release(d: Path, version=NEW, seq=None, platforms=None, stops=(), agent_min=OLD, tamper=None, expires=None,
                  short=None) -> Path:
    """A release directory as CI writes it: oarbank-fleet-<v>.json (canonical) beside its artifacts."""
    d.mkdir(parents=True, exist_ok=True)
    platforms = platforms or sorted({"darwin-arm64", SPARE, F.coordinator_platform()})
    arts = []
    for p in platforms:
        for role, fmt, name in (("node", "tar", f"oarbank-agent-{version}-{p}.tar.gz"),
                                ("node", "deb", f"oarbank-agent_{version}_{p}.deb"),
                                ("agent", "binary", f"oarbank-agent-{version}-{p}"),
                                ("coordinator", "tar", f"oarbank-coordinator-{version}-{p}.tar.gz")):
            data = artifact_bytes(name)
            (d / name).write_bytes(data)
            arts.append({"name": name, "role": role, "platform": p, "format": fmt, "sha256": hashlib.sha256(data).hexdigest(),
                         "size": len(data), "agent_version": version})
    doc = {"type": "oarbank-fleet-release", "format": 1, "version": version, "seq": seq or seq_of(version),
           "released_at": "2026-10-20T00:00:00Z", "expires": expires, "notes": f"https://example.invalid/releases/v{version}",
           "agent_min": agent_min, "stops": list(stops), "artifacts": arts}
    (d / f"oarbank-fleet-{version}.json").write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")))
    if tamper:
        data = (d / tamper).read_bytes()
        (d / tamper).write_bytes(b"X" + data[1:])
    if short:
        (d / short).write_bytes((d / short).read_bytes()[:-1])
    return d


def imported(db, tmp_path, version=NEW, **kw) -> dict:
    return F.import_dir(db, write_release(tmp_path / f"rel-{version}", version, **kw), "test")


# ------------------------------------------------------------------ nodes and their agents

def node(db, name, version=OLD, platform="darwin-arm64", install=INSTALL, ring=None):
    _, n = enrolled_node(db, name, {**facts_for(platform), "utc_offset_s": 0})
    hello(db, n, version, install)
    if ring:
        set_node(db, fresh(db, n), "update_ring", ring)
    return fresh(db, n)


def hello(db, n, version, install=INSTALL, report=None):
    body = {"agent_version": version, "facts": json.loads(fresh(db, n)["facts_json"]), "live_attempts": [], "install": install}
    if report:
        body["node_update"] = report
    return core.hello(db, fresh(db, n), body)


def beat(db, n, report=None, install=INSTALL, telemetry=None):
    body = {"attempts": [], "install": install, "telemetry": telemetry or {}}
    if report is not None:
        body["node_update"] = report
    return core.heartbeat(db, fresh(db, n), body)


def rep(state, release=NEW, error=None):
    return {"state": state, "release": release, "seq": seq_of(release), "error": error, "at": clock.now()}


def directive(db, n):
    return beat(db, n)["node_update"]


def install_on(db, n, version=NEW, ok=True):
    """What the agent and its runner do once told go: drain, install, restart on the new version, confirm, commit (or
    roll back on the old version)."""
    for st in ("draining", "installing"):
        beat(db, n, rep(st, version))
    if ok:
        hello(db, n, version, report=rep("confirming", version))
        beat(db, n, rep("done", version))
    else:
        beat(db, n, rep("rolled_back", version, "the new agent never confirmed"))


def tick(db, *nodes, dt=0.0):
    """Time passes (every listed node keeps heartbeating), then one rollout tick."""
    if dt:
        clock.advance(dt)
    for n in nodes:
        beat(db, n)
    RO.tick(db)
    if RO._PREPARING:                     # a coordinator update's prepare runs on its thread: let it finish, tick again
        for job in list(RO._PREPARING.values()):
            assert job["done"].wait(10)
        RO.tick(db)


def heartbeats(db, *nodes, k=RO.BAKE_HEARTBEATS):
    for _ in range(k):
        for n in nodes:
            beat(db, n)


def rn(db, n, rid=None):
    rid = rid or RO.active(db)["rollout_id"]
    return db.one("SELECT * FROM rollout_nodes WHERE rollout_id=? AND node_id=?", (rid, n["node_id"]))


def start(db, version=NEW, **params):
    return run_op(db, "updates.start", version, params)["result"]


def ok(db):
    assert invariants.s29_rollout_cap(db) == []
    assert invariants.s30_no_node_ahead_of_coordinator(db) == []
    assert invariants.s31_go_only_when_eligible(db) == []


def staged(db, *nodes, version=NEW):
    for n in nodes:
        assert directive(db, n)["release"] == version
        beat(db, n, rep("staged", version))


def gone(db, *nodes):
    return [n["hostname"] for n in nodes if (directive(db, n) or {}).get("go")]


def preview(db, op, target=None, params=None):
    return ops.execute(db, ops.OpRequest(op=op, actor="test", target=target, params=params or {}, dry_run=True))["plan"]


# ------------------------------------------------------------------ the manifest and its signature

@pytest.mark.parametrize("change, why", [
    (lambda d: "not json", "not JSON"),
    (lambda d: {**d, "type": "other"}, "oarbank-fleet-release"),
    (lambda d: {**d, "version": "2.10"}, "not a release version"),
    (lambda d: {**d, "seq": 0}, "positive integer"),
    (lambda d: {**d, "stops": ["2.11.0"]}, "older than the release"),
    (lambda d: {**d, "agent_min": "x"}, "agent_min"),
    (lambda d: {**d, "artifacts": []}, "non-empty"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "name": "../evil"}]}, "plain file name"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "sha256": "ABC"}]}, "64 lowercase hex"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "role": "root"}]}, "role"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "format": "exe"}]}, "format"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "platform": "Plan 9"}]}, "platform token"),
    (lambda d: {**d, "artifacts": [{**d["artifacts"][0], "size": -1}]}, "size"),
    (lambda d: {**d, "artifacts": [d["artifacts"][0], d["artifacts"][0]]}, "listed twice"),
])
def test_the_manifest_is_checked(tmp_path, change, why):
    d = write_release(tmp_path / "r")
    doc = json.loads((d / f"oarbank-fleet-{NEW}.json").read_text())
    bad = change(doc)
    with pytest.raises(F.UpdateError, match=why):
        F.parse(bad if isinstance(bad, str) else json.dumps(bad))


def test_the_manifest_text_is_kept_verbatim_and_hashed_as_is(db, tmp_path):
    d = write_release(tmp_path / "r")
    p = d / f"oarbank-fleet-{NEW}.json"
    text = json.dumps(json.loads(p.read_text()), indent=2)         # not canonical: still what everyone hashes
    p.write_text(text)
    rel = F.import_dir(db, d, "test")
    assert rel["manifest_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert db.one("SELECT manifest FROM fleet_releases")["manifest"] == text


def test_fleet_release_statements_sign_the_manifest_hash(tmp_path):
    key = tmp_path / "k" / "owner.key"
    pub = signing.keygen(key)
    stmt = signing.fleet_release_statement(NEW, 21000, "a" * 64)
    doc = json.loads(stmt)
    assert doc["type"] == "oarbank.fleet-release/v1" and stmt == json.dumps(doc, sort_keys=True, separators=(",", ":"))
    assert signing.verify_fleet_release(stmt, signing.sign(stmt, key), pub)["manifest_sha256"] == "a" * 64
    other = signing.agent_statement("a" * 64, NEW, 1, ["darwin-arm64"])
    with pytest.raises(ValueError, match="fleet release"):
        signing.verify_fleet_release(other, signing.sign(other, key), pub)
    with pytest.raises(ValueError, match="bad fleet release signature"):
        signing.verify_fleet_release(stmt, signing.sign(stmt + " ", key), pub)


def test_signing_mode_needs_the_owners_signature_over_this_manifest(db, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    key = tmp_path / "k" / "owner.key"
    db.set_state("release_pubkey", signing.keygen(key))
    a = node(db, "a")
    rel = imported(db, tmp_path)
    assert rel["state"] == "incomplete" and "the owner's signature (oarbank update sign)" in rel["gaps"]
    with pytest.raises(core.ApiError, match="not ready"):
        start(db)
    wrong = signing.fleet_release_statement(NEW, rel["seq"], "b" * 64)
    with pytest.raises(core.ApiError, match="manifest sha256"):
        run_op(db, "updates.sign", NEW, {"statement": wrong, "signature": signing.sign(wrong, key)})
    stmt = signing.fleet_release_statement(NEW, rel["seq"], rel["manifest_sha256"])
    out = run_op(db, "updates.sign", NEW, {"statement": stmt, "signature": signing.sign(stmt, key)})["result"]
    assert out["state"] == "ready" and out["signed"]
    start(db)
    assert directive(db, a)["signature"]["statement"] == stmt


# ------------------------------------------------------------------ import and fetch

def test_import_checks_every_artifact_and_skips_platforms_no_node_runs(db, tmp_path):
    node(db, "a")
    rel = imported(db, tmp_path)
    assert rel["state"] == "ready"
    skipped = {m["platform"] for m in rel["missing"]}
    assert SPARE in skipped and "darwin-arm64" not in skipped
    stored = [a for a in rel["artifacts"] if a["present"]]
    assert stored and all((db.root / "updates" / "artifacts" / a["sha256"]).exists() for a in stored)
    assert all(a["platform"] != SPARE for a in stored)
    again = imported(db, tmp_path)                                   # idempotent
    assert again["manifest_sha256"] == rel["manifest_sha256"]
    win = node(db, "w", platform=SPARE, install={**INSTALL, "format": "msi"})
    with db.tx():
        F.refresh(db)
    assert F.release(db, NEW)["state"] == "ready"   # the release has no msi: the windows node is skipped, never waited for
    assert F.artifact_for(db, NEW, win)[0] is None
    win2 = node(db, "w2", platform=SPARE)
    with db.tx():
        F.refresh(db)
    assert F.release(db, NEW)["state"] == "incomplete"               # a tar node there now: its package was skipped
    imported(db, tmp_path)
    assert F.release(db, NEW)["state"] == "ready" and F.artifact_for(db, NEW, win2)[0]


@pytest.mark.parametrize("kw, why", [
    ({"tamper": f"oarbank-agent-{NEW}-darwin-arm64.tar.gz"}, "sha256"),
    ({"short": f"oarbank-agent-{NEW}-darwin-arm64.tar.gz"}, "bytes, the manifest says"),
    ({"expires": "2020-01-01T00:00:00Z"}, "expired"),
])
def test_import_refuses_tampered_short_and_expired_releases(db, tmp_path, kw, why):
    node(db, "a")
    with pytest.raises(F.UpdateError, match=why):
        imported(db, tmp_path, **kw)
    assert not db.q("SELECT * FROM fleet_releases") and not db.q("SELECT * FROM fleet_artifacts")


def test_import_refuses_another_manifest_for_a_version_and_a_seq_that_does_not_rise(db, tmp_path):
    node(db, "a")
    imported(db, tmp_path)
    with pytest.raises(F.UpdateError, match="already imported with another manifest"):
        F.import_dir(db, write_release(tmp_path / "other", NEW, seq=seq_of(NEW) + 1), "test")
    with pytest.raises(F.UpdateError, match="does not rise"):
        F.import_dir(db, write_release(tmp_path / "old", OLD, seq=seq_of(NEW) + 5), "test")
    with pytest.raises(core.ApiError, match="dir .* or manifest"):
        run_op(db, "updates.import", None, {})


def test_staged_upload_import(db, tmp_path):
    node(db, "a")
    d = write_release(tmp_path / "r")
    shas = [F.stage(db, p.read_bytes())["sha256"] for p in sorted(d.iterdir())]
    man = hashlib.sha256((d / f"oarbank-fleet-{NEW}.json").read_bytes()).hexdigest()
    assert man in shas
    res = run_op(db, "updates.import", None, {"manifest": man})
    assert res["target"] == NEW and res["result"]["state"] == "ready"
    assert not list((db.root / "updates" / "incoming").iterdir())     # staged files are consumed


def test_fetch_downloads_the_release_and_only_what_the_fleet_needs(db, tmp_path):
    node(db, "a")
    src = tmp_path / "source"
    write_release(src / "download" / f"v{NEW}", NEW)
    (src / "latest.json").write_text(json.dumps({"version": NEW}))
    set_fleet(db, "update_source", src.as_uri())
    assert F.latest(db) == NEW
    res = run_op(db, "updates.fetch", "latest")
    rel = res["result"]
    assert res["target"] == NEW and rel["state"] == "ready" and rel["source"] == src.as_uri()
    assert {a["platform"] for a in rel["artifacts"] if a["present"]} <= {"darwin-arm64", F.coordinator_platform()}
    assert not [p for p in (db.root / "updates").iterdir() if p.name.startswith("fetch-")]
    with pytest.raises(core.ApiError, match="download"):
        run_op(db, "updates.fetch", "9.9.9")


def test_latest_asks_github_for_a_github_source(db, monkeypatch):
    seen = []

    def get(url, limit, dest=None):
        seen.append(url)
        return json.dumps({"tag_name": "v2.10.3"}).encode()
    monkeypatch.setattr(F, "_http_get", get)
    assert F.latest(db) == "2.10.3"
    assert seen == ["https://api.github.com/repos/roeehrl/oarbank/releases/latest"]


# ------------------------------------------------------------------ assignment (D61, S30)

def test_assignment_pin_hold_stops_and_never_past_the_coordinator(db, tmp_path):
    a = node(db, "a")
    imported(db, tmp_path, MID)
    imported(db, tmp_path, NEW, stops=[MID])
    imported(db, tmp_path, NEXT)
    assert F.assigned(db, a) is None                                  # no rollout, no pin: it stays
    run_op(db, "updates.pin", "a", {"version": NEW, "reason": "test the stop"})
    assert F.assigned(db, fresh(db, a))["version"] == MID              # a stop it has not reached comes first
    assert directive(db, a)["release"] == MID
    hello(db, a, MID)
    assert F.assigned(db, fresh(db, a))["version"] == NEW
    run_op(db, "updates.pin", "a", {"version": NEXT, "reason": "too new"})
    assert F.assigned(db, fresh(db, a)) is None                        # S30: never newer than this coordinator
    imported(db, tmp_path, OLD)
    run_op(db, "updates.pin", "a", {"version": OLD, "reason": "go back", "until": T0 + 60})
    d = directive(db, a)
    assert d["release"] == OLD and d["rollback"] is True
    clock.advance(61)                                                  # an expired pin is ignored: the node rejoins
    assert F.assigned(db, fresh(db, a)) is None
    run_op(db, "updates.unpin", "a")
    run_op(db, "updates.hold", "a", {"reason": "demo on friday"})
    hello(db, a, OLD)
    rid = start(db)["rollout_id"]
    assert directive(db, a) is None and rn(db, a, rid)["state"] == "skipped" and "held" in rn(db, a, rid)["error"]
    assert db.one("SELECT state FROM rollouts")["state"] == "done"       # every node skipped: nothing to wait for
    run_op(db, "updates.unhold", "a")
    tick(db, a)
    assert rn(db, a, rid)["state"] == "pending" and directive(db, a)["release"] == MID     # the stop first


def test_hold_and_pin_are_their_operations_own(db):
    a = node(db, "a")
    from helpers import settings_apply
    from oarbank.coordinator.settings import apply
    with pytest.raises(apply.ApplyError, match="updates.hold"):
        settings_apply(db, {"scope": "node", "scope_id": a["node_id"], "key": "update_hold", "value": {"reason": "x"}})
    with pytest.raises(core.ApiError, match="reason"):
        run_op(db, "updates.hold", "a", {"reason": ""}, reason="")
    with pytest.raises(core.ApiError, match="release version"):
        run_op(db, "updates.pin", "a", {"version": "latest", "reason": "x"})
    run_op(db, "updates.hold", "a", {"reason": "travel", "until": "2028-01-01T00:00:00Z"})
    hold = F.active_hold(db, fresh(db, a))
    assert hold["reason"] == "travel" and hold["until"] > T0


def test_a_machines_managed_policy_may_only_tighten_update_auto_and_hold_itself(db):
    a = node(db, "a")
    set_fleet(db, "update_auto", "on")
    core.heartbeat(db, fresh(db, a), {"attempts": [], "settings": {"applied_rev": 0, "managed": [
        {"key": "update_auto", "value": "off"}, {"key": "update_hold", "value": {"reason": "MDM freeze"}}],
        "managed_by": "Example Org"}})
    assert F._setting(db, fresh(db, a), "update_auto") == "off"
    assert F.active_hold(db, fresh(db, a))["reason"] == "MDM freeze"
    set_fleet(db, "update_auto", "off")
    core.heartbeat(db, fresh(db, a), {"attempts": [], "settings": {"applied_rev": 0, "managed": [
        {"key": "update_auto", "value": "on"}]}})
    assert F._setting(db, fresh(db, a), "update_auto") == "off"       # looser: ignored


# ------------------------------------------------------------------ the directive, the report, the artifact route

def test_unsupported_nodes_are_skipped_with_the_reason_and_keep_agent_self_update(db, tmp_path):
    a = node(db, "a")
    p = node(db, "p", install={"format": "dev", "scope": "personal", "updater": False, "why": "a personal install"})
    o = node(db, "o", install=None)
    sha = "c" * 64
    db.x("INSERT INTO agent_builds(sha256, version, path, size, uploaded_at, uploaded_by, platform, format) VALUES(?,?,?,?,?,?,?,?)",
         (sha, NEW, "/dev/null", 1, T0, "test", "darwin-arm64", "macho"))
    db.x("INSERT INTO agent_channel(platform, current, canary_nodes_json, updated_at) VALUES('darwin-arm64', ?, '[]', ?)", (sha, T0))
    imported(db, tmp_path)
    start(db)
    assert rn(db, p)["state"] == "skipped" and "personal install" in rn(db, p)["error"]
    assert rn(db, o)["state"] == "skipped" and "installation facts" in rn(db, o)["error"]
    b = beat(db, a)
    assert b["node_update"] and b["agent_update"] is None              # the package carries the agent: no half-update
    b = beat(db, p, install=None)
    assert b["node_update"] is None and b["agent_update"]["sha256"] == sha
    beat(db, a, rep("unsupported", error="no update runner trigger"))
    assert rn(db, a)["state"] == "skipped" and "trigger" in rn(db, a)["error"]


def test_the_artifact_route_serves_only_the_nodes_current_directive(db, tmp_path):
    der, a = enrolled_node(db, "a", facts_for("darwin-arm64"))
    der_b, b = enrolled_node(db, "b", facts_for("darwin-arm64"))
    for n in (a, b):
        hello(db, n, OLD)
    imported(db, tmp_path)
    c = agent_client(db)
    sha = next(x["sha256"] for x in F.release(db, NEW)["artifacts"] if x["present"])
    assert c.get(f"/v1/updates/artifacts/{sha}", headers=node_headers(der)).status_code == 404     # no directive yet
    run_op(db, "updates.pin", "a", {"version": NEW, "reason": "first"})
    d = directive(db, fresh(db, a))
    r = c.get(d["artifact"]["url"], headers=node_headers(der))
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == d["artifact"]["sha256"]
    assert c.get(d["artifact"]["url"], headers=node_headers(der_b)).status_code == 404               # not b's
    other = next(x["sha256"] for x in F.release(db, NEW)["artifacts"] if x["sha256"] != d["artifact"]["sha256"])
    assert c.get(f"/v1/updates/artifacts/{other}", headers=node_headers(der)).status_code == 404
    assert c.get(d["artifact"]["url"]).status_code in (401, 403)                                       # no certificate


def test_reports_are_kept_and_transitions_recorded(db):
    a = node(db, "a")
    beat(db, a, {"state": "bogus"})
    assert fresh(db, a)["node_update_json"] is None
    beat(db, a, rep("failed", error="disk: 2x the package needed"))
    assert json.loads(fresh(db, a)["node_update_json"])["error"].startswith("disk")
    assert db.one("SELECT 1 FROM events WHERE kind='node_update_failed'")
    assert json.loads(fresh(db, a)["install_json"])["format"] == "tar"


# ------------------------------------------------------------------ the tick

def test_a_rollout_takes_every_node_one_slot_at_a_time_and_bakes(db, tmp_path):
    a, b, c = (node(db, x) for x in ("a", "b", "c"))
    rel = imported(db, tmp_path)
    assert directive(db, a) is None
    res = start(db)
    assert res["ring"] == "broad"                                    # no update_ring anywhere: every node is broad
    d = directive(db, a)
    assert d["release"] == NEW and d["go"] is False and d["artifact"]["format"] == "tar" and d["rollback"] is False
    assert d["artifact"]["url"] == f"/v1/updates/artifacts/{d['artifact']['sha256']}" and d["drain_timeout_s"] == 1800
    assert hashlib.sha256(d["manifest"].encode()).hexdigest() == rel["manifest_sha256"]
    staged(db, a, b, c)
    tick(db)
    assert gone(db, a, b, c) == ["a"]                                # the first broad node acts as the canary: one
    tick(db)
    assert gone(db, a, b, c) == ["a"]
    ok(db)
    install_on(db, a)
    assert rn(db, a)["state"] == "done"
    tick(db)
    assert gone(db, a, b, c) == ["b"]                                # max(1, 25 % of 3) at a time from now on
    install_on(db, b)
    tick(db)
    install_on(db, c)
    ok(db)
    tick(db)
    assert RO.active(db)["state"] == "running"                       # not baked: no heartbeats on the new release yet
    heartbeats(db, a, b, c)
    tick(db)
    assert RO.active(db) is None and db.one("SELECT state FROM rollouts")["state"] == "done"
    assert all(directive(db, n) is None for n in (a, b, c))
    ok(db)


def rings(db):
    nodes = {"c1": node(db, "c1", ring="canary"), "e1": node(db, "e1", ring="early"), "e2": node(db, "e2", ring="early"),
             "b1": node(db, "b1", ring="broad"), "b2": node(db, "b2", ring="broad")}
    return {k: fresh(db, v) for k, v in nodes.items()}


def run_ring(db, members, everyone, version=NEW):
    staged(db, *members, version=version)
    for _ in members:
        tick(db, *everyone)
        for n in members:
            if (directive(db, n) or {}).get("go"):
                install_on(db, n, version)
    assert all(rn(db, n)["state"] == "done" for n in members)
    tick(db, *everyone)                                              # the ring finished: its bake starts now


def test_rings_run_in_order_and_each_bakes_by_time_and_heartbeats(db, tmp_path):
    n = rings(db)
    every = list(n.values())
    imported(db, tmp_path)
    start(db)
    assert RO.active(db)["ring"] == "canary"
    assert directive(db, n["e1"]) is None and directive(db, n["b1"]) is None      # later rings wait
    run_ring(db, [n["c1"]], every)
    heartbeats(db, n["c1"])
    tick(db, *every)
    assert RO.active(db)["ring"] == "canary"                         # 1800 s of bake first
    tick(db, *every, dt=1700)
    assert RO.active(db)["ring"] == "canary"
    tick(db, *every, dt=101)
    assert RO.active(db)["ring"] == "early"
    run_ring(db, [n["e1"], n["e2"]], every)                         # its last tick: 1 heartbeat each on the release
    clock.advance(7200)
    heartbeats(db, n["e1"], n["e2"], k=8)
    tick(db, n["c1"], n["b1"], n["b2"])
    assert RO.active(db)["ring"] == "early"                          # 9 heartbeats are not 10
    heartbeats(db, n["e1"], n["e2"], k=1)
    tick(db, n["c1"], n["b1"], n["b2"])
    assert RO.active(db)["ring"] == "broad"
    run_ring(db, [n["b1"], n["b2"]], every)
    heartbeats(db, n["b1"], n["b2"])
    tick(db, *every)
    assert db.one("SELECT state FROM rollouts")["state"] == "done"
    rings_ = RO.view_rollout(db, db.one("SELECT rollout_id FROM rollouts")["rollout_id"])["rings"]
    assert [r["ring"] for r in rings_ if r.get("baked_at")] == ["canary", "early", "broad"]
    ok(db)


def test_fast_policy_and_an_empty_ring_is_skipped(db, tmp_path):
    a = node(db, "a", ring="early")
    imported(db, tmp_path)
    start(db, fast=True)
    r = RO.active(db)
    assert r["ring"] == "early" and r["rings"]["canary"] == {"skipped": "empty"} and r["policy"]["rings"]["early"]["bake_s"] == 600
    run_ring(db, [a], [a])
    heartbeats(db, a)
    tick(db, a)                                                      # finished: the bake starts
    tick(db, a, dt=599)
    assert RO.active(db)
    tick(db, a, dt=1)
    assert RO.active(db) is None


def test_the_coordinator_goes_first_and_nodes_never_ahead_of_it(db, tmp_path, coordself, monkeypatch):
    a = node(db, "a")
    imported(db, tmp_path, NEXT)
    p = RO.plan(db, NEXT)
    assert p["coordinator"]["needed"] and p["coordinator"]["from"] == NEW and not p["refused"]
    start(db, NEXT)
    assert RO.active(db)["ring"] == "coordinator"
    tick(db, a)
    tick(db, a)
    assert coordself.calls == [NEXT]                                 # requested once
    assert directive(db, a) is None                                  # S30: nodes wait for the coordinator
    ok(db)
    monkeypatch.setattr(F, "coordinator_version", lambda: NEXT)      # restarted on the new version
    coordself.current = {"state": "done", "version": NEXT}
    tick(db, a)
    assert RO.active(db)["ring"] == "coordinator"                    # the coordinator's own bake: 600 s
    tick(db, a, dt=600)
    assert RO.active(db)["ring"] == "broad" and directive(db, a)["release"] == NEXT
    ok(db)


def test_a_coordinator_update_that_rolls_back_halts_the_rollout(db, tmp_path, coordself):
    a = node(db, "a")
    imported(db, tmp_path, NEXT)
    start(db, NEXT)
    tick(db, a)
    coordself.current = {"state": "rolled_back", "version": NEXT, "error": "probation: /v1/health never said 2.11.0"}
    tick(db, a)
    r = RO.active(db)
    assert r["state"] == "halted" and "rolled_back" in r["halted_reason"]
    alerts = {x["rule"] for x in db.q("SELECT rule FROM alerts WHERE state='open'")}
    assert {"coordinator_update_rolled_back", "rollout_halted"} <= alerts


def test_a_coordinator_update_refused_by_coordself_or_old_agents_halts(db, tmp_path, coordself):
    a = node(db, "a", version="2.8.0")
    imported(db, tmp_path, NEXT, agent_min=OLD)
    assert RO.plan(db, NEXT)["refused"]                              # the plan names the old agents
    run_op(db, "updates.hold", "a", {"reason": "old box"})
    assert not RO.plan(db, NEXT)["refused"]                          # held nodes do not block it
    start(db, NEXT)
    run_op(db, "updates.unhold", "a")
    tick(db, a)
    assert RO.active(db)["state"] == "halted" and "older than" in RO.active(db)["halted_reason"]
    assert coordself.calls == []
    run_op(db, "updates.hold", "a", {"reason": "old box"})
    coordself.refuse = "self-test failed: migration 41"
    run_op(db, "updates.resume", None)
    tick(db, a)
    assert RO.active(db)["state"] == "halted" and "migration 41" in RO.active(db)["halted_reason"]


def test_resume_asks_the_coordinator_again_after_a_refusal_whose_cause_was_fixed(db, tmp_path, coordself):
    """The root runner refused the coordinator's update (no update trust on the machine): the rollout halted. Once an
    administrator pinned the trust, a resume re-issues the coordinator step with a new request instead of reporting
    the old refusal again; a rolled-back update (it installed, and failed its probation) is not installed again."""
    a = node(db, "a")
    imported(db, tmp_path, NEXT)
    start(db, NEXT)
    tick(db, a)
    assert coordself.calls == [NEXT]
    coordself.current = {"update_id": "cu_1", "state": "refused", "version": NEXT,
                         "error": "no update trust on this machine: pin it with sudo ... trust --from-home"}
    tick(db, a)
    r = RO.active(db)
    assert r["state"] == "halted" and "no update trust" in r["halted_reason"]
    run_op(db, "updates.resume", None)
    r = RO.active(db)
    assert r["state"] == "running" and r["policy"]["coord_retry_of"] == "cu_1" and "coord_requested_at" not in r["policy"]
    assert db.one("SELECT reason FROM events WHERE kind='rollout_coordinator_retry'")["reason"].endswith("asking again")
    tick(db, a)                                                      # the old refusal does not halt it again
    tick(db, a)
    assert RO.active(db)["state"] == "running" and coordself.calls == [NEXT, NEXT]   # a new request
    assert directive(db, a) is None                                  # nodes still wait for the coordinator
    coordself.current = {**coordself.current, "update_id": "cu_2"}
    tick(db, a)
    assert RO.active(db)["state"] == "running"
    # the new request failing (no runner took it) halts it again, and a resume asks once more
    coordself.current = {"update_id": "cu_2", "state": "failed", "version": NEXT, "error": "no update runner took the request"}
    tick(db, a)
    assert RO.active(db)["state"] == "halted"
    run_op(db, "updates.resume", None)
    tick(db, a)
    tick(db, a)
    assert coordself.calls == [NEXT, NEXT, NEXT] and RO.active(db)["policy"]["coord_retry_of"] == "cu_2"
    # a rolled-back coordinator update: resume does not reinstall it, the rollout halts again on it
    coordself.current = {"update_id": "cu_3", "state": "rolled_back", "version": NEXT, "error": "probation"}
    tick(db, a)
    assert RO.active(db)["state"] == "halted"
    run_op(db, "updates.resume", None)
    tick(db, a)
    assert RO.active(db)["state"] == "halted" and coordself.calls == [NEXT, NEXT, NEXT]


def test_a_rollout_halted_at_the_coordinator_is_superseded_by_a_new_start(db, tmp_path, coordself):
    """`oarbank update coordinator <version>` (or start) after the coordinator's update was refused: the halted rollout
    installed nothing anywhere, so the new start supersedes it rather than demand a rollback (which would have every
    node reinstall what it runs). A halted rollout whose nodes were told to install still blocks a start."""
    a = node(db, "a")
    imported(db, tmp_path, NEXT)
    start(db, NEXT)
    first = RO.active(db)["rollout_id"]
    tick(db, a)
    coordself.current = {"update_id": "cu_1", "state": "refused", "version": NEXT, "error": "no update trust"}
    tick(db, a)
    assert RO.active(db)["state"] == "halted"
    assert RO.stopped_at_the_coordinator(db, RO.row(db, first))
    start(db, NEXT, rings=["coordinator"])
    second = RO.active(db)
    assert second["rollout_id"] != first and second["state"] == "running" and second["ring"] == "coordinator"
    assert RO.row(db, first)["state"] == "superseded"
    tick(db, a)
    tick(db, a)
    assert coordself.calls == [NEXT, NEXT]
    ok(db)
    # a rollout halted once a node ring started (a node was told to install) still asks for resume or rollback
    coordself.current = {"update_id": "cu_2", "state": "refused", "version": NEXT, "error": "no update trust"}
    tick(db, a)
    db.x("UPDATE rollout_nodes SET go=1 WHERE rollout_id=?", (second["rollout_id"],))
    assert not RO.stopped_at_the_coordinator(db, RO.row(db, second["rollout_id"]))
    with pytest.raises(core.ApiError, match="resume, roll back or let it finish first"):
        start(db, NEXT)


def test_the_fleet_health_gate(db, tmp_path):
    n = rings(db)
    imported(db, tmp_path)
    for k in ("b1", "b2"):
        db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (T0 - 3600, n[k]["node_id"]))
    with pytest.raises(core.ApiError, match="unhealthy"):
        start(db)
    every = list(n.values())
    for x in every:
        beat(db, x)
    start(db)
    run_ring(db, [n["c1"]], every)
    heartbeats(db, n["c1"])
    clock.advance(1800)
    for x in (n["c1"], n["e1"], n["e2"]):
        beat(db, x)                                                  # b1, b2 silent for 30 min: 2 of 5 unhealthy
    RO.tick(db)
    r = RO.active(db)
    assert r["state"] == "halted" and "fleet unhealthy at the start of ring early" in r["halted_reason"]
    assert directive(db, n["e1"]) is None
    run_op(db, "updates.resume", None)
    tick(db, *every)
    assert RO.active(db)["ring"] == "early"


def test_eligibility_window_hold_protected_phase_and_seats(db, tmp_path):
    a, b = node(db, "a"), node(db, "b")
    set_node(db, a, "update_window", {"start": "02:00", "end": "03:00"})       # T0 is 08:00 UTC
    imported(db, tmp_path)
    start(db, max_unavailable=2)
    staged(db, a, b)
    phase = {"protection": {"phases": [{"key": "render", "on": True, "rule": "r"}]}}
    beat(db, b, telemetry=phase)
    RO.tick(db)
    assert rn(db, a)["error"] == "waiting: outside its update window"
    assert "protected phase" in rn(db, b)["error"] and not rn(db, b)["go"]
    assert gone(db, a, b) == []
    db.x("INSERT INTO workload_seats(seat_id, module, workload, node_id, fence, lease_until, granted_at) VALUES('s1','m','w',?,1,?,?)",
         (b["node_id"], T0 + 100, T0))
    RO.tick(db)
    assert "seat" in rn(db, b)["error"] and gone(db, b) == []
    db.x("UPDATE workload_seats SET lease_until=? WHERE seat_id='s1'", (T0 + 1800,))   # just renewed: adopted after restart
    RO.tick(db)
    assert gone(db, b) == ["b"]
    tick(db, a, b, dt=18 * 3600 + 30 * 60)                           # Saturday 02:30
    assert gone(db, a) == ["a"]
    facts = json.loads(rn(db, a)["go_facts_json"])[-1]
    assert facts["online"] and facts["in_window"] and not facts["held"] and not facts["pinned"]
    ok(db)


def test_a_drain_that_times_out_is_deferred_and_retried_later(db, tmp_path):
    a, b = node(db, "a"), node(db, "b")
    imported(db, tmp_path)
    start(db)
    staged(db, a, b)
    RO.tick(db)
    assert gone(db, a, b) == ["a"]
    beat(db, a, rep("draining"))
    beat(db, a, rep("deferred", error="drain_timeout"))
    assert rn(db, a)["state"] == "staged" and not rn(db, a)["go"] and "retried later" in rn(db, a)["error"]
    RO.tick(db)
    assert gone(db, a, b) == ["b"]                                   # the slot goes to another node
    install_on(db, b)
    tick(db, a, b)
    assert gone(db, a, b) == []
    tick(db, a, b, dt=RO.RETRY_DEFERRED_S)
    assert gone(db, a, b) == ["a"]


def test_failures_above_the_budget_halt_and_roll_back_the_nodes_it_moved(db, tmp_path):
    n = rings(db)
    every = list(n.values())
    imported(db, tmp_path, OLD)
    imported(db, tmp_path)
    start(db, rings=["canary", "broad"])
    assert rn(db, n["e1"])["state"] == "skipped"
    run_ring(db, [n["c1"]], every)
    heartbeats(db, n["c1"])
    tick(db, *every, dt=1800)
    assert RO.active(db)["ring"] == "broad"
    staged(db, n["b1"], n["b2"])
    tick(db, *every)
    assert gone(db, n["b1"], n["b2"]) == ["b1"]
    install_on(db, n["b1"], ok=False)                               # 1 failure: within the broad budget
    tick(db, *every)
    assert RO.active(db)["state"] == "running" and gone(db, n["b2"]) == ["b2"]
    install_on(db, n["b2"], ok=False)
    tick(db, *every)
    r = RO.active(db)
    assert r["state"] == "rolling_back" and "budget" in r["halted_reason"]
    assert {x["rule"] for x in db.q("SELECT rule FROM alerts WHERE state='open'")} >= {"rollout_halted", "rollout_rolled_back"}
    d = directive(db, n["c1"])
    assert d["release"] == OLD and d["rollback"] is True
    assert directive(db, n["b1"]) is None and directive(db, n["e1"]) is None
    beat(db, n["c1"], rep("staged", OLD))
    tick(db, *every)
    assert directive(db, n["c1"])["go"]
    install_on(db, n["c1"], OLD)
    tick(db, *every)
    assert db.one("SELECT state FROM rollouts WHERE rollout_id=?", (r["rollout_id"],))["state"] == "rolled_back"
    assert fresh(db, n["c1"])["agent_version"] == OLD
    ok(db)


def test_the_canary_has_no_failure_budget_and_halt_starts_nothing_new(db, tmp_path):
    n = rings(db)
    imported(db, tmp_path)
    start(db, auto_rollback=False)
    staged(db, n["c1"])
    tick(db, *n.values())
    install_on(db, n["c1"], ok=False)
    tick(db, *n.values())
    r = RO.active(db)
    assert r["state"] == "halted" and "budget 0" in r["halted_reason"]
    assert directive(db, n["c1"]) is None
    run_op(db, "updates.resume", None)
    assert RO.active(db)["state"] == "running"


def test_offline_nodes_wait_the_ring_finishes_without_them_and_they_catch_up(db, tmp_path):
    a, b, c, d = (node(db, x) for x in "abcd")
    imported(db, tmp_path)
    start(db, max_unavailable=3)
    staged(db, a, b, c)
    clock.advance(200)
    for x in (a, b, c):
        beat(db, x)
    RO.tick(db)                                                      # d silent: waiting(offline)
    assert rn(db, d)["state"] == "waiting" and rn(db, d)["error"] == "offline"
    for x in (a, b, c):
        install_on(db, x)
    heartbeats(db, a, b, c)
    RO.tick(db)
    rid = db.one("SELECT rollout_id FROM rollouts")["rollout_id"]
    assert db.one("SELECT state FROM rollouts")["state"] == "done"
    beat(db, d)
    RO.tick(db)
    assert directive(db, d)["release"] == NEW                        # the done rollout's catch-up
    beat(db, d, rep("staged"))
    RO.tick(db)
    assert gone(db, d) == ["d"]
    install_on(db, d)
    assert rn(db, d, rid)["state"] == "done"
    ok(db)


def test_a_canary_ring_whose_nodes_are_all_offline_holds_the_rollout_until_one_updates_or_is_skipped(db, tmp_path):
    """Inconclusive is a pause (D59; TLA+ OarbankRollout's former witness BroadWithoutCanary): a ring widens the
    rollout only once one of its nodes updated, or the owner skipped them all."""
    n = rings(db)
    imported(db, tmp_path)
    start(db)
    others = [v for k, v in n.items() if k != "c1"]
    clock.advance(200)
    tick(db, *others)                                                # c1 silent: waiting(offline)
    tick(db, *others, dt=3600)
    r = RO.active(db)
    assert r["ring"] == "canary" and rn(db, n["c1"])["error"] == "offline"
    assert "no node of the canary ring has updated yet (c1 offline" in r["rings"]["canary"]["waiting_for"]
    assert all(directive(db, x) is None for x in others)              # nothing wider moves meanwhile
    run_op(db, "updates.skip", "c1")                                 # the owner's explicit call
    tick(db, *others)
    assert RO.active(db)["ring"] == "early" and "waiting_for" not in RO.active(db)["rings"]["canary"]
    ok(db)


def test_new_nodes_join_and_retired_ones_leave(db, tmp_path):
    a = node(db, "a")
    imported(db, tmp_path)
    start(db)
    late = node(db, "late")
    RO.tick(db)
    rid = RO.active(db)["rollout_id"]
    assert rn(db, late, rid)["state"] == "pending" and directive(db, late)["release"] == NEW
    db.x("UPDATE nodes SET lifecycle='retired' WHERE node_id=?", (a["node_id"],))
    RO.tick(db)
    assert rn(db, a, rid)["state"] == "skipped" and rn(db, a, rid)["error"] == "retired"


def test_a_node_stuck_over_45_minutes_raises_an_alert(db, tmp_path):
    a = node(db, "a")
    imported(db, tmp_path)
    start(db)
    staged(db, a)
    RO.tick(db)
    beat(db, a, rep("installing"))
    tick(db, a, dt=46 * 60)
    assert db.one("SELECT detail FROM alerts WHERE rule='update_node_stuck' AND state='open'")["detail"].startswith("a has been installing")
    hello(db, a, NEW, report=rep("done"))
    RO.tick(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule='update_node_stuck' AND state='open'")


def test_unhealthy_during_the_bake_counts_as_a_failure(db, tmp_path):
    n = rings(db)
    imported(db, tmp_path)
    start(db, auto_rollback=False)
    run_ring(db, [n["c1"]], list(n.values()))
    clock.advance(400)
    for k in ("e1", "e2", "b1", "b2"):
        beat(db, n[k])                                              # c1 silent through the bake
    RO.tick(db)
    assert rn(db, n["c1"])["state"] == "failed" and "bake" in rn(db, n["c1"])["error"]
    assert RO.active(db)["state"] == "halted"


def test_operator_actions(db, tmp_path):
    a, b = node(db, "a"), node(db, "b")
    imported(db, tmp_path, OLD)
    imported(db, tmp_path)
    imp = preview(db, "updates.start", NEW)["impact"]
    assert imp["rings"] == ["broad: a, b; 1 at a time, bake 0 min, failure budget 1"] and imp["coordinator"] == f"runs {NEW}"
    assert [r["ring"] for r in imp["_plan"]["rings"]] == ["canary", "early", "broad"]
    with pytest.raises(ops.OpError, match="preview"):
        ops.execute(db, ops.OpRequest(op="updates.start", actor="t", target=NEW, reason="x"))
    start(db)
    rid = RO.active(db)["rollout_id"]
    run_op(db, "updates.pause", None)
    staged(db, a, b)
    RO.tick(db)
    assert gone(db, a, b) == []                                      # paused: no new go
    run_op(db, "updates.resume", rid)
    RO.tick(db)
    assert gone(db, a, b) == ["a"]
    run_op(db, "updates.skip", "b")
    assert rn(db, b)["state"] == "skipped" and directive(db, b) is None
    install_on(db, a)
    with pytest.raises(core.ApiError, match="nothing to skip"):
        run_op(db, "updates.skip", "a")
    run_op(db, "updates.halt", None, reason="wrong release")
    assert RO.active(db)["halted_reason"] == "wrong release"
    imp = preview(db, "updates.rollback")["impact"]
    assert imp["nodes"] == [{"hostname": "a", "back_to": OLD, "state": "done"}]
    run_op(db, "updates.rollback", None)
    assert db.one("SELECT state FROM rollouts WHERE rollout_id=?", (rid,))["state"] == "rolling_back"
    assert directive(db, a)["rollback"] is True
    assert [h["kind"] for h in F.view(db)["history"]] == ["rollback", "update"]
    with pytest.raises(core.ApiError, match="no rollout"):
        run_op(db, "updates.pause", "ro_nope")


def test_a_fleet_release_supersedes_the_agent_channel_and_nothing_downgrades_the_node_after(db, tmp_path):
    """The live 2.10.3 -> 2.10.4 update: the owner had pushed the old agent through the agent-only channel. Starting the
    rollout retires that build, and once a node installed the release its heartbeats carry no agent_update (it used to
    get the old channel build back: "-> 2.10.3 (channel build): draining")."""
    from oarbank.coordinator import agentbuilds
    from test_agent_selfupdate import agent_bytes
    a = node(db, "a")
    staged_sha = agentbuilds.stage(agent_bytes(OLD))["sha256"]
    old = run_op(db, "agent.upload", None, {"sha256": staged_sha})["result"]["sha256"]
    run_op(db, "agent.canary", old, {"nodes": ["a"]})
    core.heartbeat(db, fresh(db, a), {"attempts": [], "agent_build": old})
    run_op(db, "agent.promote", "agent", {"platform": "darwin-arm64"})
    assert agentbuilds.channel(db, "darwin-arm64")["current"] == old
    imported(db, tmp_path)
    start(db)
    assert agentbuilds.channel(db, "darwin-arm64")["current"] is None
    assert db.q("SELECT kind FROM events WHERE kind='agent_build_retired'")
    staged(db, a)
    tick(db)
    install_on(db, a)
    reply = core.heartbeat(db, fresh(db, a), {"attempts": [], "agent_build": "e" * 64, "install": INSTALL})
    assert reply["node_update"] is None and reply["agent_update"] is None
    # even a channel that still held the old build (a coordinator from before this rule) assigns it to no updated node
    db.x("UPDATE agent_channel SET current=? WHERE platform='darwin-arm64'", (old,))
    assert core.heartbeat(db, fresh(db, a), {"attempts": [], "agent_build": "e" * 64})["agent_update"] is None
    with pytest.raises(core.ApiError, match=f"older than fleet release {NEW}"):
        run_op(db, "agent.canary", old, {"nodes": ["a"]})


def test_a_node_that_falls_back_below_a_done_rollout_takes_the_release_again(db, tmp_path):
    """A node the rollout updated that later runs an older agent (the old channel build took it down before this fix,
    or someone installed an older package) is not left staged without `go` forever: the done rollout's catch-up takes
    it to the release again."""
    a = node(db, "a")
    imported(db, tmp_path)
    start(db)
    staged(db, a)
    tick(db)
    install_on(db, a)
    heartbeats(db, a)
    tick(db)
    rid = db.one("SELECT rollout_id FROM rollouts")["rollout_id"]
    assert db.one("SELECT state FROM rollouts")["state"] == "done" and rn(db, a, rid)["state"] == "done"
    hello(db, a, OLD)                                                # fell back
    tick(db, a)
    m = rn(db, a, rid)
    assert m["state"] == "pending" and "fell back to agent" in m["error"]
    assert db.q("SELECT 1 FROM events WHERE kind='rollout_node_fell_back'")
    staged(db, a)
    tick(db, a)
    assert directive(db, a)["go"] is True
    install_on(db, a)
    assert rn(db, a, rid)["state"] == "done"
    ok(db)


def test_a_newer_release_supersedes_a_rollout(db, tmp_path):
    a = node(db, "a")
    imported(db, tmp_path, MID)
    imported(db, tmp_path, NEW)
    start(db, MID)
    first = RO.active(db)["rollout_id"]
    start(db, NEW)
    assert db.one("SELECT state FROM rollouts WHERE rollout_id=?", (first,))["state"] == "superseded"
    assert directive(db, a)["release"] == NEW
    with pytest.raises(core.ApiError, match="running"):
        start(db, MID)                                               # an older release does not replace a running one


# ------------------------------------------------------------------ the update policy (D60)

def test_notify_raises_a_notice_off_does_nothing_on_starts_it(db, tmp_path):
    a = node(db, "a")
    imported(db, tmp_path)
    RO.tick(db)
    al = db.one("SELECT * FROM alerts WHERE rule='update_available' AND state='open'")
    assert al["subject"] == f"release:{NEW}" and "oarbank update start" in al["detail"]
    assert not db.q("SELECT * FROM rollouts")
    set_fleet(db, "update_auto", "off")
    db.x("DELETE FROM alerts")
    RO.tick(db)
    assert not db.q("SELECT * FROM alerts") and not db.q("SELECT * FROM rollouts")
    set_fleet(db, "update_auto", "on")
    RO.tick(db)
    r = db.one("SELECT * FROM rollouts")
    assert r and r["auto"] == 1 and r["created_by"] == "system" and r["version"] == NEW
    RO.tick(db)
    assert len(db.q("SELECT * FROM rollouts")) == 1
    assert directive(db, a)["release"] == NEW


def test_an_automatic_rollout_skips_nodes_whose_own_policy_is_not_on(db, tmp_path):
    a, b = node(db, "a"), node(db, "b")
    set_fleet(db, "update_auto", "on")
    set_node(db, b, "update_auto", "notify")
    imported(db, tmp_path)
    RO.tick(db)
    assert rn(db, a)["state"] == "pending" and rn(db, b)["state"] == "skipped" and "notify" in rn(db, b)["error"]


def test_the_periodic_check_fetches_a_newer_release(db, monkeypatch):
    node(db, "a")
    set_fleet(db, "update_check_h", 1)
    fetched = []
    monkeypatch.setattr(F, "latest", lambda db: NEXT)                       # a release newer than this coordinator
    monkeypatch.setattr(F, "fetch", lambda db, v, actor: fetched.append((v, actor)))
    monkeypatch.setattr(RO, "_spawn", lambda fn: fn())
    RO.tick(db)
    assert fetched == []                                             # the first check is one period after the start
    clock.advance(3599)
    RO.tick(db)
    assert fetched == []
    clock.advance(1)
    RO.tick(db)
    assert fetched == [(NEXT, "system")]
    set_fleet(db, "update_check_h", 0)
    clock.advance(7200)
    RO.tick(db)
    assert len(fetched) == 1


# ------------------------------------------------------------------ agent_min (D61) and the invariants

def test_an_agent_older_than_agent_min_gets_no_work(db, tmp_path):
    a = node(db, "a", version="2.8.0")
    imported(db, tmp_path, NEW, agent_min=OLD)
    nv = core.node_view_for_claim(db, fresh(db, a), set(), set(), 8, 32, {})
    fail = [r for r in predicates.admission(nv) if r.code == "AGENT_TOO_OLD"][0]
    assert fail.outcome == "fail" and fail.observed == "2.8.0" and fail.required == OLD
    hello(db, a, OLD)
    nv = core.node_view_for_claim(db, fresh(db, a), set(), set(), 8, 32, {})
    assert [r for r in predicates.admission(nv) if r.code == "AGENT_TOO_OLD"][0].outcome == "pass"


def test_the_invariants_catch_what_the_tick_never_does(db, tmp_path):
    a, b = node(db, "a", ring="early"), node(db, "b", ring="early")
    imported(db, tmp_path)
    start(db)
    rid = RO.active(db)["rollout_id"]
    assert invariants.s29_rollout_cap(db) == [] and invariants.s31_go_only_when_eligible(db) == []
    db.x("UPDATE rollout_nodes SET state='installing' WHERE rollout_id=?", (rid,))
    assert invariants.s29_rollout_cap(db)
    db.x("UPDATE rollout_nodes SET state='staged', go_facts_json=? WHERE rollout_id=? AND node_id=?",
         (json.dumps([{"at": T0, "online": True, "in_window": False, "held": False, "pinned": False}]), rid, a["node_id"]))
    assert invariants.s31_go_only_when_eligible(db)
    db.x("UPDATE rollout_nodes SET ring='broad' WHERE rollout_id=? AND node_id=?", (rid, a["node_id"]))
    db.x("UPDATE rollouts SET rings_json=? WHERE rollout_id=?", (json.dumps({"early": {"started_at": T0}}), rid))
    assert any("before ring early" in v for v in invariants.s30_no_node_ahead_of_coordinator(db))
    names = [c["name"] for c in invariants.conditions(db, T0)]
    assert {"s29_rollout_cap", "s30_no_node_ahead_of_coordinator", "s31_go_only_when_eligible"} <= set(names)


def test_window_rule_matches_the_agents_schedule():
    day = 86400
    monday = 4 * day                                                  # 1970-01-05 was a Monday
    w = {"start": "22:00", "end": "06:00", "days": [0]}
    assert RO.window_contains(w, monday + 23 * 3600, 0)              # Monday 23:00
    assert RO.window_contains(w, monday + day + 3600, 0)             # Tuesday 01:00 belongs to Monday's window
    assert not RO.window_contains(w, monday + day + 23 * 3600, 0)    # Tuesday 23:00
    assert RO.window_contains({"start": "00:00", "end": "24:00"}, monday + 5, 0)
    assert RO.window_contains({"start": "09:00", "end": "17:00"}, monday + 8 * 3600, 3600)     # 09:00 at UTC+1
    assert RO.window_contains(None, 0, 0)


# ------------------------------------------------------------------ the console's Updates page and `oarbank update`

@pytest.fixture
def served(tmp_path, monkeypatch):
    """A real admin API (the console's and the CLI's) on a loopback port, the wall clock, and two nodes."""
    from oarbank.cli import main as cli
    from oarbank.coordinator import access, app as coord_app
    from test_console import SECRET, Server
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    nodes = {"a": node(d, "a"), "b": node(d, "b", ring="canary")}
    with Server(coord_app.admin_app(d, console_secret=SECRET)) as oarbankd:
        monkeypatch.setenv("OARBANK_TOKEN", access.ensure_admin_token(d.root))
        monkeypatch.setenv("OARBANK_REASON", "fleet update test")
        monkeypatch.setattr(cli, "URL", f"http://127.0.0.1:{oarbankd.port}")
        yield {"db": d, "nodes": nodes, "oarbankd": oarbankd}
    d.conn.close()


def test_the_updates_page_shows_the_fleet_and_posts_its_forms(served, tmp_path):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from test_console import SECRET
    from helpers import sign_in
    db = served["db"]
    with TestClient(console_app(ConsoleState(str(db.path), f"http://127.0.0.1:{served['oarbankd'].port}", secret=SECRET),
                                tmp_path / "logs"), client=("127.0.0.1", 50021)) as c:
        sign_in(c, db)
        html = c.get("/updates").text
        assert "<title>Updates · Oarbank</title>" in html and f"Coordinator {NEW}" in html and "No fleet release imported yet" in html
        assert '<a href="/updates">Updates</a>' in html
        d = write_release(tmp_path / "upload")
        files = [("files", (p.name, p.read_bytes(), "application/octet-stream")) for p in sorted(d.iterdir())]
        r = c.post("/do/updates.import", data={"target": "", "return_to": "/updates", "idem": "x"}, files=files)
        assert r.status_code == 200 and F.release(db, NEW)["state"] == "ready", r.text[-2000:]
        html = c.get("/updates").text
        assert f"newest ready release {NEW}" in html and 'action="/do/updates.start"' in html and "Update fleet…" in html
        assert 'action="/do/updates.hold"' in html and 'action="/do/updates.pin"' in html
        r = c.post("/do/updates.start", data={"target": NEW, "return_to": "/updates", "idem": "y"})
        assert "Review" in r.text and "canary: b" in r.text and "broad: a" in r.text
        start(db)
        run_op(db, "updates.hold", "a", {"reason": "demo day", "until": "2099-01-01T00:00:00Z"})
        html = c.get("/updates").text
        for want in ("Active rollout", "ring canary", 'action="/do/updates.pause"', 'action="/do/updates.halt"',
                     'action="/do/updates.rollback"', 'action="/do/updates.unhold"', "demo day", "held"):
            assert want in html, want
        c.post("/do/updates.pause", data={"target": RO.active(db)["rollout_id"], "return_to": "/updates", "idem": "z"})
        assert RO.active(db)["state"] == "paused"
        assert 'action="/do/updates.resume"' in c.get("/updates").text


def test_oarbank_update_commands(served, tmp_path, capsys):
    from test_console_parity import oarbank
    db = served["db"]
    code, out = oarbank(capsys, "update", "status")
    assert code == 0 and "no fleet release imported" in out
    code, out = oarbank(capsys, "update", "import", write_release(tmp_path / "rel"))
    assert code == 0 and F.release(db, NEW)["state"] == "ready", out
    code, out = oarbank(capsys, "update", "releases")
    assert code == 0 and NEW in out and "ready" in out
    code, out = oarbank(capsys, "update", "plan", NEW)
    assert code == 2 and "canary: b" in out and "broad: a" in out
    code, out = oarbank(capsys, "update", "start", NEW, "--fast", "--yes")
    assert code == 0 and RO.active(db)["policy"]["fast"], out
    code, out = oarbank(capsys, "update", "hold", "a", "--reason", "travel", "--until", "2099-01-01T00:00:00Z")
    assert code == 0 and F.active_hold(db, fresh(db, served["nodes"]["a"]))["reason"] == "travel"
    code, out = oarbank(capsys, "update", "status")
    assert code == 0 and "held: travel" in out and "(ring canary)" in out, out
    assert oarbank(capsys, "update", "pause")[0] == 0 and RO.active(db)["state"] == "paused"
    assert oarbank(capsys, "update", "resume")[0] == 0 and RO.active(db)["state"] == "running"
    assert oarbank(capsys, "update", "pin", "a", OLD, "--reason", "known good")[0] == 0
    assert oarbank(capsys, "update", "unpin", "a")[0] == 0 and oarbank(capsys, "update", "unhold", "a")[0] == 0
    assert oarbank(capsys, "update", "halt")[0] == 0 and RO.active(db)["state"] == "halted"
    code, out = oarbank(capsys, "update", "coordinator")
    assert code == 0 and f"coordinator {NEW}" in out
    assert oarbank(capsys, "update", "hold", "a")[0] == 1                   # a hold needs a reason


def test_oarbank_update_sign_signs_the_manifest_with_the_owner_key(served, tmp_path, capsys, monkeypatch):
    from test_console_parity import oarbank
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    db = served["db"]
    key = tmp_path / "keys" / "owner.key"
    db.set_state("release_pubkey", signing.keygen(key))
    monkeypatch.setattr(signing, "DEFAULT_KEY", key)
    F.import_dir(db, write_release(tmp_path / "rel"), "test")
    assert F.release(db, NEW)["state"] == "incomplete"
    code, out = oarbank(capsys, "update", "sign", NEW)
    assert code == 0 and F.release(db, NEW)["state"] == "ready", out


def test_a_node_without_update_trust_shows_the_command_that_pins_it(db, tmp_path):
    """2.10.0-2.10.4 agents say `sudo oarbank-launcher update-trust`, which only prints its usage (and on macOS is not on
    PATH): the plan shows the command that pins, per package format; a newer agent's own hint is kept."""
    imported(db, tmp_path)
    old = "no update trust is pinned: sudo oarbank-launcher update-trust"
    cases = [("mac", "darwin-arm64", "pkg", old, "sudo /Library/Oarbank/bin/oarbank-launcher update-trust --from-agent"),
             ("deb", "linux-amd64", "deb", old, "sudo oarbank-launcher update-trust --from-agent"),
             ("win", "windows-amd64", "msi", old, "oarbank-node update-trust --from-agent (in an elevated prompt)"),
             ("new", "darwin-arm64", "pkg", "no update trust is pinned: sudo /x/oarbank-launcher update-trust --from-agent",
              "sudo /x/oarbank-launcher update-trust --from-agent")]
    for name, plat, fmt, why, want in cases:
        n = node(db, name, platform=plat, install={"format": fmt, "scope": "system", "updater": False, "why": why})
        _, reason = F.artifact_for(db, NEW, fresh(db, n))
        assert reason == f"no update runner on it: no update trust is pinned: {want}", reason
        assert F.install_of(fresh(db, n))["why"] == f"no update trust is pinned: {want}"
    # anything else is shown as the agent says it
    n = node(db, "personal", install={"format": "pkg", "scope": "personal", "updater": False, "why": "a personal install"})
    assert F.install_of(fresh(db, n))["why"] == "a personal install"
