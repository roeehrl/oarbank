"""Agent self-update through oarbankd (no ssh): the build store (platforms read from executable headers, never run),
one channel per platform, the directive in hello and heartbeat replies, canary → promote gated on the canary nodes
running the build, rollback, signing mode, and what the agents report back."""
import hashlib
import struct
from pathlib import Path

import pytest

from oarbank.coordinator import agentbuilds, config as C, core, ops

from helpers import enrolled_node, facts_for, fresh, make_db

MACHO = {"arm64": 0x0100000C, "amd64": 0x01000007}
ELF = {"arm64": 0xB7, "amd64": 0x3E}
PE = {"arm64": 0xAA64, "amd64": 0x8664}


def agent_bytes(version: str, platform: str = "darwin-arm64") -> bytes:
    """An executable header for the platform plus the version marker every agent build embeds."""
    os_, arch = platform.split("-")
    if os_ == "darwin":
        head = b"\xcf\xfa\xed\xfe" + struct.pack("<III", MACHO[arch], 0, 2) + bytes(16)
    elif os_ == "linux":
        head = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack("<HH", 3, ELF[arch]) + bytes(44)
    else:
        head = b"MZ" + bytes(0x3A) + struct.pack("<I", 64) + b"PE\x00\x00" + struct.pack("<HHIIIHH", PE[arch], 0, 0, 0, 0, 0, 0x0022)
    return head + bytes(64) + f"oarbank-agent-version:{version}\x00".encode() + bytes(32)


def agent_bin(version: str, platform: str = "darwin-arm64") -> Path:
    import tempfile
    p = Path(tempfile.mkdtemp()) / "oarbank-agent"
    p.write_bytes(agent_bytes(version, platform))
    return p


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def op(db, name, target=None, **kw):
    return ops.execute(db, ops.OpRequest(op=name, actor="test", target=target, **kw))


def planned(db, name, target, params=None):
    plan = op(db, name, target, params=params or {}, dry_run=True)["plan"]
    return plan, op(db, name, plan_id=plan["plan_id"], reason="test", idempotency_key=plan["plan_id"])


def upload(db, version: str, platform: str = "darwin-arm64") -> str:
    """What `oarbank agent upload` does: stage the bytes, then the reviewed T2 operation."""
    out = agentbuilds.stage(agent_bytes(version, platform))
    plan, res = planned(db, "agent.upload", None, {"sha256": out["sha256"]})
    assert plan["impact"]["version"] == version
    return res["result"]["sha256"]


def report(db, node, build, state=None, error=None):
    """A heartbeat in which the agent reports the build it runs and its update state."""
    core.heartbeat(db, fresh(db, node), {"attempts": [], "agent_build": build, "agent_version": "x",
                                         "agent_update": {"state": state or "idle", "error": error}})
    return core.heartbeat(db, fresh(db, node), {"attempts": [], "agent_build": build})


def test_upload_registers_without_deploying_and_refuses_what_is_not_an_agent(db):
    _, n = enrolled_node(db, "mini")
    sha = upload(db, "0.4.0")
    r = agentbuilds.record(db, sha)
    assert r["version"] == "0.4.0" and hashlib.sha256(Path(r["path"]).read_bytes()).hexdigest() == sha
    assert r["platforms"] == ["darwin-arm64"] and r["format"] == "macho"
    assert agentbuilds.channel(db, "darwin-arm64")["current"] is None
    assert core.heartbeat(db, fresh(db, n), {"attempts": []})["agent_update"] is None        # nothing enabled
    script = agentbuilds.stage(b"#!/bin/sh\necho oarbank-agent-version:9.0.0\x00\n")
    with pytest.raises(core.ApiError, match="not a 64-bit"):
        planned(db, "agent.upload", None, {"sha256": script["sha256"]})
    liar = agentbuilds.stage(agent_bytes("0.1.0").replace(b"oarbank-agent-version:", b"other-tool-version:!!"))
    plan = op(db, "agent.upload", None, params={"sha256": liar["sha256"]}, dry_run=True)["plan"]
    assert "refused" in plan["impact"]
    two = agentbuilds.stage(agent_bytes("0.1.0") + b"oarbank-agent-version:0.2.0\x00")
    assert "refused" in op(db, "agent.upload", None, params={"sha256": two["sha256"]}, dry_run=True)["plan"]["impact"]


@pytest.mark.parametrize("platform,fmt", [("darwin-arm64", "macho"), ("darwin-amd64", "macho"), ("linux-arm64", "elf"),
                                          ("linux-amd64", "elf"), ("windows-arm64", "pe"), ("windows-amd64", "pe")])
def test_platform_is_read_from_the_headers(platform, fmt):
    info = agentbuilds.inspect(agent_bin("1.2.3-rc.1", platform))
    assert (info["platforms"], info["format"], info["version"]) == ([platform], fmt, "1.2.3-rc.1")


def test_universal_binaries_cover_both_darwin_arches(tmp_path):
    fat = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", MACHO["arm64"], 0, 0, 0, 0) + \
        struct.pack(">IIIII", MACHO["amd64"], 0, 0, 0, 0) + b"oarbank-agent-version:1.0.0\x00"
    (tmp_path / "a").write_bytes(fat)
    assert agentbuilds.inspect(tmp_path / "a")["platforms"] == ["darwin-amd64", "darwin-arm64"]


def test_channels_are_per_platform_and_canaries_must_match(db):
    _, mac = enrolled_node(db, "mini")
    _, box = enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))
    m, lx = upload(db, "1.0.0"), upload(db, "1.0.0", "linux-amd64")
    with pytest.raises(core.ApiError, match="is linux-amd64"):
        planned(db, "agent.canary", m, {"nodes": ["box"]})
    planned(db, "agent.canary", lx, {"nodes": ["box"]})
    assert core.heartbeat(db, fresh(db, box), {"attempts": []})["agent_update"]["sha256"] == lx
    assert core.heartbeat(db, fresh(db, mac), {"attempts": []})["agent_update"] is None   # the Mac's channel is empty
    report(db, box, lx)
    planned(db, "agent.promote", "agent", {"platform": "linux-amd64"})
    assert agentbuilds.channel(db, "linux-amd64")["current"] == lx
    assert agentbuilds.channel(db, "darwin-arm64")["current"] is None


def test_canary_reaches_only_its_nodes_and_promote_waits_until_they_run_it(db):
    _, a = enrolled_node(db, "mini")
    _, b = enrolled_node(db, "desk")
    old, new = upload(db, "0.3.2"), upload(db, "0.4.0")
    planned(db, "agent.canary", old[:12], {"nodes": ["mini", "desk"]})               # a sha prefix names it
    report(db, a, old)
    report(db, b, old)
    planned(db, "agent.promote", "agent")
    assert agentbuilds.channel(db, "darwin-arm64")["current"] == old

    planned(db, "agent.canary", "0.4.0", {"nodes": ["mini"]})
    d_a = core.heartbeat(db, fresh(db, a), {"attempts": []})["agent_update"]
    assert d_a["sha256"] == new and d_a["version"] == "0.4.0" and d_a["url"] == f"/v1/agent/builds/{new}"
    assert core.heartbeat(db, fresh(db, b), {"attempts": []})["agent_update"] is None    # desk runs current
    hello = core.hello(db, fresh(db, a), {"live_attempts": [], "agent_build": old})
    assert hello["agent_update"]["sha256"] == new                                         # hello carries it too

    report(db, a, old, state="draining")
    plan = op(db, "agent.promote", "agent", dry_run=True)["plan"]
    imp = plan["impact"]["platforms"]["darwin-arm64"]
    assert imp["ready"] is False and imp["canary_nodes"] == {"mini": "draining"}
    with pytest.raises(core.ApiError, match="not running on every canary node"):
        planned(db, "agent.promote", "agent")
    report(db, a, new)
    assert core.heartbeat(db, fresh(db, a), {"attempts": [], "agent_build": new})["agent_update"] is None
    assert agentbuilds.readiness(db, "darwin-arm64")["ready"]
    planned(db, "agent.promote", "agent")
    ch = agentbuilds.channel(db, "darwin-arm64")
    assert (ch["current"], ch["previous"], ch["canary"]) == (new, old, None)
    assert core.heartbeat(db, fresh(db, b), {"attempts": []})["agent_update"]["sha256"] == new   # now everyone


def test_rollback_abandons_a_canary_then_flips_back_to_previous(db):
    _, a = enrolled_node(db, "mini")
    old, new = upload(db, "0.3.2"), upload(db, "0.4.0")
    planned(db, "agent.canary", old, {"nodes": ["mini"]})
    report(db, a, old)
    planned(db, "agent.promote", "agent")
    planned(db, "agent.canary", new, {"nodes": ["mini"]})
    op(db, "agent.rollback", "agent", reason="bad canary")
    ch = agentbuilds.channel(db, "darwin-arm64")
    assert ch["canary"] is None and ch["current"] == old
    assert core.heartbeat(db, fresh(db, a), {"attempts": [], "agent_build": old})["agent_update"] is None
    planned(db, "agent.canary", new, {"nodes": ["mini"]})
    report(db, a, new)
    planned(db, "agent.promote", "agent")
    op(db, "agent.rollback", "agent", reason="regression")
    ch = agentbuilds.channel(db, "darwin-arm64")
    assert (ch["current"], ch["previous"]) == (old, new)
    assert core.heartbeat(db, fresh(db, a), {"attempts": []})["agent_update"]["sha256"] == old


def test_reported_failures_are_recorded_and_shown(db):
    _, a = enrolled_node(db, "mini")
    old, new = upload(db, "0.3.2"), upload(db, "0.4.0")
    planned(db, "agent.canary", new, {"nodes": ["mini"]})
    report(db, a, old, state="rolled_back", error="the new binary failed to start 3 times")
    ev = db.q("SELECT kind, reason FROM events WHERE kind LIKE 'agent_update_%'")
    assert ev and ev[-1]["kind"] == "agent_update_rolled_back" and "failed to start" in ev[-1]["reason"]
    v = agentbuilds.view(db)
    row = [n for n in v["nodes"] if n["hostname"] == "mini"][0]
    assert row["update"]["state"] == "rolled_back" and not row["up_to_date"]
    assert "rolled_back" in agentbuilds.readiness(db, "darwin-arm64")["canary_nodes"]["mini"]


def test_build_references_resolve_by_sha_prefix_or_version(db):
    sha = upload(db, "0.4.0")
    assert agentbuilds.resolve(db, sha) == agentbuilds.resolve(db, sha[:10]) == agentbuilds.resolve(db, "0.4.0") == sha
    with pytest.raises(agentbuilds.BuildError):
        agentbuilds.resolve(db, "0.9.9")


def test_signing_mode_requires_a_signed_build_and_the_directive_carries_it(db, monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    from oarbank import signing
    _, a = enrolled_node(db, "mini")
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    key = tmp_path / "k"
    db.set_setting("release_pubkey", signing.keygen(key))
    sha = upload(db, "0.4.0")
    with pytest.raises(core.ApiError, match="unsigned"):
        planned(db, "agent.canary", sha, {"nodes": ["mini"]})
    bad = signing.agent_statement(sha, "0.3.0", 1, ["darwin-arm64"])
    with pytest.raises(core.ApiError, match="does not name"):
        op(db, "agent.sign", sha, params={"statement": bad, "signature": signing.sign(bad, key)}, reason="t")
    stmt = signing.agent_statement(sha, "0.4.0", 1, ["darwin-arm64"])
    op(db, "agent.sign", sha, params={"statement": stmt, "signature": signing.sign(stmt, key)}, reason="t")
    planned(db, "agent.canary", sha, {"nodes": ["mini"]})
    d = core.heartbeat(db, fresh(db, a), {"attempts": []})["agent_update"]
    assert d["statement"] == stmt and d["signature"]
    other = upload(db, "0.5.0")                                          # anti-rollback: seq must rise
    st2 = signing.agent_statement(other, "0.5.0", 1, ["darwin-arm64"])
    with pytest.raises(core.ApiError, match="not above"):
        op(db, "agent.sign", other, params={"statement": st2, "signature": signing.sign(st2, key)}, reason="t")


def test_download_is_served_only_to_a_node_assigned_the_build(db):
    from helpers import agent_client, node_headers
    der_a, a = enrolled_node(db, "mini")
    der_b, b = enrolled_node(db, "desk")
    sha = upload(db, "0.4.0")
    planned(db, "agent.canary", sha, {"nodes": ["mini"]})
    c = agent_client(db)
    r = c.get(f"/v1/agent/builds/{sha}", headers=node_headers(der_a))
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == sha
    assert c.get(f"/v1/agent/builds/{sha}", headers=node_headers(der_b)).status_code == 404
