"""An empty release needs no owner signature (docs/release-signing.md, "Empty releases"). With signing on and the owner
key pinned, a node whose platform no enabled module runs on installs its empty release unsigned (the agent checks it
holds nothing) and becomes ready with no module; a release that holds module code reaches it only once the owner
signed it."""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, Coordinator, agent_env, install_module  # noqa: E402
from test_agent_move import t3  # noqa: E402
from test_agent_session import read_json, wait  # noqa: E402

from oarbank import signing  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"
PLATFORMS = ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-arm64", "windows-amd64"]


def elsewhere(tmp_path, here: str):
    """toy as module `elsewhere`, on every platform but this node's."""
    src = tmp_path / "elsewhere"
    shutil.copytree(TOY, src)
    t = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    t = t.replace('id = "dev.codonic.oarbank.toy"', 'id = "dev.codonic.oarbank.elsewhere"')
    t = t.replace(f"platforms = {json.dumps(PLATFORMS)}",
                  f"platforms = {json.dumps([p for p in PLATFORMS if p != here])}")
    (src / "oarbank-module.toml").write_text(t, encoding="utf-8")
    assert here not in t.split("platforms = ", 1)[1].split("\n", 1)[0]
    return src


def node(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def test_an_empty_release_installs_unsigned_and_module_code_waits_for_the_owner(agent_bin, tmp_path):
    pk, bk = tmp_path / "owner.key", tmp_path / "backup.key"
    p_pub, b_pub = signing.keygen(pk), signing.keygen(bk)
    home = tmp_path / "agent"
    with Coordinator(tmp_path / "coordinator", extra_env={"OARBANK_RELEASE_SIGNING": "1"}) as c:
        fleet = c.api("GET", "/api/v1/coordinator")["fleet_id"]
        anchors = signing.owner_anchors_statement(fleet, 1, [p_pub, b_pub])
        t3(c, "owner.set_anchors", params={"statement": anchors, "signatures": [
            {"key": p_pub, "sig": signing.sign(anchors, pk)}, {"key": b_pub, "sig": signing.sign(anchors, bk)}]})
        p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", c.url], env=agent_env(),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            pending = wait(lambda: [e for e in c.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
            c.admit(pending[0]["enrollment_id"])
            here = wait(lambda: (node(c) or {}).get("platform"), 60)
            install_module(c, elsewhere(tmp_path, here), tmp_path)

            # the node's platform runs no module: its empty release goes out unsigned and the node is ready
            n = wait(lambda: (lambda x: x if x and x.get("release_id") and x["lifecycle"] == "ready" else None)(node(c)), 90)
            rels = {r["release_id"]: r for r in c.api("GET", "/api/v1/releases")}
            empty = rels[n["release_id"]]
            assert empty["platform"] == here and empty["modules"] == [] and not empty["signed"] and empty["status"] == "current"
            assert not [r for r in rels.values() if r.get("awaiting") and r["platform"] == here]
            assert read_json(home / "agent.json")["release_pubkey"] == p_pub      # the key was pinned: not developer mode
            assert sorted(x.name for x in (home / "releases" / empty["release_id"]).iterdir()) == ["MANIFEST.json", "modules.json"]

            # a module for this platform: its release holds code and waits for the owner; the node keeps the empty one
            install_module(c, TOY, tmp_path)
            rid = wait(lambda: next((r["release_id"] for r in c.api("GET", "/api/v1/releases")
                                     if r["platform"] == here and r.get("awaiting")), None), 30)
            got = {r["release_id"]: r for r in c.api("GET", "/api/v1/releases")}[rid]
            assert got["modules"] == ["toy@0.1.0"] and not got["signed"] and got["status"] == "candidate"
            time.sleep(3)                                   # heartbeats go by: nothing unsigned with code reaches it
            assert node(c)["release_id"] == empty["release_id"]

            # the owner signs and promotes it: now the node installs it
            seq = max([r["seq"] or 0 for r in c.api("GET", "/api/v1/releases") if r["signed"]] + [0]) + 1
            stmt = signing.statement(rid, got["sha256"], seq)
            t3(c, "releases.attach_signature", target=rid, params={"statement": stmt, "signature": signing.sign(stmt, pk)})
            t3(c, "releases.promote", target=rid)
            wait(lambda: node(c)["release_id"] == rid, 120)
            assert (home / "releases" / rid / "modules" / "toy" / "toy_runner.py").exists()
        finally:
            p.terminate()
            out = p.communicate(timeout=10)[0]
            print(out[-6000:])
    assert "release install refused" not in out, out[-3000:]
