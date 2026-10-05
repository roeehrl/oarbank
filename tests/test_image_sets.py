"""Signed container image sets and GPU passthrough on the coordinator side (docs/design/secrets-and-signed-images.md,
#13): approval covers a prefix and a key, never digests; jobs list the digest-pinned images they run (refused with
image_not_approved outside every set); the release carries the sets with their keys to agents; each digest's first
run is recorded and audited; 500 distinct images run under one approval; GPU container jobs reserve the agent's gpu pool."""
import shutil

import pytest

from oarbank.coordinator import core, effects, modcalls, modimages, modsandbox, modstore, ops, releases
from oarbank.coordinator.db import jl

from helpers import FIXTURES, install, make_db, run_op
from test_secrets import DOCTOR, node

VAULT_DIR = FIXTURES / "vault"
SET = "registry.example.org/bench/tasks"


def digest(i: int) -> str:
    return "sha256:" + f"{i:064x}"


@pytest.fixture
def db(tmp_path):
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(d, VAULT_DIR, enable=False)
    modsandbox.approve(d, "vault", r["version"], "test", None)
    modstore.enable(d, "vault", r["version"])
    modcalls.use(d)
    releases.sync(d)
    return d


def test_approval_shows_the_prefix_and_the_key_never_digests(db):
    from oarbank_sdk import images
    st = modsandbox.status(db, "vault", "1.0.0")
    key = (VAULT_DIR / "keys" / "tasks.pub").read_text(encoding="utf-8")
    assert st["requests"]["container_sets"] == [{"name": "tasks", "registry": "registry.example.org", "repository": "bench/tasks/",
                                                  "platform": "linux/amd64", "key_sha256": images.key_sha256(key), "index": None}]
    text = modsandbox.describe(st["requests"])
    assert f"container images under {SET}/ (linux/amd64) signed by key SHA256:{images.key_sha256(key)[:16]}" in text
    assert st["approved"]


def test_the_release_carries_the_sets_with_their_keys(db):
    entry = releases.module_entry("vault", "1.0.0", "d", db.abs(modstore.record(db, "vault", "1.0.0")["path"]))
    sets = entry["sandbox"]["container_sets"]
    assert sets == [{"name": "tasks", "registry": "registry.example.org", "repository": "bench/tasks/", "platform": "linux/amd64",
                     "key": (VAULT_DIR / "keys" / "tasks.pub").read_text(encoding="utf-8")}]


def test_jobs_list_digest_pinned_images_inside_a_set(db):
    run_op(db, "mod.vault.queue_tasks", params={"images": [f"{SET}/t1@{digest(1)}", f"{SET}/sub/t2:v2@{digest(2)}"]})
    rows = db.q("SELECT images_json FROM jobs WHERE stage='task' ORDER BY job_id")
    assert [jl(r["images_json"]) for r in rows] == [[f"{SET}/t1@{digest(1)}"], [f"{SET}/sub/t2:v2@{digest(2)}"]]
    for bad, why in ((f"registry.example.org/bench/other/t@{digest(3)}", "neither an approved image"),
                     (f"{SET}/t1:latest", "not pinned by digest"),
                     (f"{SET}-x/t1@{digest(4)}", "neither an approved image")):
        with pytest.raises(ops.OpError, match="image_not_approved") as e:
            run_op(db, "mod.vault.queue_tasks", params={"images": [bad], "campaign_id": "c_bad"})
        assert why in e.value.detail
    c = db.one("SELECT * FROM campaigns LIMIT 1")
    with pytest.raises(effects.EffectError, match="bad_images"):          # a stage without the containers pool
        effects.enqueue(db, "vault", c, [{"job_key": "a" * 64 + ":probe", "stage": "probe", "spec": {},
                                          "images": [f"{SET}/t@{digest(5)}"]}])


def test_five_hundred_distinct_signed_images_run_under_one_approval_and_each_first_run_is_audited(db):
    approvals = db.q("SELECT * FROM module_grants")
    n = node(db)
    imgs = [f"{SET}/task-{i}@{digest(i)}" for i in range(500)]
    run_op(db, "mod.vault.queue_tasks", params={"images": imgs})
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE stage='task'")["n"] == 500
    ran = []
    while True:
        gs = core.claim(db, n, {"free_cpu": 64, "free_mem_gb": 256, "ready_datasets": []})["grants"]
        if not gs:
            break
        for g in gs:
            assert g["images"] and g["images"][0] in imgs
            ran.append(g["images"][0])
            body = {"result": {"envelope": 1, "schema": "vault/result@1", "module_version": "1.0.0", "protocol": 1,
                               "payload": {"digest": "task"}}, "images": [{"set": "tasks", "image": g["images"][0]}]}
            core.complete(db, n, g["attempt_id"], body)
        n = db.one("SELECT * FROM nodes WHERE node_id=?", (n["node_id"],))
    assert sorted(ran) == sorted(imgs)
    assert db.q("SELECT * FROM module_grants") == approvals                     # still the one approval
    assert db.one("SELECT COUNT(*) n FROM module_images WHERE module='vault'")["n"] == 500
    assert db.one("SELECT COUNT(*) n FROM audit WHERE operation='containers.first_run'")["n"] == 500
    first = db.one("SELECT * FROM audit WHERE operation='containers.first_run' ORDER BY event_id LIMIT 1")
    assert first["actor"] == f"node:{n['node_id']}" and '"set": "tasks"' in first["after_json"]
    # a digest that ran before is not new; an image outside the set or a set the module lacks is not recorded
    assert modimages.record_runs(db, "vault", n["node_id"], 1, [{"set": "tasks", "image": imgs[0]},
                                                                 {"set": "tasks", "image": f"registry.example.org/x@{digest(9999)}"},
                                                                 {"set": "nope", "image": f"{SET}/y@{digest(9998)}"}]) == []


def gpu_variant(tmp_path):
    src = tmp_path / "vault-gpu"
    shutil.copytree(VAULT_DIR, src)
    m = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    m = m.replace('capabilities = ["deterministic_output"]', 'capabilities = ["deterministic_output"]\ngpu = { use = "exclusive", in_container = true }')
    m = m.replace("pools = { containers = 1 } }", "pools = { containers = 1, gpu = 1 } }")
    (src / "oarbank-module.toml").write_text(m)
    return src


def test_gpu_container_jobs_reserve_the_gpu_pool_and_obey_gpu_admission(tmp_path):
    from oarbank.coordinator import explain
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(d, gpu_variant(tmp_path), enable=False)
    st = modsandbox.status(d, "vault", r["version"])
    assert st["requests"]["container_gpu"] and "GPU passthrough to containers" in modsandbox.describe(st["requests"])
    modsandbox.approve(d, "vault", r["version"], "test", None)
    modstore.enable(d, "vault", r["version"])
    modcalls.use(d)
    releases.sync(d)
    n = node(d)                                                     # offers containers but no gpu pool (macOS)
    run_op(d, "mod.vault.queue_tasks", params={"images": [f"{SET}/t@{digest(1)}"]})
    grab = lambda **kw: core.claim(d, d.one("SELECT * FROM nodes WHERE node_id=?", (n["node_id"],)),
                                   {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": [], **kw})["grants"]
    assert grab() == []
    job = d.one("SELECT job_id FROM jobs WHERE stage='task'")["job_id"]
    assert "POOL_EXHAUSTED" in [s.code for s in explain.explain(d, "job", str(job)).summary]
    core.heartbeat(d, n, {"doctor": DOCTOR, "attempts": [], "ready_datasets": [], "capacity": {"pools": {"containers": 2, "gpu": 1}}})
    assert grab(gpu_jobs=0) == []                                   # the owner admits no GPU job now: GPU_BLOCKED
    g = grab()
    assert len(g) == 1 and g[0]["spec"]["resources"]["pools"] == {"containers": 1, "gpu": 1}
