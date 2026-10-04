"""Dataset effects (docs/design/sdk-1.3.md, #4): datasets.create of a declared short kind (a repeat is skipped, other
contents refused), datasets.update merging meta, datasets.delete of the module's own datasets that no open job names."""
import hashlib
import json

import pytest
from oarbank_sdk import effects as fx

from oarbank.coordinator import clock, effects, modcalls

from helpers import PARAMS, SCENES, create_study, make_db

KINDS = {"datasets.create", "datasets.update", "datasets.delete"}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def blob(db, module="relay", body=b"frame") -> dict:
    """A blob the module can reach (one of its files), as {path, digest, size}."""
    d = hashlib.sha256(body).hexdigest()
    db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (d, "/dev/null", len(body)))
    db.x("INSERT OR IGNORE INTO module_files(module,path,digest,size,updated_at) VALUES(?,?,?,?,?)",
         (module, f"in/{d[:8]}", d, len(body), clock.now()))
    return {"path": "frame.exr", "digest": d, "size": len(body)}


def apply(db, *effs, module="relay"):
    with db.tx():
        return effects.apply(db, module, KINDS, [e.model_dump() for e in effs])


def meta(db, did):
    return json.loads(db.one("SELECT meta_json FROM datasets WHERE dataset_id=?", (did,))["meta_json"])


def code(db, *effs, module="relay"):
    with pytest.raises(effects.EffectError) as e:
        apply(db, *effs, module=module)
    return e.value.status, e.value.code


def test_create_takes_a_declared_short_kind_and_a_repeat_is_skipped(db):
    f = blob(db)
    assert apply(db, fx.datasets_create("scene:new", "scene", [f], {"scene": "atrium"})) == [{"kind": "datasets.create",
                                                                                              "dataset_id": "scene:new"}]
    assert db.one("SELECT kind, module FROM datasets WHERE dataset_id='scene:new'") == {"kind": "scene", "module": "relay"}
    assert apply(db, fx.datasets_create("scene:new", "scene", [f], {"scene": "atrium"}))[0]["skipped"] is True
    assert code(db, fx.datasets_create("scene:new", "scene", [f], {"scene": "lobby"})) == (409, "dataset_exists")
    assert code(db, fx.datasets_create("x:1", "relay/scene", [f])) == (422, "undeclared_kind")      # never namespaced
    assert code(db, fx.datasets_create("x:2", "archive", [f])) == (422, "undeclared_kind")
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('op:1','scene',NULL,'{}','[]',0)")
    assert code(db, fx.datasets_create("op:1", "scene", [])) == (409, "dataset_owned")              # the operator's


def test_the_query_takes_the_same_short_kind(db):
    apply(db, fx.datasets_create("scene:new", "scene", [blob(db)]))
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('op:1','scene',NULL,'{}','[]',0)")
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('toy:1','scene','toy','{}','[]',0)")
    query = modcalls.host_callbacks(db)["host.datasets.query"]
    ids = {d["id"] for d in query("relay", {"kind": "scene", "limit": 100})["datasets"]}
    assert {"scene:new", "op:1", *SCENES} <= ids and "toy:1" not in ids        # its own and the operator's, never another's
    assert query("relay", {"kind": "relay/scene"})["datasets"] == []


def test_update_merges_meta_and_never_changes_files(db):
    f = blob(db)
    apply(db, fx.datasets_create("scene:new", "scene", [f], {"scene": "atrium", "frames": "1-24", "draft": True}))
    apply(db, fx.datasets_update("scene:new", {"frames": "1-48", "draft": None, "summary": "settled"}))
    assert meta(db, "scene:new") == {"scene": "atrium", "frames": "1-48", "summary": "settled"}
    bad = fx.effect("datasets.update", dataset_id="scene:new", meta={"x": 1}, files=[])
    assert code(db, bad) == (422, "dataset_immutable")
    assert code(db, fx.datasets_update("scene:none", {"x": 1})) == (404, "unknown_dataset")
    assert code(db, fx.datasets_update("scene:new", {"x": 1}), module="toy") == (403, "not_owner")


def test_delete_removes_the_modules_own_dataset_unless_open_work_names_it(db):
    from oarbank.coordinator import core
    f = blob(db)
    apply(db, fx.datasets_create("scene:tmp", "scene", [f]), fx.datasets_create("scene:busy", "scene", [f]))
    assert apply(db, fx.datasets_delete("scene:tmp"))[0] == {"kind": "datasets.delete", "dataset_id": "scene:tmp"}
    assert not db.one("SELECT 1 FROM datasets WHERE dataset_id='scene:tmp'")
    assert apply(db, fx.datasets_delete("scene:tmp"))[0]["missing"] is True                      # a no-op now
    assert db.one("SELECT 1 FROM blobs WHERE digest=?", (f["digest"],))                          # blobs stay
    create_study(db, "s", [], ["scene:busy"], {"label": "base", "params": PARAMS})
    assert code(db, fx.datasets_delete("scene:busy")) == (409, "dataset_in_use")
    assert code(db, fx.datasets_delete(SCENES[0]), module="toy") == (403, "not_owner")
    art = core._register_artifacts(db, {"artifacts": [{"name": "frame", "files": [f]}]}, "relay")
    assert art is None
    did = db.one("SELECT dataset_id FROM datasets WHERE kind='artifact'")["dataset_id"]
    assert code(db, fx.datasets_delete(did)) == (422, "host_dataset")
