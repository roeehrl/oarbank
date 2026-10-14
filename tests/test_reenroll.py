"""Re-enrolment keeps the node (coordinator/nodeidentity.py; docs/design/node-enrollment.md, "Re-enrolment").

A machine re-added to the tailnet is a new Tailscale device: the coordinator refuses its certificate there (a key copied
off a node is refused the same way), its agent enrolls again with a CSR for the same key, and approving that keeps the
node's id, settings and history. A machine that cannot prove a node's key is a new node, and the preview says so."""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from helpers import FACTS, make_db, node_key_and_csr, run_op, set_node
from oarbank.contracts import impact as impact_text
from oarbank.coordinator import clock, core, joincodes, nodeidentity, ops

from test_console import env  # noqa: F401  (the console fixture: oarbankd + console + a session)

OLD_IP, NEW_IP, OTHER_IP = "100.64.0.11", "100.64.0.12", "100.64.0.13"     # placeholder tailnet addresses


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "home" / "oarbank.sqlite3")


@pytest.fixture
def tailnet(monkeypatch):
    """`tailscale whois` over a table the test edits: {ip: StableID}."""
    devices = {}
    monkeypatch.setattr(core, "tailscale_whois", lambda ip: {"ts_node_id": devices[ip], "ts_name": None, "login": None,
                                                             "tags": []} if ip in devices else None)
    return devices


def csr_for(key, name="host-a") -> str:
    return x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM).decode()


def der_of(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)


def join(db, key, ip, name="host-a", facts=None):
    """An agent's enrollment (approved by the owner) from `ip`: (enrollment id, node id, certificate DER)."""
    e = core.enroll(db, name, {**(facts or FACTS), "hostname": name}, ip, csr_for(key, name))
    nid = run_op(db, "nodes.admit", e["enrollment_id"])["result"]["node_id"]
    st = core.enroll_status(db, e["enrollment_id"])
    return e["enrollment_id"], nid, der_of(st["cert_pem"])


def preview(db, eid) -> dict:
    return ops.execute(db, ops.OpRequest(op="nodes.admit", actor="test", source="system", target=eid, params={},
                                         reason="test", dry_run=True))["plan"]["impact"]


def disabled(db, nid) -> list:
    """The modules the node's own settings switch off, as its agent gets them."""
    from oarbank.coordinator.settings.apply import node_values
    return node_values(node(db, nid))["modules_disabled"]


def node(db, nid):
    return db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))


def test_a_machine_re_added_to_the_tailnet_keeps_its_node_and_settings(db, tailnet):
    tailnet[OLD_IP] = "ts-old"
    key, _ = node_key_and_csr()
    _, nid, der = join(db, key, OLD_IP)
    core.auth_cert(db, der, OLD_IP)
    core.set_node_state(db, nid, "paused", "owner")                       # node-scoped settings the owner chose
    set_node(db, nid, "enabled", False, module="toy")
    assert "toy" in disabled(db, nid)

    # an admin applies a tag: a new Tailscale device (StableID and address); the old one is gone
    del tailnet[OLD_IP]
    tailnet[NEW_IP] = "ts-new"
    with pytest.raises(core.ApiError) as err:
        core.auth_cert(db, der, NEW_IP)
    assert err.value.code == "unauthorized" and "another Tailscale device" in err.value.detail
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='node_cert_other_device' AND node_id=?", (nid,))["n"] == 1
    with pytest.raises(core.ApiError):
        core.auth_cert(db, der, NEW_IP)                                   # logged once an hour, refused every time
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='node_cert_other_device' AND node_id=?", (nid,))["n"] == 1

    # the agent keeps its key and enrolls again: the request proves the node, and stays pending for the owner
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(key))
    assert e["status"] == "pending"
    imp = preview(db, e["enrollment_id"])
    assert nid in imp["re_enrolment_of"] and "keeps the node id" in imp["re_enrolment_of"]
    assert imp["tailscale_device_changed"].startswith("ts-old -> ts-new") and "warning" not in imp
    assert any("re enrolment of" in line for line in impact_text.lines(imp))          # the CLI preview says it too

    assert run_op(db, "nodes.admit", e["enrollment_id"])["result"]["node_id"] == nid
    n = node(db, nid)
    assert (n["ts_node_id"], n["ts_ip"], n["desired_state"]) == ("ts-new", NEW_IP, "paused")
    assert "toy" in disabled(db, nid)
    assert db.one("SELECT COUNT(*) n FROM nodes")["n"] == 1                # no second record, no duplicate host name
    assert db.one("SELECT 1 FROM events WHERE kind='node_tailscale_repinned' AND node_id=?", (nid,))
    new_der = der_of(core.enroll_status(db, e["enrollment_id"])["cert_pem"])
    assert core.auth_cert(db, new_der, NEW_IP)["node_id"] == nid
    with pytest.raises(core.ApiError):
        core.auth_cert(db, der, NEW_IP)                                   # the certificate it replaced is gone


def test_a_copied_key_is_still_refused_and_cannot_move_the_node_without_the_owner(db, tailnet):
    tailnet[OLD_IP], tailnet[OTHER_IP] = "ts-a", "ts-thief"
    key, _ = node_key_and_csr()
    _, nid, der = join(db, key, OLD_IP)
    core.auth_cert(db, der, OLD_IP)
    with pytest.raises(core.ApiError) as err:
        core.auth_cert(db, der, OTHER_IP)                                 # the certificate and key, used elsewhere
    assert err.value.code == "unauthorized"
    assert node(db, nid)["ts_ip"] == OLD_IP
    # a multi-use code that approves automatically admits machines; it does not move a node to another device
    code = joincodes.create(db, urls=["https://127.0.0.1:7443"], pins=["ab" * 32], cik="AA" * 21 + "A=",
                            actor="owner", uses=5, approve=True)
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OTHER_IP, csr_for(key),
                    join=joincodes.decode(code["code"])["token"])
    assert e["status"] == "pending"
    assert node(db, nid)["ts_node_id"] == "ts-a" and core.auth_cert(db, der, OLD_IP)["node_id"] == nid
    # the owner is told: the node is still online from its own device
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (clock.now(), nid))
    imp = preview(db, e["enrollment_id"])
    assert nid in imp["re_enrolment_of"] and "still online from its own Tailscale device" in imp["warning"]
    # the owner rejects it: nothing changed
    run_op(db, "nodes.reject_enrollment", e["enrollment_id"])
    assert node(db, nid)["ts_node_id"] == "ts-a"


def test_a_lookalike_without_the_key_is_a_new_node_and_the_preview_warns(db, tailnet):
    tailnet[OLD_IP], tailnet[NEW_IP] = "ts-old", "ts-new"
    _, nid, der = join(db, node_key_and_csr()[0], OLD_IP)
    core.set_node_state(db, nid, "paused", "owner")
    set_node(db, nid, "enabled", False, module="toy")
    # reinstalled (a new key), on a new Tailscale device: nothing proves it is the old node
    e = core.enroll(db, "HOST-A", {**FACTS, "hostname": "HOST-A"}, NEW_IP, csr_for(node_key_and_csr()[0], "HOST-A"))
    imp = preview(db, e["enrollment_id"])
    assert imp["new_node"] is True and "re_enrolment_of" not in imp
    assert nid in imp["warning"] and "same hardware" in imp["warning"] and "NEW node" in imp["warning"]
    assert "do NOT apply" in imp["warning"] and f"nodes.retire {nid}" in imp["old_record"][0]
    assert any(line.strip().startswith("warning:") for line in impact_text.lines(imp))
    new = run_op(db, "nodes.admit", e["enrollment_id"])["result"]["node_id"]
    assert new != nid and node(db, new)["desired_state"] == "active"     # fleet defaults: the owner was told
    assert node(db, nid)["desired_state"] == "paused"                     # the old record is untouched
    ev = db.one("SELECT reason FROM events WHERE kind='enroll_approved' AND node_id=?", (new,))
    assert nid in ev["reason"]
    # retiring the old record, as offered
    run_op(db, "nodes.retire", nid)
    assert node(db, nid)["lifecycle"] == "retired" and node(db, nid)["client_key_sha256"] is None


def test_a_node_enrolled_before_keys_were_recorded_learns_its_key_on_its_next_session(db, tailnet):
    tailnet[OLD_IP] = "ts-old"
    key, _ = node_key_and_csr()
    _, nid, der = join(db, key, OLD_IP)
    db.x("UPDATE nodes SET client_key_sha256=NULL WHERE node_id=?", (nid,))     # as a 2.10.3 coordinator left it
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(key))
    assert "re_enrolment_of" not in preview(db, e["enrollment_id"])          # nothing to prove it against yet
    core.reject_enrollment(db, e["enrollment_id"], "test")
    core.auth_cert(db, der, OLD_IP)                                         # its next request records the key
    assert node(db, nid)["client_key_sha256"]
    tailnet[NEW_IP] = "ts-new"
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(key))
    assert nid in preview(db, e["enrollment_id"])["re_enrolment_of"]


def test_the_previous_key_proves_the_node_while_renewing_and_a_retired_node_is_never_adopted(db, tailnet):
    tailnet[OLD_IP] = "ts-old"
    key, _ = node_key_and_csr()
    _, nid, der = join(db, key, OLD_IP)
    n = core.auth_cert(db, der, OLD_IP)
    new_key, _ = node_key_and_csr()
    core.renew_cert(db, n, csr_for(new_key))                              # the agent may not have the new one yet
    tailnet[NEW_IP] = "ts-new"
    for k in (key, new_key):
        e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(k))
        assert nid in preview(db, e["enrollment_id"])["re_enrolment_of"]
        core.reject_enrollment(db, e["enrollment_id"], "test")
    run_op(db, "nodes.retire", nid)
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(new_key))
    imp = preview(db, e["enrollment_id"])
    assert "re_enrolment_of" not in imp and imp["new_node"] is True and "warning" not in imp   # retired: no lookalike


def identity(db, eid) -> dict:
    return nodeidentity.of_enrollment(db, db.one("SELECT * FROM enrollments WHERE enrollment_id=?", (eid,)))


def test_a_retired_node_is_not_what_a_request_from_its_tailscale_device_is(db, tailnet):
    tailnet[OLD_IP] = "ts-old"
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    core.set_node_state(db, old, "paused", "owner")
    set_node(db, old, "enabled", False, module="toy")
    run_op(db, "nodes.retire", old)
    assert node(db, old)["ts_node_id"] == "ts-old"                         # the retired record keeps its StableID
    # the machine enrolls again from the same Tailscale device with a new key: it is a new machine, and the retired
    # record is neither the node it keeps nor one it looks like
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OLD_IP, csr_for(node_key_and_csr()[0]))
    i = identity(db, e["enrollment_id"])
    assert (i["node_id"], i["via"], i["lookalikes"]) == (None, None, [])
    imp = preview(db, e["enrollment_id"])
    assert imp["new_node"] is True and "re_enrolment_of" not in imp and "warning" not in imp and "old_record" not in imp
    assert old not in str(imp)
    new = run_op(db, "nodes.admit", e["enrollment_id"])["result"]["node_id"]
    assert new != old and db.one("SELECT COUNT(*) n FROM nodes")["n"] == 2
    o = node(db, old)                                                     # still retired, untouched
    assert (o["lifecycle"], o["desired_state"], o["client_cert_fp"], o["client_key_sha256"]) == ("retired", "paused",
                                                                                                 None, None)
    n = node(db, new)                                                     # a new node: the fleet's defaults
    assert (n["ts_node_id"], n["desired_state"]) == ("ts-old", "active") and "toy" not in disabled(db, new)
    assert db.one("SELECT reason FROM events WHERE kind='enroll_approved' AND node_id=?", (new,))["reason"] is None
    assert core.auth_cert(db, der_of(core.enroll_status(db, e["enrollment_id"])["cert_pem"]), OLD_IP)["node_id"] == new
    # the retired record and the new node now share the StableID: a later request from that device is the live node
    e2 = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OLD_IP, csr_for(node_key_and_csr()[0]))
    i2 = identity(db, e2["enrollment_id"])
    assert (i2["node_id"], i2["via"]) == (new, "tailscale")
    assert new in preview(db, e2["enrollment_id"])["re_enrolment_of"]


def test_a_join_code_never_brings_a_retired_node_back(db, tailnet):
    tailnet[OLD_IP] = "ts-old"
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    run_op(db, "nodes.retire", old)
    code = joincodes.create(db, urls=["https://127.0.0.1:7443"], pins=["ab" * 32], cik="AA" * 21 + "A=",
                            actor="owner", uses=5, approve=True)
    e = core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OLD_IP, csr_for(node_key_and_csr()[0]),
                    join=joincodes.decode(code["code"])["token"])
    assert e["status"] == "approved"                                      # a new machine, as the code admits them
    new = db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (e["enrollment_id"],))["node_id"]
    assert new != old and node(db, old)["lifecycle"] == "retired" and node(db, new)["lifecycle"] == "enrolled"
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='enroll_approved' AND node_id=?", (old,))["n"] == 1


def test_the_fleet_page_says_which_waiting_machine_keeps_a_node_and_which_becomes_a_new_one(env, monkeypatch):
    c, db, state = env["c"], env["db"], env["state"]
    devices = {OLD_IP: "ts-old", NEW_IP: "ts-new"}
    monkeypatch.setattr(core, "tailscale_whois", lambda ip: {"ts_node_id": devices[ip]} if ip in devices else None)
    key, _ = node_key_and_csr()
    _, nid, der = join(db, key, OLD_IP)
    core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, NEW_IP, csr_for(key))          # proves the node
    core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OTHER_IP, csr_for(node_key_and_csr()[0]))   # cannot
    state.rebuild()
    fleet = c.get("/frag/fleet").text
    assert "re-enrolment</span> of" in fleet and "its Tailscale device changed" in fleet
    assert "new node</span> looks like" in fleet and "(same hardware)" in fleet and "NEW node" in fleet
    assert 'action="/do/nodes.retire"' in fleet and f'name="target" value="{nid}"' in fleet


def test_the_fleet_page_shows_a_machine_on_a_retired_nodes_device_as_new_and_how_a_node_matched(env, monkeypatch):
    c, db, state = env["c"], env["db"], env["state"]
    devices = {OLD_IP: "ts-old", NEW_IP: "ts-new"}
    monkeypatch.setattr(core, "tailscale_whois", lambda ip: {"ts_node_id": devices[ip]} if ip in devices else None)
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    run_op(db, "nodes.retire", old)
    _, live, _ = join(db, node_key_and_csr()[0], NEW_IP, name="host-b")
    # a new key from the retired node's device, and a new key from the live node's device
    core.enroll(db, "host-a", {**FACTS, "hostname": "host-a"}, OLD_IP, csr_for(node_key_and_csr()[0]))
    core.enroll(db, "host-b", {**FACTS, "hostname": "host-b"}, NEW_IP, csr_for(node_key_and_csr()[0], "host-b"))
    state.rebuild()
    fleet = c.get("/frag/fleet").text
    assert f"/nodes/{old}" not in fleet and "new node</span> looks like" not in fleet   # no match, no lookalike
    assert fleet.count("re-enrolment</span> of") == 1                                  # only the live node's device
    assert f"host-b</a>: it comes from the node's Tailscale device and keeps" in fleet
    assert "it proves the node's key" not in fleet
