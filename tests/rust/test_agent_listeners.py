"""Inbound listeners end to end (docs/design/inbound-listeners.md): a real coordinator, two real agents and a fake
gateway on loopback that acts as a NAT (it forwards each mapping's external port to its internal address). The SDK's
reference module `publicecho` serves its `echo` listener through its endpoint service; the agent maps the port, a
client is answered through the relay at the mapped address, the second agent proves reachability with a dial-back,
the gateway reboots and the mapping comes back, the kill switch removes it, and stopping the agent releases it. No
real router is ever asked: both agents name the fake gateway (OARBANK_PORTMAP_GATEWAY, OARBANK_PORTMAP_SSDP)."""
import json
import os
import signal
import socket
import subprocess
import sys
import time


sys.path.insert(0, os.path.dirname(__file__))
from conftest import CARGO, REPO, agent_env, free_port, install_module  # noqa: E402
from agentbin import cargo_env  # noqa: E402
from test_agent_jobs import node_modules  # noqa: E402
from test_agent_session import wait  # noqa: E402

PUBLICECHO = REPO / "vendor" / "oarbank-sdk" / "examples" / "publicecho"
FAKE = REPO / "rust" / "target" / "debug" / ("oarbank-fake-gateway" + (".exe" if os.name == "nt" else ""))


class Gateway:
    """The fake NAT-PMP, PCP and UPnP gateway (rust/crates/oarbank-portmap, feature `fake`)."""

    def __init__(self, cfg: dict):
        r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-portmap", "--features", "fake", "--bin", "oarbank-fake-gateway"],
                           cwd=REPO / "rust", env=cargo_env(), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-2000:]
        self.p = subprocess.Popen([str(FAKE), json.dumps(cfg)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addr = json.loads(self.p.stdout.readline())

    def cmd(self, **c):
        self.p.stdin.write(json.dumps(c) + "\n")
        self.p.stdin.flush()

    def state(self):
        self.cmd(op="mappings")
        return json.loads(self.p.stdout.readline())

    def ours(self):
        return [m for m in self.state()["mappings"] if not m["foreign"]]

    def close(self):
        try:
            self.cmd(op="quit")
            self.p.wait(5)
        except Exception:
            self.p.kill()


def node_doc(c, nid):
    return c.api("GET", f"/api/v1/listeners?node={nid}")["nodes"][0]


def listener(c, nid, key="publicecho/echo"):
    return next((x for x in node_doc(c, nid)["listeners"] if x["key"] == key), {})


def ask(addr: str, line: str) -> str:
    host, port = addr.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=10) as s:
        s.sendall(line.encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode().strip()


def start_agent(agent_bin, coordinator, home, gw: Gateway):
    env = {**agent_env(), "OARBANK_PORTMAP_GATEWAY": gw.addr["pmp"], "OARBANK_PORTMAP_SSDP": gw.addr["ssdp"],
           "OARBANK_PORTMAP_TIMING": "fast", "OARBANK_LISTENER_PROBE_ALLOW_LOCAL": "1"}
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    seen = {e["enrollment_id"] for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"]}
    pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"]
                            if e["status"] == "pending" and e["enrollment_id"] not in seen] or None)
    nid = coordinator.admit(pending[0]["enrollment_id"])["result"]["node_id"]
    return p, nid, env


def test_a_public_listener_is_mapped_probed_served_recovered_and_released(agent_bin, coordinator, tmp_path):
    c = coordinator
    ext = free_port()
    gw = Gateway({"forward": True, "external": "127.0.0.1", "natpmp": True, "pcp": True, "upnp": True})
    install_module(c, PUBLICECHO, tmp_path, approve=True)
    agents = []
    try:
        a, nid, env = start_agent(agent_bin, c, tmp_path / "agent-a", gw)
        agents.append(a)
        b, nid_b, _ = start_agent(agent_bin, c, tmp_path / "agent-b", gw)      # the prober (another node)
        agents.append(b)
        wait(lambda: node_modules(c).get("publicecho") is not None, timeout=240)
        # the owner assigns the listener to node A (unsigned statements: developer mode)
        params = {"key": "publicecho/echo", "external_port": ext, "fallback": "refuse", "mapping": "auto"}
        plan = c.api("POST", "/api/v1/ops/listeners.configure", json={"target": nid, "params": params, "dry_run": True})["plan"]
        c.api("POST", "/api/v1/ops/listeners.configure", json={"plan_id": plan["plan_id"], "reason": "e2e"})
        # A listens, maps the port by PCP on the gateway and is checked from B
        x = wait(lambda: (lambda x: x if x.get("state") == "listening" and x.get("external") else None)(listener(c, nid)), timeout=240)
        assert x["external"] == f"127.0.0.1:{ext}", x
        assert x["portmaps"][0]["protocol"] == "pcp" and x["portmaps"][0]["state"] == "mapped", x
        assert [m["external_port"] for m in gw.ours()] == [ext]
        # a new mapping asks for a dial-back by itself (probe_wanted); the coordinator picks B to dial
        x = wait(lambda: (lambda x: x if x.get("result") == "REACHABLE" else None)(listener(c, nid)), timeout=180)
        assert x["probe"]["state"] == "reachable" and x["probe"]["via"] == f"fleet:{nid_b}", x
        # a client at the mapped address is served by the module, through the relay; the service knows its address
        answer = wait(lambda: (lambda r: r if r.endswith(f"127.0.0.1:{ext}") else None)(ask(f"127.0.0.1:{ext}", "hello")), timeout=60)
        assert answer == f"echo hello 127.0.0.1:{ext}"
        wait(lambda: (listener(c, nid).get("conns") or {}).get("accepted", 0) >= 1, timeout=60)
        # the gateway reboots: the epoch goes back, the agent maps again
        time.sleep(3)
        gw.cmd(op="reboot")
        wait(lambda: [m["external_port"] for m in gw.ours()] == [ext], timeout=60)
        assert ask(f"127.0.0.1:{ext}", "again") == f"echo again 127.0.0.1:{ext}"
        # the kill switch closes the listener and removes the mapping; resuming brings both back
        c.api("POST", "/api/v1/ops/listeners.disable", json={"target": "fleet", "reason": "e2e"})
        wait(lambda: listener(c, nid).get("refused") == "LISTENERS_DISABLED" and not gw.ours(), timeout=60)
        c.api("POST", "/api/v1/ops/listeners.resume", json={"target": "fleet", "reason": "e2e"})
        wait(lambda: [m["external_port"] for m in gw.ours()] == [ext], timeout=120)
        # nobody else's mapping was ever deleted
        assert not [d for d in gw.state()["deletes"] if d["foreign"]]
        # stopping the agent releases its mapping
        a.send_signal(signal.SIGTERM) if os.name != "nt" else a.terminate()
        a.wait(60)
        assert not gw.ours(), gw.state()
        # a crash leaves the journal; the uninstall step's release-all cleans it
        a2 = subprocess.Popen([str(agent_bin), "--home", str(tmp_path / "agent-a"), "run", "--coordinator", c.url], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        agents.append(a2)
        wait(lambda: [m["external_port"] for m in gw.ours()] == [ext], timeout=120)
        a2.kill()
        a2.wait(30)
        assert gw.ours()
        r = subprocess.run([str(agent_bin), "--home", str(tmp_path / "agent-a"), "portmap", "release-all"], env=env,
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stdout + r.stderr
        assert json.loads(r.stdout)["released"] >= 1
        assert not gw.ours(), gw.state()
    finally:
        for p in agents:
            if p.poll() is None:
                p.terminate()
            try:
                out = p.communicate(timeout=30)[0]
                print((out or "")[-4000:])
            except Exception:
                p.kill()
        gw.close()
