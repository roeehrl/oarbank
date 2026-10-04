"""oarbank-core (Rust, through the `oarbank_core` extension) against the Python SDK, the reference: the shared vectors
and goldens, then seeded random inputs. Runs under pytest or as a script.

    uv venv /tmp/ocore-venv --python 3.12
    uv pip install --python /tmp/ocore-venv <oarbank_core wheel> -e vendor/oarbank-sdk
    /tmp/ocore-venv/bin/python rust/crates/oarbank-core-py/tests/test_parity.py

The few known, deliberate differences are asserted as such (see KNOWN below), so any other mismatch fails.
"""
import ipaddress
import json
import math
import os
import random
import struct
import sys
from pathlib import Path

import oarbank_core as oc
from oarbank_sdk import bundle, deps, egress_proxy, images, imagetest, keys, portable, sandbox

SPEC = Path(__file__).resolve().parents[4] / "vendor" / "oarbank-sdk" / "spec"
SEED = int(os.environ.get("OCORE_PARITY_SEED", 20261003))
N = int(os.environ.get("OCORE_PARITY_N", 4000))         # random cases per test

# Deliberate differences, each a Python behaviour that looks like a bug (see the oarbank-core docs):
# - Python's `$` matches before a trailing newline, so the SDK accepts "a\n" as a PortablePath, "linux-amd64\n" as a
#   platform token and "x-1-py3-none-any.whl\n" as a wheel; Rust refuses all three.
# - serde_json refuses lone surrogates ("\ud800"), which Python's json.loads passes through to canonical_json.
KNOWN = {"trailing-newline": 0, "lone-surrogate": 0}


def outcome(f, *a, **kw):
    """("ok", value) or ("err", message). The extension raises ValueError; the SDK raises ValueError subclasses,
    SandboxError (a RuntimeError) for profiles, and TypeError/KeyError for malformed documents."""
    try:
        return ("ok", f(*a, **kw))
    except (ValueError, TypeError, KeyError, sandbox.SandboxError) as e:
        return ("err", str(e))


def same(py, rs, ctx, messages=False):
    if messages:
        assert py == rs, f"{ctx}: python {py!r} != rust {rs!r}"
    else:
        assert py[0] == rs[0] and (py[0] == "err" or py[1] == rs[1]), f"{ctx}: python {py!r} != rust {rs!r}"


# ---------------------------------------------------------------------------- canonical JSON and job keys

def test_canonical_vectors():
    v = json.loads((SPEC / "vectors" / "canonical-json.json").read_text())
    for c in v["cases"]:
        assert oc.canonical_json(json.dumps(c["input"])) == keys.canonical_json(c["input"]) == c["canonical"]
        assert oc.canonical_json(json.dumps(c["input"], ensure_ascii=False)) == c["canonical"]
    for r in v["refused"]:
        text = json.dumps(r["value"] if not isinstance(r["value"], str) else float(r["value"]))  # NaN / Infinity
        assert outcome(keys.canonical_json, json.loads(text))[0] == "err"
        assert outcome(oc.canonical_json, text)[0] == "err"


def rand_float(rng):
    k = rng.randrange(7)
    if k == 0:
        x = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]   # any double, every exponent
    elif k == 1:
        x = rng.uniform(-1e6, 1e6)
    elif k == 2:
        x = float(rng.randrange(-10**6, 10**6)) * 10.0 ** rng.randrange(-30, 30)
    elif k == 3:
        x = rng.choice([0.0, -0.0, 5e-324, -5e-324, 1e21, 1e-7, 1e-6, 9007199254740992.0, 9007199254740993.0,
                        2.0 ** 53 + 2, 1.7976931348623157e308, 2.2250738585072014e-308, 0.1, 0.2, 0.30000000000000004])
    elif k == 4:
        x = float(rng.randrange(-2**60, 2**60))
    elif k == 5:
        x = rng.random() * 10.0 ** rng.randrange(-330, 309)
    else:
        x = float(f"{rng.randrange(1, 10**rng.randrange(1, 18))}e{rng.randrange(-325, 309)}")
    return x if math.isfinite(x) else 1.5


def rand_int(rng):
    return rng.choice([
        rng.randrange(-1000, 1000), rng.randrange(-2**53 - 3, -2**53 + 3), rng.randrange(2**53 - 3, 2**53 + 3),
        rng.randrange(-2**64, 2**64), rng.randrange(-10**40, 10**40), 0,
    ])


def rand_str(rng, n=8):
    pools = [range(0x20, 0x7f), range(0, 0x20), range(0x80, 0x800), range(0x800, 0xd800), range(0xe000, 0x10000),
             range(0x10000, 0x110000), [0x7f, 0x2028, 0x2029, 0xfeff, 0xffff, ord('"'), ord("\\"), ord("/")]]
    out = []
    for _ in range(rng.randrange(n + 1)):
        pool = rng.choice(pools)
        out.append(chr(rng.choice(pool) if isinstance(pool, list) else rng.randrange(pool.start, pool.stop)))
    return "".join(out)


def rand_value(rng, depth=0):
    k = rng.randrange(9 if depth < 4 else 6)
    if k == 0:
        return rng.choice([None, True, False])
    if k in (1, 2):
        return rand_float(rng)
    if k == 3:
        return rand_int(rng)
    if k in (4, 5):
        return rand_str(rng)
    if k == 6:
        return [rand_value(rng, depth + 1) for _ in range(rng.randrange(5))]
    return {rand_str(rng, 4): rand_value(rng, depth + 1) for _ in range(rng.randrange(6))}


def test_canonical_random():
    rng = random.Random(SEED)
    for i in range(N):
        v = rand_value(rng)
        text = json.dumps(v, ensure_ascii=rng.random() < 0.5)
        py = outcome(keys.canonical_json, json.loads(text))
        rs = outcome(oc.canonical_json, text)
        same(py, rs, f"canonical #{i} {text[:200]!r}")


def test_canonical_number_spellings():
    rng = random.Random(SEED + 1)
    lits = ["0", "-0", "-0.0", "0e0", "1E5", "1e+5", "1.0e-7", "0.1e1", "123456789012345678901234567890",
            "-9007199254740993", "9007199254740992", "1e400", "-1e400", "1e-400", "4.35", "100e-2", "1.5E+300"]
    for _ in range(N):
        lits.append(f"{rng.choice(['', '-'])}{rng.randrange(10**rng.randrange(1, 25))}"
                    f"{rng.choice(['', '.' + str(rng.randrange(10**rng.randrange(1, 20)))])}"
                    f"{rng.choice(['', 'e', 'E', 'e+', 'e-'])}" + "")
    for lit in lits:
        if lit[-1] in "eE+-":
            lit += str(rng.randrange(400))
        py = outcome(lambda t: keys.canonical_json(json.loads(t)), lit)
        rs = outcome(oc.canonical_json, lit)
        if lit in ("1e400", "-1e400"):
            assert py[0] == rs[0] == "err"
            continue
        same(py, rs, f"number {lit}")


def test_lone_surrogates_are_a_known_difference():
    text = '"\\ud800"'
    assert outcome(lambda t: keys.canonical_json(json.loads(t)), text)[0] == "ok"
    assert outcome(oc.canonical_json, text)[0] == "err"
    KNOWN["lone-surrogate"] += 1


def test_job_keys():
    for c in json.loads((SPEC / "vectors" / "job-key.json").read_text())["cases"]:
        assert oc.job_key(c["module_id"], c["compat"], json.dumps(c["key_inputs"]), c["stage"]) == c["job_key"]
    rng = random.Random(SEED + 2)
    for i in range(N // 4):
        inputs = {rand_str(rng, 4): rand_value(rng, 2) for _ in range(rng.randrange(4))}
        stage = rng.choice([None, "", "score", rand_str(rng, 3)])
        mid, compat = rand_str(rng, 6), rand_str(rng, 3)
        if any(0xd800 <= ord(ch) < 0xe000 for ch in mid + compat + (stage or "")):
            continue
        py = outcome(keys.job_key, mid, compat, json.loads(json.dumps(inputs)), stage)
        rs = outcome(oc.job_key, mid, compat, json.dumps(inputs), stage)
        same(py, rs, f"job_key #{i}")
    assert oc.job_key("dev.x.y", "c", '{"n": 3}') == oc.job_key("dev.x.y", "c", '{"n": 3.0}')


# ---------------------------------------------------------------------------- portable paths and platform tokens

def py_path(p, dot):
    return outcome(portable.check_portable_path, p, dot)


def rs_path(p, dot):
    return outcome(oc.check_portable_path, p, dot)


def test_portable_path_vectors():
    v = json.loads((SPEC / "vectors" / "portable-path.json").read_text())
    for p in v["accept"]:
        assert oc.check_portable_path(p) == p
    for p in v["accept_with_dotfiles"]:
        assert oc.check_portable_path(p, True) == p and rs_path(p, False)[0] == "err"
    for p in v["reject"]:
        for dot in (False, True):
            same(py_path(p, dot), rs_path(p, dot), p, messages=p.isascii())


def rand_path(rng):
    atoms = ["a", "B", "x.txt", ".env", "..", ".", "", "con", "CON.txt", "lpt9", "COM1.log", "aux", "conin$", "nul.",
             "trail.", "trail ", "sp ace", "q?", "a*", "|", "<", ">", '"', "'", ":", "\\", "\n", "\t", "\x00", "\x7f",
             "é", "x" * 101, "y" * 60, "dir.", "A-b_c+d@e", "@", "+", "-", "_", "x..y", "..x", "...", "~", "%"]
    n = rng.randrange(1, 6)
    segs = ["".join(rng.choice(atoms) for _ in range(rng.randrange(1, 3))) for _ in range(n)]
    p = "/".join(segs)
    if rng.random() < 0.1:
        p = "/" + p
    if rng.random() < 0.05:
        p = "".join(chr(rng.randrange(0x20, 0x7f)) for _ in range(rng.randrange(1, 12)))
    return p


def test_portable_path_random():
    rng = random.Random(SEED + 3)
    for i in range(N * 2):
        p, dot = rand_path(rng), rng.random() < 0.5
        py, rs = py_path(p, dot), rs_path(p, dot)
        if py != rs and rs[0] == "err" and any(seg.endswith("\n") for seg in p.split("/")):
            # Python let a "seg\n" segment through, so it accepts or fails later (with another message)
            assert rs[1].endswith("has a character that is not portable") or rs[1].endswith("ends with '.' or a space") \
                or "reserved device name" in rs[1], (p, rs)
            KNOWN["trailing-newline"] += 1
            continue
        same(py, rs, f"path #{i} {p!r} dot={dot}", messages=p.isascii())
        paths = [p, p.upper(), p.lower(), p.swapcase(), p]
        assert [tuple(x) for x in oc.casefold_collisions(paths)] == portable.casefold_collisions(paths) or not p.isascii()


def test_platform_tokens():
    v = json.loads((SPEC / "vectors" / "platform-token.json").read_text())
    assert all(oc.is_platform_token(p) for p in v["accept"])
    assert not any(oc.is_platform_token(p) for p in v["reject"])
    rng = random.Random(SEED + 4)
    alphabet = "abz09_-AZ.!\n "
    for _ in range(N):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 10)))
        if rng.random() < 0.3:
            s = rng.choice(["darwin", "linux", "x1", "Linux"]) + "-" + rng.choice(["arm64", "amd64", "riscv_64", "", "A"]) + rng.choice(["", "\n", "-x"])
        py, rs = portable.is_platform_token(s), oc.is_platform_token(s)
        if py and not rs and s.endswith("\n") and portable.is_platform_token(s[:-1]):
            KNOWN["trailing-newline"] += 1
            continue
        assert py == rs, repr(s)
    assert oc.is_platform_token(portable.host_platform())


# ---------------------------------------------------------------------------- bundle digests

def test_content_digest():
    rng = random.Random(SEED + 5)
    modes = ["644", "755", "0o644", "0O755", "0644", " 6_44 ", 420, 493, 420.9, 493.0, "600", "100644", "rw-", True,
             None, 644, "", "0o_755", "+644", "-644"]
    for i in range(N // 2):
        files = []
        for _ in range(rng.randrange(0, 6)):
            path = rng.choice(["README.md", "a", "B", "é", "a/b", "z", rand_str(rng, 5)])
            if any(0xd800 <= ord(ch) < 0xe000 for ch in path):
                path = "s"
            files.append({"path": path, "sha256": rng.choice(["ab" * 32, "x", ""]), "mode": rng.choice(modes)})
        py = outcome(bundle.content_digest, files)
        rs = outcome(oc.content_digest, json.dumps(files))
        same(py, rs, f"digest #{i} {files!r}")


# ---------------------------------------------------------------------------- sandbox profiles

def test_sandbox_goldens_and_shapes():
    golden = SPEC / "sandbox" / "backends" / "macos-golden"
    for c in json.loads((golden / "cases.json").read_text()):
        want = (golden / f"{c['name']}.sb").read_text()
        got = oc.render_sandbox_text(c["kind"], c["ro"], c["rw"], c["links"], c["net"], c["broker"], c["gpu"],
                                     c.get("proxy_port"), c.get("exec_rw", False))
        assert got == want, c["name"]
    for kind in ("runner", "service", "coordinator", "doctor"):
        for n_ro in (0, 1, 3):
            for n_rw in (0, 2):
                for n_links in (0, 1, 12):
                    for net in ("none", "egress-allowlist", "egress-any", "open"):
                        for port in (None, 0, 1, 47001, 65535):
                            for flags in range(8):
                                broker, gpu, exec_rw = bool(flags & 1), bool(flags & 2), bool(flags & 4)
                                a = (kind, n_ro, n_rw, n_links, net, broker, gpu, port, exec_rw)
                                same(outcome(sandbox.render_text, *a), outcome(oc.render_sandbox_text, *a), str(a), messages=True)


# ---------------------------------------------------------------------------- egress allow list and addresses

def test_egress_allowed():
    allow = ["api.example.org", "*.files.example.org:8443"]
    for host, port, ok in [("api.example.org", 443, True), ("api.example.org", 80, False),
                           ("x.files.example.org", 8443, True), ("files.example.org", 8443, False),
                           ("evil.example.org", 443, False), ("127.0.0.1", 443, False), ("[::1]", 443, False),
                           ("API.Example.org.", 443, True)]:
        assert oc.egress_allowed(allow, host, port) is ok is egress_proxy.allowed(allow, host, port)
    rng = random.Random(SEED + 6)
    hosts = ["api.example.org", "API.example.org.", "x.files.example.org", "files.example.org", "localhost", "a.b.c",
             "127.0.0.1", "[::1]", "::1", "1.2.3.4", "01.2.3.4", "[fe80::1%en0]", "fe80::1%en0", "1.2.3", "", ".",
             "example.org..", "*.example.org", "xn--bcher-kva.example", "Ünï.example", "[[1.2.3.4]]", "1::2::3"]
    entries = ["api.example.org", "*.files.example.org:8443", "*.example.org", "localhost:5000", " API.example.org:80 ",
               "h:abc", "h:", "x: 4_43", "*.:443", "[::1]:443", "1.2.3.4", "example.org:+443", "a.b.c:0443",
               "Ünï.example", "*.b.c"]
    for i in range(N):
        allow = rng.sample(entries, rng.randrange(0, 4))
        host = rng.choice(hosts)
        port = rng.choice([443, 80, 8443, 5000, 0, 65535, rng.randrange(65536)])
        same(outcome(egress_proxy.allowed, allow, host, port), outcome(oc.egress_allowed, allow, host, port),
             f"allowed #{i} {allow!r} {host!r}:{port}")


def test_ip_is_global():
    rng = random.Random(SEED + 7)
    samples = ["0.0.0.0", "127.0.0.1", "100.64.0.1", "192.0.0.9", "192.0.0.10", "192.0.0.11", "192.0.0.170",
               "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8", "::ffff:10.0.0.1", "2001:1::1",
               "2001:1::3", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1", "2001:40::1", "64:ff9b::1",
               "64:ff9b:1::1", "fe80::1%en0", "ff02::1", "3fff::1", "4000::1", "2002::1"]
    for _ in range(N):
        k = rng.randrange(4)
        if k == 0:
            samples.append(str(ipaddress.IPv4Address(rng.getrandbits(32))))
        elif k == 1:
            samples.append(str(ipaddress.IPv6Address(rng.getrandbits(128))))
        elif k == 2:   # inside the special registries, where the edges are
            net = rng.choice(ipaddress.IPv4Address._constants._private_networks + ipaddress.IPv6Address._constants._private_networks
                             + ipaddress.IPv6Address._constants._private_networks_exceptions)
            samples.append(str(net.network_address + rng.randrange(min(net.num_addresses, 2**64))))
        else:
            samples.append("::ffff:" + str(ipaddress.IPv4Address(rng.getrandbits(32))))
    for s in samples:
        same(outcome(lambda x: ipaddress.ip_address(x).is_global, s), outcome(oc.ip_is_global, s), s)
    # parsing: random strings over the address alphabet
    for _ in range(N):
        s = "".join(rng.choice("0123456789abcdefABCDEFg:.%/x ") for _ in range(rng.randrange(0, 20)))
        if rng.random() < 0.3:
            s = ":".join(rng.choice(["", "0", "1", "ffff", "12345", "1.2.3.4"]) for _ in range(rng.randrange(1, 10)))
        same(outcome(lambda x: ipaddress.ip_address(x).is_global, s), outcome(oc.ip_is_global, s), repr(s))


# ---------------------------------------------------------------------------- wheels and requirements

PLATFORMS = ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-arm64", "windows-amd64",
             "linux-riscv64", "darwin-riscv", "plan9-mips", "darwin", ""]


def test_wheel_fits():
    rng = random.Random(SEED + 8)
    dists = ["dep", "Foo_Bar", "a.b", "x"]
    pys = ["py3", "py2.py3", "cp312", "cp311", "cp39", "cp313", "cp3", "cp310.cp311", "pp310", "py312", "cpx"]
    abis = ["none", "abi3", "cp312", "cp311", "none.abi3"]
    plats = ["any", "macosx_11_0_arm64", "macosx_10_9_x86_64", "macosx_10_9_universal2", "macosx_10_9_intel",
             "manylinux_2_17_x86_64.manylinux2014_x86_64", "musllinux_1_2_aarch64", "linux_riscv64", "win_amd64",
             "win_arm64", "win32", "manylinux_2_28_aarch64"]
    names = ["dep-1.0-py3-none.whl", "dep-1.0-b-py3-none-any.whl", "dep--py3-none-any.whl", "dep-1.0-py3-none-any.zip",
             "dep-1-2-3-py3-none-any.whl", "dep-1.0-py3-none-.whl", "dep-1.0-py3-none-any.whl.whl"]
    for _ in range(N):
        build = rng.choice(["", "", "-1", "-2b", "-x"])
        names.append(f"{rng.choice(dists)}-{rng.choice(['1.0', '2!1+l'])}{build}-{rng.choice(pys)}-{rng.choice(abis)}-{rng.choice(plats)}.whl")
    for name in names:
        for plat in PLATFORMS:
            assert oc.wheel_fits(name, plat) == deps.wheel_fits(name, plat), (name, plat)
    n = "dep-1.0-py3-none-any.whl\n"
    assert deps.wheel_fits(n, "linux-amd64") and not oc.wheel_fits(n, "linux-amd64")
    KNOWN["trailing-newline"] += 1


def test_parse_requirements():
    rng = random.Random(SEED + 9)
    h = ["0" * 64, "f" * 64, "a" * 63, "A" * 64, "0123456789abcdef" * 4 + "0"]
    lines = ["", "# comment", "   ", "a==1", "Foo_Bar.baz[extra]==1.0.post1", "pydantic==2", "typing_extensions==4",
             "a>=1", "-e .", "--extra-index-url https://x", "a==1 ; python_version>'3'", "a[x==1", "a==", "a == 1",
             "!!", "é==1", "q==2!3+local", "x==1  # via y", "1abc==0", "a==1;x"]
    for i in range(N):
        out = []
        for _ in range(rng.randrange(1, 5)):
            line = rng.choice(lines)
            for _ in range(rng.randrange(0, 3)):
                line += rng.choice([" --hash=sha256:", " \\\n    --hash=sha256:", " --hash=sha512:", "--hash=sha256:"]) + rng.choice(h)
            line += rng.choice(["", " # c", "\t", " \\"])
            out.append(line)
        text = rng.choice(["\n", "\r\n", "\r", "\x0c"]).join(out) + rng.choice(["", "\n"])
        py = outcome(lambda t: [(r["name"], r["version"], sorted(r["hashes"])) for r in deps.parse_requirements(t)], text)
        rs = outcome(lambda t: [(n, v, list(hs)) for n, v, hs in oc.parse_requirements(t)], text)
        same(py, rs, f"requirements #{i} {text!r}", messages=text.isascii())


def test_image_signatures():
    """Container set signatures: the shared vectors, then random tampering of valid signatures and documents."""
    import base64
    v = json.loads((SPEC / "vectors" / "image-signatures.json").read_text())
    pem, reg, repo = v["keys"][0]["pem"], v["set"]["registry"], v["set"]["repository"]
    assert oc.image_key_sha256(pem) == images.key_sha256(pem)
    covers = lambda r: r.partition("/")[0] == reg and r.partition("/")[2].startswith(repo)
    q = images.public_key(pem)
    for c in v["simple"]:
        payload = base64.b64decode(c["payload_b64"])
        r = oc.image_check_simple(pem, payload, c["signature_b64"], c["digest"], reg, repo)
        assert (r is None) == (images.check_simple_signing(q, payload, c["signature_b64"], c["digest"], covers) is None) == c["ok"]
    for c in v["bundle"]:
        b = base64.b64decode(c["bundle_b64"])
        assert (oc.image_check_bundle(pem, b, c["digest"]) is None) == (images.check_bundle(q, b, c["digest"]) is None) == c["ok"]
    for c in v["normalize"]:
        assert outcome(oc.image_normalize, c["ref"])[0] == outcome(images.normalize, c["ref"])[0]
        if not c.get("error"):
            assert oc.image_normalize(c["ref"]) == images.normalize(c["ref"])
    rng = random.Random(SEED)
    key = imagetest.Key.from_seed(b"parity")
    kpem = key.public_pem()
    for i in range(min(N, 400)):
        digest = "sha256:" + "%064x" % rng.getrandbits(256)
        b = bytearray(imagetest.bundle(key, f"{reg}/{repo}t{i}@{digest}", digest))
        if rng.random() < 0.5:
            b[rng.randrange(len(b))] = rng.randrange(256)
        b = bytes(b)
        want = outcome(images.check_bundle, images.public_key(kpem), b, digest)
        got = outcome(oc.image_check_bundle, kpem, b, digest)
        assert (want[0], want[1] is None) == (got[0], got[1] is None), (i, want, got)
        doc = bytearray(images.index_document(reg, repo, rng.randrange(100), [digest]))
        if rng.random() < 0.5:
            doc[rng.randrange(len(doc))] = rng.randrange(256)
        assert outcome(images.parse_index, bytes(doc), reg, repo)[0] == outcome(oc.image_parse_index, bytes(doc), reg, repo)[0]


def test_version():
    assert oc.version().startswith("1.")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, f in tests:
        f()
        print(f"ok   {name}")
    print(f"{len(tests)} passed; known differences exercised: {KNOWN}")
    sys.exit(0)
