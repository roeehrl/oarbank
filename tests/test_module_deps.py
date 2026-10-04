"""Module dependencies (oarbank-sdk spec/bundles.md, "Dependencies"): hash-pinned wheels shipped in the bundle,
installed offline inside the sandbox; anything that could run code at install is refused."""
import base64
import hashlib
import shutil
import zipfile
from pathlib import Path

import pytest

from helpers import TOY_DIR, make_db
from oarbank.coordinator import modstore
from oarbank_sdk import bundle as B
from oarbank_sdk import deps


def make_wheel(d: Path, name="tinydep", version="1.0", value=42) -> Path:
    files = {f"{name}/__init__.py": f"VALUE = {value}\n".encode(),
             f"{name}-{version}.dist-info/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
             f"{name}-{version}.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    rec = [f"{p},sha256={base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('=')},{len(b)}"
           for p, b in files.items()] + [f"{name}-{version}.dist-info/RECORD,,"]
    files[f"{name}-{version}.dist-info/RECORD"] = ("\n".join(rec) + "\n").encode()
    d.mkdir(parents=True, exist_ok=True)
    out = d / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(out, "w") as z:
        for p, b in files.items():
            z.writestr(p, b)
    return out


def module_with_deps(tmp_path, version="0.3.0", req=None) -> Path:
    src = tmp_path / "toy-deps"
    shutil.copytree(TOY_DIR, src)
    m = (src / "oarbank-module.toml").read_text().replace('version = "0.1.0"', f'version = "{version}"', 1)
    (src / "oarbank-module.toml").write_text(m)
    w = make_wheel(src / "wheels")
    h = hashlib.sha256(w.read_bytes()).hexdigest()
    (src / "requirements.txt").write_text(req if req is not None else f"tinydep==1.0 \\\n    --hash=sha256:{h}\n")
    return src


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def test_requirements_must_pin_every_distribution_by_hash():
    ok = deps.parse_requirements("a==1.0 --hash=sha256:" + "a" * 64 + "\n# c\nb-c==2 \\\n --hash=sha256:" + "b" * 64)
    assert [(r["name"], r["version"]) for r in ok] == [("a", "1.0"), ("b-c", "2")]
    for bad in ("a==1.0", "a>=1 --hash=sha256:" + "a" * 64, "--index-url https://evil.example/simple",
                "-e git+https://x/y", "a==1; sys_platform=='darwin' --hash=sha256:" + "a" * 64,
                "pydantic==2.9 --hash=sha256:" + "a" * 64):
        with pytest.raises(deps.DepsError):
            deps.parse_requirements(bad)


@pytest.mark.parametrize("name,plat,ok", [
    ("x-1-py3-none-any.whl", "windows-arm64", True),
    ("x-1-cp312-cp312-macosx_11_0_arm64.whl", "darwin-arm64", True),
    ("x-1-cp312-cp312-macosx_11_0_arm64.whl", "darwin-amd64", False),
    ("x-1-cp38-abi3-macosx_10_9_universal2.whl", "darwin-amd64", True),
    ("x-1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "linux-amd64", True),
    ("x-1-cp312-cp312-manylinux_2_17_aarch64.whl", "linux-amd64", False),
    ("x-1-cp311-cp311-win_amd64.whl", "windows-amd64", False),
    ("x-1-cp312-cp312-win_amd64.whl", "windows-amd64", True),
])
def test_wheel_tags_per_platform(name, plat, ok):
    assert deps.wheel_fits(name, plat) is ok


def test_build_refuses_missing_wheels_wrong_hashes_and_sdists(tmp_path):
    src = module_with_deps(tmp_path)
    B.build(src, tmp_path / "ok.mfb")                                              # complete: builds
    (src / "requirements.txt").write_text("tinydep==1.0 --hash=sha256:" + "0" * 64 + "\n")
    with pytest.raises(B.BundleError, match="matches none of its hashes"):
        B.build(src, tmp_path / "bad.mfb")
    (src / "requirements.txt").write_text("other==2.0 --hash=sha256:" + "0" * 64 + "\n")
    with pytest.raises(B.BundleError, match="no wheel"):
        B.build(src, tmp_path / "bad.mfb")
    (src / "wheels" / "evil-1.0.tar.gz").write_bytes(b"setup.py runs code")
    with pytest.raises(B.BundleError, match="only .whl"):
        B.build(src, tmp_path / "bad.mfb")


@pytest.mark.skipif(not shutil.which("uv"), reason="needs uv")
def test_install_builds_the_environment_offline_inside_the_sandbox(db, tmp_path):
    src = module_with_deps(tmp_path)
    out, _ = B.build(src, tmp_path / "toy-0.3.0.mfb")
    r = modstore.install(db, out, actor="test", self_test=True)
    venv = Path(r["path"]) / ".venv"
    site = next(venv.glob("lib/python*/site-packages"))
    assert (site / "tinydep" / "__init__.py").read_text() == "VALUE = 42\n"
    assert modstore.record(db, "toy", "0.3.0")["runtime"] == "venv+wheels"


def test_install_refuses_unpinned_requirements_even_in_a_hand_made_bundle(db, tmp_path, monkeypatch):
    src = module_with_deps(tmp_path, "0.4.0")
    out, _ = B.build(src, tmp_path / "toy-0.4.0.mfb")
    dest = tmp_path / "unpacked"
    B.verify(out, dest)
    (dest / "requirements.txt").write_text("tinydep>=1.0\n")                         # tampered after the build check
    with pytest.raises(modstore.InstallError, match="requirements.txt"):
        modstore._build_runtime(dest)


@pytest.mark.skipif(not shutil.which("uv"), reason="needs uv")
def test_a_venv_an_earlier_coordinator_build_made_is_rebuilt_on_this_interpreter(db, tmp_path):
    """An in-place coordinator update leaves the previous build (and its Python) beside the new one, so a module venv
    made at install still resolves, to the old interpreter, which the module sandbox does not grant: the module could
    not start until its venv is rebuilt on the running interpreter (oarbankd does it at every start)."""
    import os
    import sys
    from oarbank.coordinator import modlife
    from oarbank.platform import files
    src = module_with_deps(tmp_path, "0.5.0")
    out, _ = B.build(src, tmp_path / "toy-0.5.0.mfb")
    venv = Path(modstore.install(db, out, actor="test", self_test=False)["path"]) / ".venv"
    py = files.venv_python(venv)
    assert py.resolve() == Path(sys.executable).resolve()
    assert modlife.runtimes_ok(db) == []                                 # this build's venv: left alone
    old = tmp_path / "coordinator-app" / "0.1.0-earlier" / "python" / "bin" / "python3.12"   # the earlier build's Python
    old.parent.mkdir(parents=True)
    shutil.copyfile(sys.executable, old)
    py.unlink()
    os.symlink(old, py)
    assert modlife.runtimes_ok(db) == ["toy@0.5.0"]
    assert files.venv_python(venv).resolve() == Path(sys.executable).resolve()
    site = next(venv.glob("lib/python*/site-packages"))
    assert (site / "tinydep" / "__init__.py").read_text() == "VALUE = 42\n"
    assert db.one("SELECT reason FROM events WHERE kind='module_runtime_rebuilt'")["reason"] == "toy@0.5.0"
    shutil.rmtree(venv)                                                  # gone altogether (a move): rebuilt too
    assert modlife.runtimes_ok(db) == ["toy@0.5.0"]
