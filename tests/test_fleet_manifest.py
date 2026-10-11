"""scripts/fleet-manifest.py (PLAN D56; docs/design/fleet-updates.md, "The fleet release manifest"): every release asset
classified by its name, the canonical bytes that are signed, seq, stops and agent_min."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "fleet-manifest.py"
_spec = importlib.util.spec_from_file_location("fleet_manifest", SCRIPT)
fm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fm)

# a release's assets as the packaging scripts name them (the v2.8.0 release's list, at 2.10.0)
V = "2.10.0"
RELEASE = {
    "install-oarbankd.ps1": None,
    "install-oarbankd.sh": None,
    f"oarbank-agent-{V}-1.aarch64.rpm": ("node", "linux-arm64", "rpm"),
    f"oarbank-agent-{V}-1.x86_64.rpm": ("node", "linux-amd64", "rpm"),
    f"oarbank-agent-{V}-darwin-amd64": ("agent", "darwin-amd64", "binary"),
    f"oarbank-agent-{V}-darwin-arm64": ("agent", "darwin-arm64", "binary"),
    f"oarbank-agent-{V}-linux-amd64": ("agent", "linux-amd64", "binary"),
    f"oarbank-agent-{V}-linux-amd64.tar.gz": ("node", "linux-amd64", "tar"),
    f"oarbank-agent-{V}-linux-arm64": ("agent", "linux-arm64", "binary"),
    f"oarbank-agent-{V}-linux-arm64.tar.gz": ("node", "linux-arm64", "tar"),
    f"oarbank-agent-{V}-macos-arm64.pkg": ("node", "darwin-arm64", "pkg"),
    f"oarbank-agent-{V}-macos-x86_64.pkg": ("node", "darwin-amd64", "pkg"),
    f"oarbank-agent-{V}-windows-admx.zip": None,
    f"oarbank-agent-{V}-windows-arm64.exe": ("agent", "windows-arm64", "binary"),
    f"oarbank-agent-{V}-windows-arm64.msi": ("node", "windows-arm64", "msi"),
    f"oarbank-agent-{V}-windows-x64.exe": ("agent", "windows-amd64", "binary"),
    f"oarbank-agent-{V}-windows-x64.msi": ("node", "windows-amd64", "msi"),
    f"oarbank-agent_{V}_amd64.deb": ("node", "linux-amd64", "deb"),
    f"oarbank-agent_{V}_arm64.deb": ("node", "linux-arm64", "deb"),
    f"oarbank-coordinator-{V}-darwin-arm64.tar.gz": ("coordinator", "darwin-arm64", "tar"),
    f"oarbank-coordinator-{V}-linux-amd64.deb": None,
    f"oarbank-coordinator-{V}-linux-amd64.rpm": None,
    f"oarbank-coordinator-{V}-linux-amd64.tar.gz": ("coordinator", "linux-amd64", "tar"),
    f"oarbank-coordinator-{V}-linux-arm64.deb": None,
    f"oarbank-coordinator-{V}-linux-arm64.rpm": None,
    f"oarbank-coordinator-{V}-linux-arm64.tar.gz": ("coordinator", "linux-arm64", "tar"),
    f"oarbank-coordinator-{V}-macos-arm64.pkg": None,
    f"oarbank-coordinator-{V}-windows-amd64.tar.gz": ("coordinator", "windows-amd64", "tar"),
    f"oarbank-coordinator-{V}-windows-arm64.msi": None,
    f"oarbank-coordinator-{V}-windows-arm64.tar.gz": ("coordinator", "windows-arm64", "tar"),
    f"oarbank-coordinator-{V}-windows-x64.msi": None,
    "oarbank-install.ps1": None,
    "oarbank-install.sh": None,
    f"SHA256SUMS-agent-{V}-darwin-amd64": None,
    f"SHA256SUMS-agent-{V}-linux-amd64": None,
    f"SHA256SUMS-coordinator-{V}-darwin-arm64": None,
    f"SHA256SUMS-coordinator-msi-{V}-windows-x64": None,
    f"SHA256SUMS-coordinator-packages-{V}-linux-amd64": None,
    f"SHA256SUMS-install-{V}": None,
    # another version's files in the same directory
    "oarbank-agent_2.9.0_amd64.deb": None,
    "oarbank-agent-2.10.01-darwin-arm64": None,
    "oarbank-agent-2.10.0-rc.1-darwin-arm64": None,
    f"oarbank-fleet-{V}.json": None,
}


def test_every_asset_of_a_release_is_classified_by_its_name():
    for name, want in RELEASE.items():
        got = fm.classify(name, V)
        assert (got and (got["role"], got["platform"], got["format"])) == (want or None), name


def test_the_packaging_scripts_write_the_names_it_classifies():
    # the names come from these lines; a renamed asset must be renamed here too
    text = {p: (REPO / p).read_text(encoding="utf-8") for p in (
        "scripts/package-macos.sh", "scripts/package-linux.sh", "scripts/package-windows.ps1", "scripts/build-coordinator.sh",
        "scripts/build-coordinator.ps1", "deploy/linux/nfpm.yaml")}
    assert 'PKG="$OUT/oarbank-agent-$VERSION-macos-$ARCH.pkg"' in text["scripts/package-macos.sh"]
    assert 'cp "$PAYLOAD/oarbank-agent" "$OUT/oarbank-agent-$VERSION-$PLATFORM"' in text["scripts/package-macos.sh"]
    assert '"$OUT/oarbank-agent-$VERSION-linux-$ARCH.tar.gz"' in text["scripts/package-linux.sh"]
    assert 'cp "$BIN_DIR/oarbank-agent" "$OUT/oarbank-agent-$VERSION-linux-$ARCH"' in text["scripts/package-linux.sh"]
    assert "name: oarbank-agent\n" in text["deploy/linux/nfpm.yaml"]     # nFPM's own deb and rpm file names
    assert '$Msi = "$Out\\oarbank-agent-$Version-windows-$Arch.msi"' in text["scripts/package-windows.ps1"]
    assert '"$Out\\oarbank-agent-$Version-windows-$Arch.exe"' in text["scripts/package-windows.ps1"]
    assert 'TGZ="$OUT/oarbank-coordinator-$VERSION-$PLATFORM.tar.gz"' in text["scripts/build-coordinator.sh"]
    assert '"$Out\\oarbank-coordinator-$Version-$Platform.tar.gz"' in text["scripts/build-coordinator.ps1"]


def test_a_pre_release_deb_and_rpm_carry_nfpms_tilde():
    v = "2.10.0-rc.1"
    assert fm.classify("oarbank-agent_2.10.0~rc.1_amd64.deb", v)["format"] == "deb"
    assert fm.classify("oarbank-agent-2.10.0~rc.1-1.x86_64.rpm", v)["platform"] == "linux-amd64"
    assert fm.classify("oarbank-agent-2.10.0-rc.1-macos-arm64.pkg", v)["format"] == "pkg"
    assert fm.classify("oarbank-agent_2.10.0_amd64.deb", v) is None


def _dist(tmp_path, names=RELEASE):
    d = tmp_path / "dist"
    d.mkdir()
    for i, name in enumerate(names):
        (d / name).write_bytes(name.encode() * (i + 1))
    return d


def test_the_manifest_lists_each_artifact_with_its_hash_and_size(tmp_path):
    d = _dist(tmp_path)
    m = fm.manifest(V, d, released_at="2026-10-20T00:00:00Z")
    assert {k: m[k] for k in ("type", "format", "version", "seq", "released_at", "expires", "agent_min", "stops")} == {
        "type": "oarbank-fleet-release", "format": 1, "version": V, "seq": 21000,
        "released_at": "2026-10-20T00:00:00Z", "expires": None, "agent_min": "2.9.0", "stops": []}
    assert m["notes"] == "https://github.com/roeehrl/oarbank/releases/tag/v2.10.0"
    want = {n: w for n, w in RELEASE.items() if w}
    assert {a["name"] for a in m["artifacts"]} == set(want)
    for a in m["artifacts"]:
        data = (d / a["name"]).read_bytes()
        assert (a["role"], a["platform"], a["format"]) == want[a["name"]]
        assert a["sha256"] == hashlib.sha256(data).hexdigest() and a["size"] == len(data)
        assert a.get("agent_version") == (V if a["role"] in ("node", "agent") else None)
    # ordered by role, platform, format: the same directory always gives the same bytes
    keys = [(a["role"], a["platform"], a["format"]) for a in m["artifacts"]]
    assert keys == sorted(keys)


def test_the_canonical_bytes_are_sorted_compact_ascii_without_a_newline(tmp_path):
    m = fm.manifest(V, _dist(tmp_path), released_at="0", notes="https://example.test/né")
    b = fm.canonical(m)
    assert b == json.dumps(json.loads(b), sort_keys=True, separators=(",", ":")).encode()
    assert not b.endswith(b"\n") and b.isascii() and b"\\u00e9" in b and b": " not in b and b", " not in b
    assert b.startswith(b'{"agent_min":"2.9.0","artifacts":[{"agent_version":"2.10.0","format":"binary","name":')
    assert m["released_at"] == "1970-01-01T00:00:00Z"


def test_the_command_writes_exactly_the_canonical_bytes(tmp_path):
    d = _dist(tmp_path)
    out = tmp_path / "m.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "v" + V, str(d), "--seq", "7", "--agent-min", "2.8.1",
                        "--stops", "2.9.0, 2.8.5", "--out", str(out), "--expires", "2027-01-01T00:00:00Z"],
                       capture_output=True, text=True, env={"SOURCE_DATE_EPOCH": "1760000000", "PATH": ""})
    assert r.returncode == 0, r.stderr
    data = out.read_bytes()
    m = json.loads(data)
    assert data == fm.canonical(m)
    assert (m["seq"], m["agent_min"], m["stops"], m["expires"]) == (7, "2.8.1", ["2.8.5", "2.9.0"], "2027-01-01T00:00:00Z")
    assert m["released_at"] == "2025-10-09T08:53:20Z"
    assert hashlib.sha256(data).hexdigest() in r.stdout
    # the default place: beside the assets, under the name the signatures and the TUF target use
    r = subprocess.run([sys.executable, str(SCRIPT), V, str(d)], capture_output=True, text=True)
    assert r.returncode == 0 and (d / f"oarbank-fleet-{V}.json").is_file()
    assert sorted(p.name for p in d.iterdir() if p.name.endswith(".tmp")) == []


def test_seq_rises_with_every_version_and_refuses_what_would_overlap():
    assert fm.default_seq("2.10.0") == 21000 and fm.default_seq("2.9.3") == 20903 and fm.default_seq("0.0.1") == 1
    assert fm.default_seq("2.10.0-rc.1") == 21000
    assert fm.default_seq("2.10.99") < fm.default_seq("2.11.0") < fm.default_seq("3.0.0")
    with pytest.raises(ValueError, match="--seq"):
        fm.default_seq("2.10.100")
    assert fm.default_agent_min("2.10.0") == "2.9.0" and fm.default_agent_min("3.0.4") == "3.0.0"


@pytest.mark.parametrize("args,why", [
    (["not-a-version"], "not a version"),
    ([V, "--stops", "2.10.0"], "not older"),
    ([V, "--stops", "2.x"], "not a version"),
    ([V, "--seq", "-1"], "negative"),
    ([V, "--expires", "2027-01-01T00:00:00"], "time zone"),
    (["9.9.9"], "no artifact"),
])
def test_refusals(tmp_path, args, why):
    d = _dist(tmp_path, [n for n, w in RELEASE.items() if w])
    r = subprocess.run([sys.executable, str(SCRIPT), args[0], str(d), *args[1:]], capture_output=True, text=True)
    assert r.returncode == 2 and why in r.stderr, r.stderr
    assert not list(d.glob("oarbank-fleet-*"))


def test_two_assets_for_one_platform_and_format_are_refused(tmp_path):
    d = _dist(tmp_path, [f"oarbank-agent-{V}-1.x86_64.rpm", f"oarbank-agent-{V}-2.x86_64.rpm"])
    with pytest.raises(ValueError, match="both the rpm node for linux-amd64"):
        fm.manifest(V, d)


# ---------------------------------------------------------------------------------------------------------------------
# CI: the manifest beside a release's assets, and the packages updated through the runner on free runners


def test_ci_writes_the_manifest_from_every_package_jobs_assets():
    ci = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = ci[ci.index("\n  fleet-manifest:"):]
    assert "needs: [package, package-linux, package-windows]" in job
    assert "merge-multiple: true" in job and "pattern: oarbank-${{ env.VERSION || github.sha }}-*-unsigned" in job
    assert 'python3 scripts/fleet-manifest.py "$v" dist --out "oarbank-fleet-$v.json"' in job
    assert "name: oarbank-${{ env.VERSION || github.sha }}-fleet-manifest" in job


def test_ci_updates_each_os_package_through_the_runner():
    fleet = (REPO / ".github/workflows/fleet-update.yml").read_text(encoding="utf-8")
    assert "runs-on: ubuntu-24.04" in fleet and "scripts/ci-fleet-update-linux.sh --build" in fleet
    mac = fleet[fleet.index("macos-pkg-update:"):]
    # macOS runners queue long: tags and by hand only
    assert "if: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'" in mac
    assert "scripts/ci-fleet-update-macos.sh" in mac and "OARBANK_INSTALLER_IDENTITY" not in fleet
    msi = (REPO / ".github/workflows/msi.yml").read_text(encoding="utf-8")
    assert "scripts/ci-fleet-update-windows.ps1 -First dist/oarbank-agent-2.5.900-windows-x64.msi" in msi
    for script in ("ci-fleet-update-linux.sh", "ci-fleet-update-macos.sh"):
        assert subprocess.run(["bash", "-n", str(REPO / "scripts" / script)]).returncode == 0, script
    linux = (REPO / "scripts/ci-fleet-update-linux.sh").read_text(encoding="utf-8")
    for needle in ("debian:stable", "fedora:latest", '"$L" update-trust --unsigned',
                   '"$L" update-run --once --probation-s 5', "step unconfirmed no \"$pkg2\" rolled_back \"$v1\""):
        assert needle in linux, needle
    win = (REPO / "scripts/ci-fleet-update-windows.ps1").read_text(encoding="utf-8")
    assert 'Step "unconfirmed" $Second $false "rolled_back" $v1' in win and '"--probation-s", "5"' in win
