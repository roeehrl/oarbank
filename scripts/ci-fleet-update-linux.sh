#!/usr/bin/env bash
# Fleet updates of the Linux packages through the update runner (PLAN D57; docs/design/fleet-updates.md, "Packages in
# CI"), in throwaway containers: Debian for the deb, Fedora for the rpm, no systemd (the runner runs by hand, as its
# oneshot unit would run it). In each container:
#   1. the first version installed by hand (dpkg -i, rpm -i), its postinstall setting the node up without a service, and
#      root's update trust set to `unsigned` (update-trust --unsigned: no owner key in a test fleet);
#   2. a request for the first version again, confirmed: the runner now keeps that package;
#   3. a request for the second version that no agent confirms: probation (5 s here) fails, the runner reinstalls the
#      package it kept and points `current` back (result rolled_back; the package database says the first version);
#   4. the second version again, confirmed (result done; the package database and `current` say the second version).
# The test plays the agent: it writes the spool's package and request.json (built here from fleet-manifest.py's
# manifest), and the confirmation the new agent would write after its first hello and heartbeat.
#
#   scripts/ci-fleet-update-linux.sh [--build] [--dist DIR] [--formats "deb rpm"] V1 V2
#
# --build makes both versions' packages first (scripts/package-linux.sh, which needs nFPM). Needs docker (or podman as
# `docker`) and python3; runs as anyone who may run containers, and changes nothing outside them but DIR (with --build).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == --inside ]]; then
    # ---- in the container, as root: --inside FORMAT PKG1 PKG2 V1 V2 ----
    fmt="$2" pkg1="$3" pkg2="$4" v1="$5" v2="$6"
    L=/usr/lib/oarbank/oarbank-launcher
    AGENT=/var/lib/oarbank/agent
    SPOOL="$AGENT/updates"
    STATE=/var/lib/oarbank/update
    fail() {
        echo "FAIL $*" >&2
        for f in /tmp/runner.log "$SPOOL/result.json" "$STATE/journal.json" "$STATE"/logs/*; do
            [[ -f "$f" ]] && { echo "--- $f" >&2; cat "$f" >&2; }
        done
        exit 1
    }
    installed() {
        if [[ "$fmt" == deb ]]; then dpkg-query -W -f '${Version}' oarbank-agent; else rpm -q --qf '%{VERSION}' oarbank-agent; fi
    }
    state_is() { grep -Eq "\"state\"[[:space:]]*:[[:space:]]*\"($1)\"" "$SPOOL/result.json" 2>/dev/null; }
    current_is() {
        local t
        t="$(readlink "$AGENT/current")"
        [[ "$t" == "versions/$1-"*/oarbank-agent ]] || fail "current points at $t, not $1"
    }

    if [[ "$fmt" == deb ]]; then dpkg -i "/dist/$pkg1"; else rpm -i "/dist/$pkg1"; fi
    [[ "$(installed)" == "$v1" ]] || fail "the first install is $(installed)"
    current_is "$v1"
    "$L" update-trust --unsigned

    # step NAME CONFIRM PKG WANT_STATE WANT_VERSION
    step() {
        local name="$1" confirm="$2" pkg="$3" want="$4" version="$5" id release i rc
        read -r id release < "/work/request-$name.id"
        echo "== $name: $release, $([[ $confirm == yes ]] && echo confirmed || echo never confirmed)"
        install -d -m 700 -o oarbank -g oarbank "$SPOOL"
        rm -f "$SPOOL/confirmed" "$SPOOL/result.json"
        install -m 600 -o oarbank -g oarbank "/dist/$pkg" "$SPOOL/package"
        # written last, through a rename, as the agent does
        install -m 600 -o oarbank -g oarbank "/work/request-$name.json" "$SPOOL/.request.json.tmp"
        mv "$SPOOL/.request.json.tmp" "$SPOOL/request.json"
        "$L" update-run --once --probation-s 5 > /tmp/runner.log 2>&1 &
        local runner=$!
        if [[ "$confirm" == yes ]]; then
            for ((i = 0; i < 3000; i++)); do
                state_is installed && break
                state_is "refused|failed|rolled_back" && fail "$name: the runner gave up before the install"
                kill -0 "$runner" 2>/dev/null || break
                sleep 0.2
            done
            state_is installed || fail "$name: no installed result within 600 s"
            # the new agent's confirmation, in its account
            printf '{"id":"%s","release":"%s","agent_version":"%s","at":%s}' "$id" "$release" "$release" "$(date +%s)" \
                > "$SPOOL/.confirmed.tmp"
            chown oarbank:oarbank "$SPOOL/.confirmed.tmp"
            mv "$SPOOL/.confirmed.tmp" "$SPOOL/confirmed"
        fi
        rc=0
        wait "$runner" || rc=$?
        cat /tmp/runner.log
        state_is "$want" || fail "$name: the result is not $want (runner exit $rc)"
        [[ ! -e "$SPOOL/request.json" ]] || fail "$name: the runner left the request"
        [[ "$(installed)" == "$version" ]] || fail "$name: the package database says $(installed), not $version"
        current_is "$version"
        echo "ok   $name: $want, $fmt $version installed and current"
    }
    step reinstall yes "$pkg1" "done" "$v1"
    step unconfirmed no "$pkg2" rolled_back "$v1"
    step update yes "$pkg2" "done" "$v2"
    exit 0
fi

# ---- on the host ----
BUILD="" DIST="$REPO/dist" FORMATS="deb rpm"
while [[ $# -gt 2 ]]; do
    case "$1" in
        --build) BUILD=1; shift ;;
        --dist) DIST="$2"; shift 2 ;;
        --formats) FORMATS="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
[[ $# -eq 2 ]] || { echo "usage: $0 [--build] [--dist DIR] [--formats \"deb rpm\"] V1 V2" >&2; exit 2; }
V1="$1" V2="$2"
case "$(uname -m)" in x86_64) ARCH=amd64 RPMARCH=x86_64 ;; aarch64) ARCH=arm64 RPMARCH=aarch64 ;; *) echo "unsupported arch" >&2; exit 2 ;; esac
if [[ -n "$BUILD" ]]; then
    for v in "$V1" "$V2"; do "$REPO/scripts/package-linux.sh" "$v"; done
fi
DIST="$(cd "$DIST" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-fleet-ci.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
chmod 755 "$WORK"
# each version's manifest, as CI writes it for a release (seq 1 and 2: any two versions in order)
python3 "$REPO/scripts/fleet-manifest.py" "$V1" "$DIST" --seq 1 --released-at 0 --out "$WORK/oarbank-fleet-$V1.json"
python3 "$REPO/scripts/fleet-manifest.py" "$V2" "$DIST" --seq 2 --released-at 0 --out "$WORK/oarbank-fleet-$V2.json"

for fmt in $FORMATS; do
    case "$fmt" in
        deb) image=debian:stable pkg1="oarbank-agent_${V1}_$ARCH.deb" pkg2="oarbank-agent_${V2}_$ARCH.deb" ;;
        rpm) image=fedora:latest pkg1="oarbank-agent-$V1-1.$RPMARCH.rpm" pkg2="oarbank-agent-$V2-1.$RPMARCH.rpm" ;;
        *) echo "no format $fmt (deb or rpm)" >&2; exit 2 ;;
    esac
    # the requests the agent would write (docs/design/fleet-updates.md, "Spool files"), one id each
    python3 - "$WORK" "$DIST" "$fmt" "$V1:$pkg1:1" "$V2:$pkg2:2" <<'PY'
import hashlib, json, sys, time
from pathlib import Path
work, dist, fmt = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
versions = {}
for arg in sys.argv[4:]:
    version, pkg, seq = arg.split(":")
    data = (dist / pkg).read_bytes()
    manifest = (work / f"oarbank-fleet-{version}.json").read_text(encoding="ascii")
    names = {a["name"] for a in json.loads(manifest)["artifacts"]}
    assert pkg in names, f"the {version} manifest does not name {pkg}"
    versions[version] = {"release": version, "seq": int(seq), "format": fmt, "sha256": hashlib.sha256(data).hexdigest(),
                         "size": len(data), "manifest": manifest}
(v1, a), (v2, b) = versions.items()
for name, v in (("reinstall", a), ("unconfirmed", b), ("update", b)):
    req = {"id": f"ci-{fmt}-{name}-{time.time_ns()}", **v, "signature": None, "owner_anchors": None, "rollback": False,
           "requested_at": time.time()}
    (work / f"request-{name}.json").write_text(json.dumps(req), encoding="ascii")
    (work / f"request-{name}.id").write_text(f"{req['id']} {req['release']}\n", encoding="ascii")
PY
    chmod 644 "$WORK"/*.json "$WORK"/*.id
    echo "== $fmt in $image"
    docker run --rm -v "$DIST:/dist:ro" -v "$WORK:/work:ro" -v "$REPO/scripts/ci-fleet-update-linux.sh:/ci.sh:ro" \
        "$image" bash /ci.sh --inside "$fmt" "$pkg1" "$pkg2" "$V1" "$V2"
done
echo "ok   fleet updates through the runner: $FORMATS"
