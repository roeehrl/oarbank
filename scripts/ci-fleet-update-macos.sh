#!/usr/bin/env bash
# A fleet update of the macOS pkg through the update runner (PLAN D57; docs/design/fleet-updates.md, "Packages in CI"),
# on a throwaway runner (.github/workflows/fleet-update.yml, tags and workflow_dispatch only):
#   1. the first unsigned pkg installed by hand (installer -pkg), the node laid out without a service (setup --scope
#      system --no-service: the agent's account and home), and root's update trust set to `unsigned` (no owner key in a
#      test fleet; an unsigned pkg pins no Developer ID Installer team, so the runner checks no native signature);
#   2. the test plays the agent: the second pkg and its request in the agent's spool, written last through a rename.
#      launchd starts the runner through the package's own job (dev.codonic.oarbank.agent.update, WatchPaths), which
#      installs the pkg (its postinstall finds the runner's job running and leaves it loaded), points `current` at the
#      new agent and waits; the test confirms as the new agent would;
#   3. the result is done, the pkg receipt says the second version, `current` is its agent, and the job is loaded.
# It changes the machine for good (sudo): never run it anywhere else.
#
#   scripts/ci-fleet-update-macos.sh FIRST.pkg SECOND.pkg
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo "Only for disposable GitHub Actions runners." >&2; exit 2; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIRST="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
SECOND="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
DIST="$(dirname "$FIRST")"
version_of() { [[ "$(basename "$1")" =~ ^oarbank-agent-(.+)-macos-(arm64|x86_64)\.pkg$ ]] && echo "${BASH_REMATCH[1]}"; }
V1="$(version_of "$FIRST")" V2="$(version_of "$SECOND")"
L=/Library/Oarbank/bin/oarbank-launcher
SUPPORT="/Library/Application Support/Oarbank"
AGENT="$SUPPORT/agent"
SPOOL="$AGENT/updates"
JOB=dev.codonic.oarbank.agent.update
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-fleet-ci.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() {
    echo "FAIL $*" >&2
    sudo cat "$SPOOL/result.json" "$SUPPORT/update/journal.json" "$SUPPORT/update/logs/runner.log" >&2 || true
    sudo launchctl print "system/$JOB" >&2 || true
    exit 1
}
receipt() { pkgutil --pkg-info dev.codonic.oarbank.agent | sed -n 's/^version: //p'; }
current_is() {
    local t
    t="$(sudo readlink "$AGENT/current")"
    [[ "$t" == "versions/$1-"*/oarbank-agent ]] || fail "current points at $t, not $1"
}

python3 "$REPO/scripts/fleet-manifest.py" "$V2" "$DIST" --seq 2 --released-at 0 --out "$WORK/oarbank-fleet-$V2.json"
id="ci-pkg-$(date +%s)"
python3 - "$WORK" "$SECOND" "$V2" "$id" <<'PY'
import hashlib, json, sys, time
from pathlib import Path
work, pkg, version, rid = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
manifest = (work / f"oarbank-fleet-{version}.json").read_text(encoding="ascii")
assert pkg.name in {a["name"] for a in json.loads(manifest)["artifacts"]}
data = pkg.read_bytes()
req = {"id": rid, "release": version, "seq": 2, "format": "pkg", "sha256": hashlib.sha256(data).hexdigest(),
       "size": len(data), "manifest": manifest, "signature": None, "owner_anchors": None, "rollback": False,
       "requested_at": time.time()}
(work / "request.json").write_text(json.dumps(req), encoding="ascii")
PY

# 1. by hand
sudo installer -pkg "$FIRST" -target /
[[ "$(receipt)" == "$V1" ]] || fail "the first install is $(receipt)"
sudo launchctl print "system/$JOB" >/dev/null || fail "the pkg did not load $JOB"
sudo "$L" setup --scope system --no-service
current_is "$V1"
sudo "$L" update-trust --unsigned

# 2. the agent's part: package, then request, in the agent's account
owner="$(sudo stat -f%Su "$AGENT")"
sudo install -d -m 700 -o "$owner" "$SPOOL"
sudo install -m 600 -o "$owner" "$SECOND" "$SPOOL/package"
sudo install -m 600 -o "$owner" "$WORK/request.json" "$SPOOL/.request.json.tmp"
sudo mv "$SPOOL/.request.json.tmp" "$SPOOL/request.json"
state=""
for ((i = 0; i < 3000; i++)); do
    state="$(sudo cat "$SPOOL/result.json" 2>/dev/null | python3 -c 'import json,sys
try: r = json.load(sys.stdin)
except ValueError: r = {}
print(r.get("state", "") if r.get("id") == sys.argv[1] else "")' "$id")"
    [[ -n "$state" && "$state" != installing ]] && break
    # WatchPaths on a file whose directory came after the job loaded: say so if launchd has not started it in a
    # minute, and start the job by hand (the same job and program)
    if [[ $i -eq 300 && -z "$state" ]] && sudo test -e "$SPOOL/request.json"; then
        echo "::warning::launchd did not start $JOB on the request within 60 s; starting it with kickstart"
        sudo launchctl kickstart "system/$JOB"
    fi
    sleep 0.2
done
[[ "$state" == installed ]] || fail "launchd's runner did not install $V2 ($state)"
current_is "$V2"
printf '{"id":"%s","release":"%s","agent_version":"%s","at":%s}' "$id" "$V2" "$V2" "$(date +%s)" > "$WORK/confirmed"
sudo install -m 600 -o "$owner" "$WORK/confirmed" "$SPOOL/.confirmed.tmp"
sudo mv "$SPOOL/.confirmed.tmp" "$SPOOL/confirmed"

# 3. committed
for ((i = 0; i < 600; i++)); do
    sudo grep -Eq '"state"[[:space:]]*:[[:space:]]*"(done|rolled_back|failed|refused)"' "$SPOOL/result.json" && break
    sleep 0.5
done
sudo grep -Eq '"state"[[:space:]]*:[[:space:]]*"done"' "$SPOOL/result.json" || fail "the update did not commit"
[[ "$(receipt)" == "$V2" ]] || fail "the receipt says $(receipt), not $V2"
current_is "$V2"
[[ ! -e "$SPOOL/request.json" ]] || fail "the runner left the request"
sudo launchctl print "system/$JOB" >/dev/null || fail "$JOB is no longer loaded"
sudo cat "$SUPPORT/update/logs/runner.log" || true
echo "ok   the pkg updated from $V1 to $V2 through launchd's update runner"
