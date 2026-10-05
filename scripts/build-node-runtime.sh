#!/usr/bin/env bash
# Build the node runtime the agent packages ship: a relocatable CPython 3.12 (uv's managed build) with the module
# SDK and its dependencies (what spec/bundles.md says modules get "from the host"), and uv for module environments.
#
#   scripts/build-node-runtime.sh OUT_DIR PLATFORM       # PLATFORM: darwin-arm64, darwin-amd64, linux-arm64, linux-amd64
#
# Layout: OUT_DIR/bin/python3 (and the rest of the interpreter), OUT_DIR/bin/uv. The launcher points the agent at it
# (OARBANK_RUNTIME_PYTHON, OARBANK_UV) when it sits beside the launcher as `runtime/`. The packaging scripts check it
# before they package it (scripts/check-package.py). Every native file is for PLATFORM: the interpreter is its
# python-build-standalone build, uv installs the wheels the interpreter asks for (it runs it, under Rosetta 2 for
# darwin-amd64 on Apple silicon), and uv is its release for PLATFORM (scripts/fetch-uv.py).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?scripts/build-node-runtime.sh OUT_DIR PLATFORM}"
PLATFORM="${2:?scripts/build-node-runtime.sh OUT_DIR PLATFORM}"
case "$PLATFORM" in
    darwin-arm64) REQUEST=macos-aarch64-none ;; darwin-amd64) REQUEST=macos-x86_64-none ;;
    linux-arm64) REQUEST=linux-aarch64-gnu ;; linux-amd64) REQUEST=linux-x86_64-gnu ;;
    *) echo "no node runtime for $PLATFORM" >&2; exit 2 ;;
esac
PYVER="${OARBANK_PYTHON:-3.12}"
"$REPO/scripts/bundle-python.sh" "$OUT" "cpython-$PYVER-$REQUEST"
# the build runs the interpreter with -B: bytecode written now would name this build's directory
PY="$OUT/bin/python$PYVER"
# the runtime's own uv installs into it, as on Windows (where uv writes launchers for its own architecture)
"$PY" -I -B "$REPO/scripts/fetch-uv.py" "$PLATFORM" "$OUT/bin/uv"
"$OUT/bin/uv" pip install -q --python "$PY" --break-system-packages "$REPO/vendor/oarbank-sdk"
# a plain install, as from an index: uv records the checkout it installed from (direct_url.json), a path on this build
# machine that the runtime has no use for
INFO="$(echo "$OUT"/lib/python3*/site-packages/oarbank_sdk-*.dist-info)"
rm "$INFO/direct_url.json"
grep -v '/direct_url\.json,' "$INFO/RECORD" > "$INFO/RECORD.new" && mv "$INFO/RECORD.new" "$INFO/RECORD"
"$PY" -I -B "$REPO/scripts/relocate_shebangs.py" "$OUT/bin"   # pip's shebangs name this build path
# bytecode for everything, written again (uv runs the interpreter to inspect it, which leaves bytecode naming this
# directory), recording paths relative to the runtime and checked against the sources' hashes (the packages' file times
# are not the build's), so a runtime installed read-only never compiles on start
"$PY" -I -B -m compileall -q -f -j 0 -s "$OUT" -e "$OUT" --invalidation-mode checked-hash "$OUT/lib"
"$PY" -I -B -c 'import oarbank_sdk, platform, pydantic; print("node runtime:", platform.machine(), oarbank_sdk.__name__, pydantic.VERSION)'
