#!/usr/bin/env bash
# Build the node runtime the agent packages ship: a relocatable CPython 3.12 (uv's managed build) with the module
# SDK and its dependencies (what spec/bundles.md says modules get "from the host"), and uv for module environments.
#
#   scripts/build-node-runtime.sh OUT_DIR
#
# Layout: OUT_DIR/bin/python3 (and the rest of the interpreter), OUT_DIR/bin/uv. The launcher points the agent at it
# (OARBANK_RUNTIME_PYTHON, OARBANK_UV) when it sits beside the launcher as `runtime/`. The packaging scripts check it
# before they package it (scripts/check-package.py).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?scripts/build-node-runtime.sh OUT_DIR}"
PYVER="${OARBANK_PYTHON:-3.12}"
"$REPO/scripts/bundle-python.sh" "$OUT" "$PYVER"
# the build runs the interpreter with -B: bytecode written now would name this build's directory
PY="$OUT/bin/python$PYVER"
uv pip install -q --python "$PY" --break-system-packages "$REPO/vendor/oarbank-sdk"
# a plain install, as from an index: uv records the checkout it installed from (direct_url.json), a path on this build
# machine that the runtime has no use for
INFO="$(echo "$OUT"/lib/python3*/site-packages/oarbank_sdk-*.dist-info)"
rm "$INFO/direct_url.json"
grep -v '/direct_url\.json,' "$INFO/RECORD" > "$INFO/RECORD.new" && mv "$INFO/RECORD.new" "$INFO/RECORD"
"$PY" -I -B "$REPO/scripts/relocate_shebangs.py" "$OUT/bin"   # pip's shebangs name this build path
install -m 755 "$(command -v uv)" "$OUT/bin/uv"
# bytecode for everything, written again (uv runs the interpreter to inspect it, which leaves bytecode naming this
# directory), recording paths relative to the runtime and checked against the sources' hashes (the packages' file times
# are not the build's), so a runtime installed read-only never compiles on start
"$PY" -I -B -m compileall -q -f -j 0 -s "$OUT" -e "$OUT" --invalidation-mode checked-hash "$OUT/lib"
"$PY" -I -B -c 'import oarbank_sdk, pydantic; print("node runtime:", oarbank_sdk.__name__, pydantic.VERSION)'
