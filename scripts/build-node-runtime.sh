#!/usr/bin/env bash
# Build the node runtime the agent packages ship: a relocatable CPython 3.12 (uv's managed build) with the module
# SDK and its dependencies (what spec/bundles.md says modules get "from the host"), and uv for module environments.
#
#   scripts/build-node-runtime.sh OUT_DIR
#
# Layout: OUT_DIR/bin/python3 (and the rest of the interpreter), OUT_DIR/bin/uv. The launcher points the agent at it
# (OARBANK_RUNTIME_PYTHON, OARBANK_UV) when it sits beside the launcher as `runtime/`.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?scripts/build-node-runtime.sh OUT_DIR}"
PYVER="${OARBANK_PYTHON:-3.12}"
uv python install -q "$PYVER"
PYHOME="$(cd "$(dirname "$(uv python find --managed-python "$PYVER")")/.." && pwd -P)"
case "$PYHOME" in /usr|/usr/local|/) echo "refusing to bundle $PYHOME" >&2; exit 1 ;; esac
rm -rf "$OUT"
cp -R "$PYHOME" "$OUT"
rm -f "$OUT"/lib/python3*/EXTERNALLY-MANAGED
PY="$OUT/bin/python$PYVER"
[[ -x "$OUT/bin/python3" ]] || ln -s "python$PYVER" "$OUT/bin/python3"
uv pip install -q --python "$PY" --break-system-packages "$REPO/vendor/oarbank-sdk"
"$PY" -I "$REPO/scripts/relocate_shebangs.py" "$OUT/bin"   # pip's shebangs name this build path
install -m 755 "$(command -v uv)" "$OUT/bin/uv"
"$PY" -I -c 'import oarbank_sdk, pydantic; print("node runtime:", oarbank_sdk.__name__, pydantic.VERSION)'
