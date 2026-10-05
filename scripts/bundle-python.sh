#!/usr/bin/env bash
# Copy uv's managed CPython (python-build-standalone, relocatable) to DEST for a build to ship, as files of its own:
# never a virtual environment (uv finds the checkout's .venv first unless told --system) nor the link uv names a managed
# Python by, no bytecode this machine wrote into uv's store (it names the store's path), its build configuration and on
# macOS its library naming nothing of the store, as python-build-standalone ships them. scripts/build-node-runtime.sh and
# scripts/build-coordinator.sh use it; scripts/check-package.py checks what they build.
#
#   scripts/bundle-python.sh DEST [VERSION]      # VERSION: 3.12 by default (OARBANK_PYTHON)
set -euo pipefail
DEST="${1:?scripts/bundle-python.sh DEST [VERSION]}"
PYVER="${2:-${OARBANK_PYTHON:-3.12}}"
uv python install -q "$PYVER"
PYHOME="$("$(uv python find --managed-python --system "$PYVER")" -I -B -c 'import os, sys; print(os.path.realpath(sys.base_prefix))')"
case "$PYHOME" in "$(cd "$(uv python dir)" && pwd -P)"/*) ;; *) echo "refusing to bundle $PYHOME: not a uv-managed Python" >&2; exit 1 ;; esac
rm -rf "$DEST"
cp -R "$PYHOME" "$DEST"
rm -f "$DEST"/lib/python3*/EXTERNALLY-MANAGED
find "$DEST" -name __pycache__ -type d -prune -exec rm -rf {} +
[[ -e "$DEST/bin/python3" ]] || ln -s "python$PYVER" "$DEST/bin/python3"
# uv writes its store's path into the build configuration, where python-build-standalone has /install
"$DEST/bin/python$PYVER" -I -B - "$PYHOME" "$DEST"/lib/python3*/_sysconfigdata_*.py <<'PY'
import sys
store, files = sys.argv[1], sys.argv[2:]
for f in files:
    with open(f, encoding="utf-8") as fh:
        text = fh.read()
    with open(f, "w", encoding="utf-8") as fh:
        fh.write(text.replace(store, "/install"))
PY
if [[ "$(uname -s)" == Darwin && -f "$DEST/lib/libpython$PYVER.dylib" ]]; then
    install_name_tool -id "@rpath/libpython$PYVER.dylib" "$DEST/lib/libpython$PYVER.dylib" 2>/dev/null
    codesign --force --sign - "$DEST/lib/libpython$PYVER.dylib" 2>/dev/null   # the change voids its signature
fi
