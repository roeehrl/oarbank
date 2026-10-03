#!/usr/bin/env bash
# Build a coordinator build for this machine's platform: dist/oarbank-coordinator-<version>-<platform>.tar.gz, the
# archive `oarbank coordinator-build upload` registers and moves install (coordinator-builds format 1).
#
#   scripts/build-coordinator.sh [version]
#
# Layout: oarbank-coordinator.json, python/ (a relocatable CPython with the coordinator's dependencies and the SDK;
# modules run on this interpreter), bin/oarbankd, bin/oarbank, bin/oarbank-console, and off macOS bin/oarbank-sandbox
# (the agent's module launcher). The core is compiled with Nuitka
# into one native extension module (D7: its source is not shipped); its templates, static files and schemas sit
# beside it. OARBANK_CODESIGN_IDENTITY signs every Mach-O file (default: ad-hoc).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || { echo "bad version $VERSION" >&2; exit 2; }
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) PLATFORM=darwin-arm64 ;; Darwin-x86_64) PLATFORM=darwin-amd64 ;;
    Linux-aarch64) PLATFORM=linux-arm64 ;; Linux-x86_64) PLATFORM=linux-amd64 ;;
    *) echo "unsupported build host $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
OUT="$REPO/dist"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-coord.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/oarbank-coordinator"
mkdir -p "$OUT" "$ROOT/bin"

# 1. the interpreter: uv's managed CPython (python-build-standalone) is relocatable and carries its headers; never a
#    system Python (copying its prefix would copy /usr)
PYVER="${OARBANK_PYTHON:-3.12}"
uv python install -q "$PYVER"
PYHOME="$(cd "$(dirname "$(uv python find --managed-python "$PYVER")")/.." && pwd -P)"
case "$PYHOME" in /usr|/usr/local|/) echo "refusing to bundle $PYHOME" >&2; exit 1 ;; esac
cp -R "$PYHOME" "$ROOT/python"
rm -f "$ROOT/python/lib/python$PYVER/EXTERNALLY-MANAGED"
PY="$ROOT/python/bin/python$PYVER"

# 2. the dependencies (locked) and the SDK, never the core's source
(cd "$REPO" && uv export --frozen --no-dev --no-emit-project --no-editable --no-hashes -q) | grep -v '^\./vendor/oarbank-sdk$' > "$WORK/requirements.txt"
uv pip install -q --python "$PY" --break-system-packages -r "$WORK/requirements.txt"
uv pip install -q --python "$PY" --break-system-packages --no-deps "$REPO/vendor/oarbank-sdk"

# 3. the core, compiled
SITE="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
(cd "$REPO" && uv run --no-project --python "$PY" --with "nuitka>=2.7" python -m nuitka --module src/oarbank --include-package=oarbank \
    --nofollow-imports --output-dir="$WORK/nuitka" --remove-output --quiet --assume-yes-for-downloads)
cp "$WORK"/nuitka/oarbank.*.so "$SITE/"
(cd "$REPO/src" && find oarbank -type f ! -name '*.py' ! -name '*.pyc' ! -path '*__pycache__*' -exec rsync -R {} "$SITE/" \;)
"$PY" -I -c 'import oarbank, oarbank.coordinator.app, oarbank.console.app; assert hasattr(oarbank, "__compiled__"), oarbank.__file__'

# 3b. off macOS, the agent's launcher confines module processes (Landlock and seccomp; an AppContainer)
if [[ "$(uname -s)" != Darwin ]]; then
    (cd "$REPO/rust" && cargo build -q --release --locked -p oarbank-agent)
    install -m 755 "$REPO/rust/target/release/oarbank-agent" "$ROOT/bin/oarbank-sandbox"
fi

# 4. entry points, relative to the build so it runs from wherever it is unpacked
launcher() {
    cat > "$ROOT/bin/$1" <<SH
#!/bin/sh
here="\$(cd "\$(dirname "\$0")/.." && pwd -P)"
exec "\$here/python/bin/python$PYVER" -I -c 'import sys; from $2 import main; sys.argv[0] = "$1"; sys.exit(main())' "\$@"
SH
    chmod 755 "$ROOT/bin/$1"
}
launcher oarbankd oarbank.coordinator.__main__
launcher oarbank oarbank.cli.main
launcher oarbank-console oarbank.console.__main__
# pip wrote the build path into its console scripts' shebangs (python/bin/oarbank-sdk, uvicorn, ...): point them at the
# python beside them, and stop if any script still names an interpreter by absolute path
"$PY" -I "$REPO/scripts/relocate_shebangs.py" "$ROOT/python/bin" "$ROOT"
cat > "$ROOT/oarbank-coordinator.json" <<JSON
{"format": 1, "version": "$VERSION", "platform": "$PLATFORM", "exec": ["bin/oarbankd"], "console": ["bin/oarbank-console"]}
JSON

# 5. signatures (macOS), then the archive
if [[ "$(uname -s)" == Darwin ]]; then
    ID="${OARBANK_CODESIGN_IDENTITY:--}"
    find "$ROOT" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) -print0 | while IFS= read -r -d '' f; do
        file -b "$f" | grep -q Mach-O || continue
        if [[ "$ID" == "-" ]]; then codesign --force --sign - "$f" 2>/dev/null
        else codesign --force --options runtime --timestamp --sign "$ID" "$f"; fi
    done
fi
"$ROOT/bin/oarbankd" --help >/dev/null
TGZ="$OUT/oarbank-coordinator-$VERSION-$PLATFORM.tar.gz"
(cd "$ROOT" && COPYFILE_DISABLE=1 tar -czf "$TGZ" oarbank-coordinator.json bin python)
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 "$(basename "$TGZ")" > "SHA256SUMS-coordinator-$VERSION-$PLATFORM")
echo "$TGZ"
