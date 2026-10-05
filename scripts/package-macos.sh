#!/usr/bin/env bash
# Build the macOS agent package: dist/oarbank-agent-<version>-macos.pkg (+ the agent binary for the coordinator's
# agent-build channel and SHA256SUMS).
#
#   scripts/package-macos.sh [version]
#
# Signing is the owner's: nothing here holds keys.
#   OARBANK_CODESIGN_IDENTITY   "Developer ID Application: …" for the binaries (default: ad-hoc, for local tests)
#   OARBANK_INSTALLER_IDENTITY  "Developer ID Installer: …" to sign the pkg (default: unsigned)
#   OARBANK_NOTARY_PROFILE      a notarytool keychain profile: notarize and staple the signed pkg
#   OARBANK_TUF_ROOT            the vendor's TUF root.json, compiled into the agent (scripts/tuf_vendor.py)
# The binaries are universal when the x86_64-apple-darwin Rust target is installed, else arm64 only.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/rust/Cargo.toml" | head -1)}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || { echo "bad version $VERSION" >&2; exit 2; }
OUT="$REPO/dist"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

targets=(aarch64-apple-darwin)
rustup target list --installed 2>/dev/null | grep -x x86_64-apple-darwin >/dev/null && targets+=(x86_64-apple-darwin)
# the crates' source paths the binaries embed name CARGO_HOME as /cargo, not this machine's
for t in "${targets[@]}"; do
    (cd "$REPO/rust" && OARBANK_AGENT_VERSION="$VERSION" cargo build -q --release --locked --target "$t" -p oarbank-agent -p oarbank-launcher \
        --config "build.rustflags=['--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo']")
done

PAYLOAD="$WORK/root/Library/Oarbank/bin"
mkdir -p "$PAYLOAD" "$WORK/root/Library/Oarbank/etc"
for b in oarbank-agent oarbank-launcher; do
    inputs=()
    for t in "${targets[@]}"; do inputs+=("$REPO/rust/target/$t/release/$b"); done
    lipo -create "${inputs[@]}" -output "$PAYLOAD/$b"
done
install -m 755 "$REPO/deploy/macos/oarbank-uninstall" "$PAYLOAD/oarbank-uninstall"
# the node runtime beside the launcher (CPython 3.12 with the module SDK, and uv; scripts/build-node-runtime.sh)
"$REPO/scripts/build-node-runtime.sh" "$PAYLOAD/runtime"
# the payload holds no link out of itself and no path of this machine, and the runtime runs from elsewhere
uv run --no-project --python 3.12 python "$REPO/scripts/check-package.py" --build-path "$WORK" --build-path "$(uv python dir)" \
    --run "$PAYLOAD/runtime=bin/python3" "$WORK/root" "$PAYLOAD/oarbank-agent" "$PAYLOAD/oarbank-launcher"

ID="${OARBANK_CODESIGN_IDENTITY:--}"
for b in oarbank-agent oarbank-launcher; do
    if [[ "$ID" == "-" ]]; then
        codesign --force --sign - "$PAYLOAD/$b"
    else
        codesign --force --options runtime --timestamp --identifier "dev.codonic.$b" --sign "$ID" "$PAYLOAD/$b"
    fi
    codesign --verify --strict "$PAYLOAD/$b"
done
# every Mach-O file of the runtime, signed like the binaries
find "$PAYLOAD/runtime" -type f \( -perm -u+x -o -name '*.so' -o -name '*.dylib' \) -print0 | while IFS= read -r -d '' f; do
    file -b "$f" | grep Mach-O >/dev/null || continue
    if [[ "$ID" == "-" ]]; then codesign --force --sign - "$f" 2>/dev/null
    else codesign --force --options runtime --timestamp --sign "$ID" "$f"; fi
done
grep -aq "oarbank-agent-version:$VERSION" "$PAYLOAD/oarbank-agent" || { echo "the agent does not carry version $VERSION" >&2; exit 1; }

# no extended attributes: pkgbuild would carry them as ._ AppleDouble files
cp -R "$REPO/deploy/macos/scripts" "$WORK/scripts"
xattr -cr "$WORK/root" "$WORK/scripts"
# pkgbuild (macOS 27.0.1) compresses the bill of materials it writes in place (decmpfs: an extended attribute, the data
# truncated, the compressed flag set) while its writer still holds the file, after the complete bill was written and
# synced; the writer's last header writes are then refused, and it prints "write: Permission denied" once each. Those
# lines go, and the finished package's bill is checked against the payload below instead.
pkgbuild --quiet --root "$WORK/root" --scripts "$WORK/scripts" --identifier dev.codonic.oarbank.agent \
    --version "$VERSION" --install-location / --ownership recommended "$WORK/agent.pkg" 2> >(grep -vx 'write: Permission denied' >&2)
# a provenance attribute macOS will not let us clear still comes through as ._ entries: rebuild the payload without
# them (libarchive's cpio honours COPYFILE_DISABLE) and its bill of materials. grep reads the whole listing (not -q):
# under pipefail a pkgutil cut off by an early exit fails the pipeline, and the test took a payload full of ._ entries
# for a clean one
if pkgutil --payload-files "$WORK/agent.pkg" | grep '/\._' >/dev/null; then
    pkgutil --expand "$WORK/agent.pkg" "$WORK/x"
    (cd "$WORK/root" && find . | COPYFILE_DISABLE=1 cpio -o --format odc -R 0:0 --quiet | gzip -9 -c) > "$WORK/x/Payload"
    (cd "$WORK/root" && find . | while read -r f; do
        if [[ -d "$f" ]]; then printf '%s\t40%s\t0/0\n' "$f" "$(stat -f%Lp "$f")"
        else printf '%s\t100%s\t0/0\t%s\t%s\n' "$f" "$(stat -f%Lp "$f")" "$(stat -f%z "$f")" "$(cksum < "$f" | cut -d' ' -f1)"; fi
    done) > "$WORK/bom.txt"
    mkbom -i "$WORK/bom.txt" "$WORK/x/Bom"
    n=$(cd "$WORK/root" && find . | wc -l | tr -d ' ')
    sed -i '' "s/numberOfFiles=\"[0-9]*\"/numberOfFiles=\"$n\"/" "$WORK/x/PackageInfo"
    rm "$WORK/agent.pkg"
    pkgutil --flatten "$WORK/x" "$WORK/agent.pkg"
    ! pkgutil --payload-files "$WORK/agent.pkg" | grep '/\._' >/dev/null || { echo "._ entries remain in the payload" >&2; exit 1; }
fi
# the bill of materials lists exactly what the payload holds
pkgutil --expand "$WORK/agent.pkg" "$WORK/bom-check"
diff <(lsbom -s "$WORK/bom-check/Bom" | sort) <(cd "$WORK/root" && find . | sort) >/dev/null \
    || { echo "the package's bill of materials does not list its payload" >&2; exit 1; }
PKG="$OUT/oarbank-agent-$VERSION-macos.pkg"
if [[ -n "${OARBANK_INSTALLER_IDENTITY:-}" ]]; then
    productbuild --quiet --package "$WORK/agent.pkg" --sign "$OARBANK_INSTALLER_IDENTITY" --timestamp "$PKG"
else
    productbuild --quiet --package "$WORK/agent.pkg" "$PKG"
fi
if [[ -n "${OARBANK_NOTARY_PROFILE:-}" ]]; then
    [[ -n "${OARBANK_INSTALLER_IDENTITY:-}" ]] || { echo "notarizing needs a signed pkg (OARBANK_INSTALLER_IDENTITY)" >&2; exit 1; }
    xcrun notarytool submit "$PKG" --keychain-profile "$OARBANK_NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
fi

arch=$( [[ ${#targets[@]} -gt 1 ]] && echo universal || echo arm64 )
cp "$PAYLOAD/oarbank-agent" "$OUT/oarbank-agent-$VERSION-darwin-$arch"
(cd "$OUT" && shasum -a 256 "oarbank-agent-$VERSION-macos.pkg" "oarbank-agent-$VERSION-darwin-$arch" > "SHA256SUMS-agent-$VERSION")
echo "$PKG"
