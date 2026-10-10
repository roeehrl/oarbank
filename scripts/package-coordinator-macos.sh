#!/usr/bin/env bash
# Wrap a compiled coordinator build in a native Installer package. No host installation.
# scripts/package-coordinator-macos.sh [archive]
# Its postinstall (deploy/macos/coordinator/scripts) links /usr/local/bin/oarbank and oarbank-setup to the app's
# launchers, refreshes an installed system service on the new build, and moves an earlier release's per-user
# coordinator to the system service (docs/design/coordinator-system-service.md); a first install starts no service.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)"
ARCH="$(uname -m)"
case "$ARCH" in arm64) PLATFORM=darwin-arm64 ;; x86_64) PLATFORM=darwin-amd64 ;; *) echo "unsupported Mac architecture" >&2; exit 2 ;; esac
ARCHIVE="${1:-$REPO/dist/oarbank-coordinator-$VERSION-$PLATFORM.tar.gz}"
OUT="$REPO/dist"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-coordinator-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/root/Applications/Oarbank Coordinator.app"
ROOT="$APP/Contents/Resources/coordinator"
mkdir -p "$ROOT" "$APP/Contents/MacOS" "$OUT"
tar -xzf "$ARCHIVE" -C "$ROOT"
# The package's identity and architecture come from its build, never a filename.
PY="$ROOT/python/bin/python3.12"
"$PY" -I -B -c 'import json, sys; from pathlib import Path; m=json.loads((Path(sys.argv[1])/"oarbank-coordinator.json").read_text()); assert m["format"] == 1 and m["version"] == sys.argv[2] and m["platform"] == sys.argv[3]; import oarbank.setup' "$ROOT" "$VERSION" "$PLATFORM"
[[ -x "$ROOT/install-oarbankd.sh" && -x "$ROOT/bin/oarbank-setup" ]] || { echo "build has no guided setup" >&2; exit 1; }
# the postinstall puts these on the PATH as links (/usr/local/bin): each must run through a link to it, as by its path
mkdir "$WORK/linked"
for cmd in oarbank oarbank-setup; do
    ln -s "$ROOT/bin/$cmd" "$WORK/linked/$cmd"
    "$WORK/linked/$cmd" --help >/dev/null || { echo "bin/$cmd does not run through a link to it" >&2; exit 1; }
done
cp "$REPO/deploy/icons/oarbank.icns" "$REPO/deploy/icons/oarbank-coordinator-symbolic.png" "$REPO/deploy/icons/oarbank-coordinator-symbolic@2x.png" "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.codonic.oarbank.coordinator</string>
<key>CFBundleName</key><string>Oarbank Coordinator</string>
<key>CFBundleDisplayName</key><string>Oarbank Coordinator</string>
<key>CFBundleExecutable</key><string>Oarbank Coordinator</string>
<key>LSUIElement</key><true/>
<key>CFBundleIconFile</key><string>oarbank.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSLocalNetworkUsageDescription</key><string>Oarbank connects your computers to this coordinator to run the jobs you choose.</string>
</dict></plist>
PLIST
# the menu bar app, with the menu bar model it shares with Oarbank Node.app (deploy/macos/shared/MenuBar.swift)
xcrun swiftc -O -parse-as-library -target "$ARCH-apple-macos15.0" -framework AppKit -framework ServiceManagement \
    "$REPO/deploy/macos/coordinator/Launcher.swift" "$REPO/deploy/macos/shared/MenuBar.swift" -o "$APP/Contents/MacOS/Oarbank Coordinator"
# Remove inherited extended attributes before sealing the application (and from the scripts: no ._ files).
cp -R "$REPO/deploy/macos/coordinator/scripts" "$WORK/scripts"
xattr -cr "$WORK/root" "$WORK/scripts"
ID="${OARBANK_CODESIGN_IDENTITY:--}"
# every Mach-O file, the bundled interpreter with deploy/macos/python.entitlements (modules run on it and load wheels
# signed by other teams; scripts/macos-codesign.sh, docs/release-signing.md "macOS code signatures"), then the app
source "$REPO/scripts/macos-codesign.sh"
macos_sign_tree "$ID" "$APP"
macos_sign "$ID" "$APP"
# the interpreter carries exactly that entitlement (with the hardened runtime under a Developer ID) and loads a native
# wheel from PyPI the build did not sign, in an environment outside the app; the seal check below sees any change
DEVELOPER_ID=()
[[ "$ID" == "-" ]] || DEVELOPER_ID=(--developer-id)
"$PY" -I -B "$REPO/scripts/check-macos-signing.py" ${DEVELOPER_ID[@]+"${DEVELOPER_ID[@]}"} --canary --work "$WORK/canary" "$ROOT"
rm -rf "$WORK/canary"
codesign --verify --deep --strict "$APP"
# pkgbuild marks the bundles it finds relocatable: Installer would then update a copy of the app it finds anywhere on the
# disk instead of installing /Applications/Oarbank Coordinator.app. Pin every bundle where the payload puts it.
pkgbuild --analyze --root "$WORK/root" "$WORK/components.plist" >/dev/null
n=0
while plutil -extract "$n.RootRelativeBundlePath" raw -o /dev/null "$WORK/components.plist" 2>/dev/null; do
    plutil -replace "$n.BundleIsRelocatable" -bool NO "$WORK/components.plist"
    n=$((n + 1))
done
[[ $n -gt 0 ]] || { echo "pkgbuild found no bundle in the payload (Oarbank Coordinator.app)" >&2; exit 1; }
pkgbuild --quiet --root "$WORK/root" --component-plist "$WORK/components.plist" --scripts "$WORK/scripts" --identifier dev.codonic.oarbank.coordinator --version "$VERSION" --install-location / --ownership recommended "$WORK/coordinator.pkg" 2> >(grep -vx 'write: Permission denied' >&2)
# macOS can retain provenance attributes despite xattr -cr. pkgbuild then embeds
# AppleDouble siblings; omit those without changing signed app resources, link
# targets, file modes or Installer's recommended root ownership.
if pkgutil --payload-files "$WORK/coordinator.pkg" | grep '/\._' >/dev/null; then
    pkgutil --expand "$WORK/coordinator.pkg" "$WORK/expanded"
    (cd "$WORK/root" && find . | COPYFILE_DISABLE=1 cpio -o --format odc -R 0:0 --quiet | gzip -9 -c) > "$WORK/expanded/Payload"
    lsbom "$WORK/expanded/Bom" | "$PY" -I -B -c 'import sys; sys.stdout.write("".join(line for line in sys.stdin if not any(p.startswith("._") for p in line.split("\t", 1)[0].split("/"))))' > "$WORK/bom.txt"
    mkbom -i "$WORK/bom.txt" "$WORK/expanded/Bom"
    count=$(cd "$WORK/root" && find . | wc -l | tr -d ' ')
    sed -i '' "s/numberOfFiles=\"[0-9]*\"/numberOfFiles=\"$count\"/" "$WORK/expanded/PackageInfo"
    rm "$WORK/coordinator.pkg"
    pkgutil --flatten "$WORK/expanded" "$WORK/coordinator.pkg"
fi
! pkgutil --payload-files "$WORK/coordinator.pkg" | grep '/\._' >/dev/null || { echo "AppleDouble metadata remains in coordinator package" >&2; exit 1; }
pkgutil --expand "$WORK/coordinator.pkg" "$WORK/bom-check"
diff <(lsbom -s "$WORK/bom-check/Bom" | sort) <(cd "$WORK/root" && find . | sort) >/dev/null || { echo "coordinator package bill does not match its payload" >&2; exit 1; }
# Explicit host architecture: the package cannot claim Intel support with an ARM runtime.
if [[ "$ARCH" == arm64 ]]; then apple_silicon=true; else apple_silicon=false; fi
cat > "$WORK/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
<title>Oarbank Coordinator</title>
<options customize="never" require-scripts="false" hostArchitectures="$ARCH"/>
<installation-check script="architecture()"/>
<script><![CDATA[
function architecture() {
    if ((system.sysctl("hw.optional.arm64") == 1) == $apple_silicon) return true;
    my.result.type = "Fatal";
    my.result.title = "This package is for $ARCH Macs";
    my.result.message = "Download the coordinator package for this Mac's architecture.";
    return false;
}
]]></script>
<domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
<choices-outline><line choice="coordinator"/></choices-outline>
<choice id="coordinator" visible="false"><pkg-ref id="dev.codonic.oarbank.coordinator"/></choice>
<pkg-ref id="dev.codonic.oarbank.coordinator" version="$VERSION" onConclusion="none">coordinator.pkg</pkg-ref>
</installer-gui-script>
XML
PKG="$OUT/oarbank-coordinator-$VERSION-macos-$ARCH.pkg"
SIGN=()
[[ -z "${OARBANK_INSTALLER_IDENTITY:-}" ]] || SIGN=(--sign "$OARBANK_INSTALLER_IDENTITY" --timestamp)
productbuild --quiet --distribution "$WORK/distribution.xml" --package-path "$WORK" ${SIGN[@]+"${SIGN[@]}"} "$PKG"
if [[ -n "${OARBANK_NOTARY_PROFILE:-}" ]]; then
    [[ -n "${OARBANK_INSTALLER_IDENTITY:-}" && "$ID" != "-" ]] || { echo "notarization needs Developer ID signatures" >&2; exit 1; }
    xcrun notarytool submit "$PKG" --keychain-profile "$OARBANK_NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
fi
(cd "$OUT" && shasum -a 256 "oarbank-coordinator-$VERSION-$PLATFORM.tar.gz" "$(basename "$PKG")" > "SHA256SUMS-coordinator-$VERSION-$PLATFORM")
echo "$PKG"
