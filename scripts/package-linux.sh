#!/usr/bin/env bash
# Build the Linux agent packages on a Linux host: dist/oarbank-agent_<version>_<arch>.deb, .rpm and a static
# tarball, with nFPM (https://nfpm.goreleaser.com) from deploy/linux/nfpm.yaml.
#
#   scripts/package-linux.sh [version]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/rust/Cargo.toml" | head -1)}"
[[ "$(uname -s)" == Linux ]] || { echo "build Linux packages on Linux" >&2; exit 2; }
command -v nfpm >/dev/null || { echo "nfpm is not installed" >&2; exit 2; }
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *) echo "unsupported arch" >&2; exit 2 ;; esac
(cd "$REPO/rust" && OARBANK_AGENT_VERSION="$VERSION" cargo build -q --release --locked -p oarbank-agent -p oarbank-launcher)
OUT="$REPO/dist"
mkdir -p "$OUT"
export ARCH VERSION BIN_DIR="$REPO/rust/target/release"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-deb.XXXXXX")"
RUNTIME_DIR="$WORK/runtime"
trap 'rm -rf "$WORK"; rm -f "$REPO/deploy/linux/.nfpm.build.yaml"' EXIT
"$REPO/scripts/build-node-runtime.sh" "$RUNTIME_DIR"
cd "$REPO/deploy/linux"
# nFPM expands variables in some fields only: fill them in a copy beside the scripts it names
sed -e "s|\${ARCH}|$ARCH|g" -e "s|\${VERSION}|$VERSION|g" -e "s|\${BIN_DIR}|$BIN_DIR|g" -e "s|\${RUNTIME_DIR}|$RUNTIME_DIR|g" nfpm.yaml > .nfpm.build.yaml
for fmt in deb rpm; do
    nfpm package --config .nfpm.build.yaml --packager "$fmt" --target "$OUT/"
done
tar -C "$BIN_DIR" -czf "$OUT/oarbank-agent-$VERSION-linux-$ARCH.tar.gz" oarbank-agent oarbank-launcher
cp "$BIN_DIR/oarbank-agent" "$OUT/oarbank-agent-$VERSION-linux-$ARCH"
(cd "$OUT" && sha256sum ./*"$VERSION"*linux* ./*.deb ./*.rpm > "SHA256SUMS-agent-$VERSION-linux-$ARCH")
ls "$OUT"
