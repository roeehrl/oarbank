#!/usr/bin/env bash
# Wrap an existing coordinator move archive; never rebuild or modify it.
# scripts/package-coordinator-linux.sh [version] [archive.tar.gz]
# Architecture comes from the archive, so nFPM can also package on another host.
set -euo pipefail
umask 022
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -le 2 ]] || { echo "usage: $0 [version] [archive.tar.gz]" >&2; exit 2; }
VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || { echo "bad version $VERSION" >&2; exit 2; }
command -v nfpm >/dev/null || { echo "nfpm is not installed" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is not installed" >&2; exit 2; }
if [[ $# -ge 2 ]]; then
    ARCHIVE="$2"
else
    case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported arch; pass an archive" >&2; exit 2 ;; esac
    ARCHIVE="$REPO/dist/oarbank-coordinator-$VERSION-linux-$ARCH.tar.gz"
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-coordinator-package.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
python3 "$REPO/deploy/linux/coordinator-stage.py" "$REPO" "$ARCHIVE" "$VERSION" "$WORK"
ARCH="$(cat "$WORK/arch")"
OUT="$REPO/dist"
mkdir -p "$OUT"
# Scripts/config are in this private directory, never a shared .nfpm.build.yaml.
for fmt in deb rpm; do
    nfpm package --config "$WORK/nfpm.yaml" --packager "$fmt" \
        --target "$WORK/oarbank-coordinator-$VERSION-linux-$ARCH.$fmt"
done
# Publish only after both packagers succeed. Keep archive checksum files intact.
for fmt in deb rpm; do
    cp "$WORK/oarbank-coordinator-$VERSION-linux-$ARCH.$fmt" "$OUT/"
done
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 "oarbank-coordinator-$VERSION-linux-$ARCH.deb" \
    "oarbank-coordinator-$VERSION-linux-$ARCH.rpm" > "SHA256SUMS-coordinator-packages-$VERSION-linux-$ARCH")
echo "$OUT/oarbank-coordinator-$VERSION-linux-$ARCH.deb"
echo "$OUT/oarbank-coordinator-$VERSION-linux-$ARCH.rpm"
