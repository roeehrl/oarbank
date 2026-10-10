#!/usr/bin/env bash
# The one-line node installers as release assets (docs/design/node-enrollment.md, "Channels"): scripts/install/
# oarbank-install.sh (macOS, Linux) and oarbank-install.ps1 (Windows) with the release's version filled in, written to
# OUTDIR with LF line endings, and their SHA-256 in SHA256SUMS-install-<version> there (LF; entries for these two names
# are replaced, others kept). The version names the release whose packages they download.
#
#   scripts/package-install-scripts.sh [version] [outdir]       # the repository's version and dist/ by default
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -le 2 ]] || { echo "usage: $0 [version] [outdir]" >&2; exit 2; }
VERSION="${1:-}"
VERSION="${VERSION#v}"
[[ -n "$VERSION" ]] || VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/rust/Cargo.toml" | head -1)"
# also what keeps the substitution below plain: no character sed would read
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || { echo "bad version $VERSION" >&2; exit 2; }
OUT="${2:-$REPO/dist}"
mkdir -p "$OUT"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
NAMES=(oarbank-install.sh oarbank-install.ps1)
for name in "${NAMES[@]}"; do
    sed -e "s/@OARBANK_VERSION@/$VERSION/g" "$REPO/scripts/install/$name" | tr -d '\r' > "$OUT/$name"
    if grep -q '@OARBANK_VERSION@' "$OUT/$name"; then echo "$name: the version was not filled in" >&2; exit 1; fi
done
chmod 755 "$OUT/oarbank-install.sh"
chmod 644 "$OUT/oarbank-install.ps1"
SUMS="$OUT/SHA256SUMS-install-$VERSION"
{
    if [[ -f "$SUMS" ]]; then grep -v -E '  (\./)?oarbank-install\.(sh|ps1)$' "$SUMS" || true; fi
    (cd "$OUT" && sha256 "${NAMES[@]}")
} | tr -d '\r' > "$SUMS.new"
mv "$SUMS.new" "$SUMS"
for name in "${NAMES[@]}"; do echo "$OUT/$name"; done
echo "$SUMS"
