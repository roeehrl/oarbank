#!/usr/bin/env bash
# Native package smoke on disposable GitHub runners; never a user's computer.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'Only for disposable GitHub Actions runners.' >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml" | head -1)"
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; *) exit 2 ;; esac
PACKAGE="$REPO/dist/oarbank-coordinator-$VERSION-linux-$ARCH.deb"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
sudo dpkg --install "$PACKAGE"
trap 'sudo dpkg --remove oarbank-coordinator; rm -rf "$scratch"' EXIT
# Help must resolve the /usr/bin symlink to the payload, without setup or services.
HOME="$scratch" oarbank-setup --help
[[ -x /opt/oarbank/coordinator/bin/oarbankd && -e /usr/share/applications/oarbank-coordinator.desktop ]]
[[ ! -e "$scratch/.local/share/oarbank/coordinator" ]]
[[ -s /usr/share/icons/hicolor/scalable/apps/oarbank-coordinator.svg ]]
grep -qx "Icon=oarbank-coordinator" /usr/share/applications/oarbank-coordinator.desktop
sudo dpkg --remove oarbank-coordinator
[[ ! -e /opt/oarbank/coordinator/bin/oarbankd && ! -e /usr/bin/oarbank-setup ]]
[[ ! -e /usr/share/icons/hicolor/scalable/apps/oarbank-coordinator.svg ]]
trap 'rm -rf "$scratch"' EXIT
