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
sudo apt-get install -y "$PACKAGE"
trap 'sudo dpkg --remove oarbank-coordinator; rm -rf "$scratch"' EXIT
# Help must resolve the /usr/bin symlink to the payload, without setup or services.
HOME="$scratch" oarbank-setup --help
# The CLI resolves from the PATH (the /usr/bin link) to the payload, and behaves as by its full path: the same local
# admin channel lookup, in the home of the account that runs it.
[[ "$(command -v oarbank)" == /usr/bin/oarbank && "$(readlink /usr/bin/oarbank)" == /opt/oarbank/coordinator/bin/oarbank ]]
help="$(HOME="$scratch" oarbank --help)"
[[ "$help" == "usage: oarbank "* ]]
token="$scratch/.local/share/oarbank/coordinator/admin.token"
for cli in oarbank /opt/oarbank/coordinator/bin/oarbank; do
    if out="$(env -u XDG_DATA_HOME -u OARBANKD_HOME -u OARBANKD_URL -u OARBANK_TOKEN HOME="$scratch" "$cli" fleet 2>&1)"; then
        echo "$cli fleet succeeded without a coordinator" >&2; exit 1
    fi
    [[ "$out" == *"($token)"* ]] || { echo "$cli did not look for this account's coordinator: $out" >&2; exit 1; }
done
[[ -x /opt/oarbank/coordinator/bin/oarbankd && -e /usr/share/applications/dev.codonic.oarbank.coordinator.desktop ]]
[[ ! -e "$scratch/.local/share/oarbank/coordinator" ]]
[[ -s /usr/share/icons/hicolor/scalable/apps/oarbank-coordinator.svg ]]
grep -qx "Icon=oarbank-coordinator" /usr/share/applications/dev.codonic.oarbank.coordinator.desktop
sudo apt-get install -y xvfb dbus-x11
XDG_CONFIG_HOME="$scratch/config" xvfb-run -a dbus-run-session -- /usr/bin/oarbank-coordinator --self-test
sudo dpkg --remove oarbank-coordinator
[[ ! -e /opt/oarbank/coordinator/bin/oarbankd && ! -e /usr/bin/oarbank-setup ]]
[[ ! -e /usr/bin/oarbank && ! -L /usr/bin/oarbank ]]
hash -r  # forget where bash found oarbank before
if command -v oarbank >/dev/null; then echo "oarbank still resolves from the PATH after removal" >&2; exit 1; fi
[[ ! -e /usr/share/icons/hicolor/scalable/apps/oarbank-coordinator.svg ]]
trap 'rm -rf "$scratch"' EXIT
