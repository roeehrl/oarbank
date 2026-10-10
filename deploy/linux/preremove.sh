#!/bin/sh
# Before the package goes (deb: "remove" or "deconfigure"; rpm: $1 = 0): stop and remove the service, and stop keeping
# the account's user manager alive (setup enabled lingering for rootless containers). The node's home and identity stay
# in /var/lib/oarbank, as Debian's remove keeps what purge deletes: reinstalling brings the same node back. deb's purge
# deletes it (postremove.sh); rpm has no purge, so `sudo oarbank-node leave` before `dnf remove` is how a node is
# removed for good. On an upgrade (deb: "upgrade", "failed-upgrade"; rpm: $1 >= 1) nothing happens.
set -u
case "${1:-}" in
    upgrade|failed-upgrade|abort-*|[1-9]*) exit 0 ;;
esac
/usr/lib/oarbank/oarbank-launcher remove --scope system || true
if command -v loginctl >/dev/null 2>&1; then
    loginctl disable-linger oarbank 2>/dev/null || true
fi
exit 0
