#!/bin/sh
# Before the package goes (deb: "remove" or "deconfigure"; rpm: $1 = 0): stop and disable the update runner's path
# unit and disable its service (a runner at work finishes; dpkg's lock keeps it from overlapping a removal), stop and
# remove the node's service, and stop keeping the account's user manager alive (setup enabled lingering for rootless
# containers). The node's home and identity stay
# in /var/lib/oarbank, as Debian's remove keeps what purge deletes: reinstalling brings the same node back. deb's purge
# deletes it (postremove.sh); rpm has no purge, so `sudo oarbank-node leave` before `dnf remove` is how a node is
# removed for good. On an upgrade (deb: "upgrade", "failed-upgrade"; rpm: $1 >= 1) nothing happens.
set -u
case "${1:-}" in
    upgrade|failed-upgrade|abort-*|[1-9]*) exit 0 ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl disable --now dev.codonic.oarbank.agent.update.path >/dev/null 2>&1 || true
    systemctl disable dev.codonic.oarbank.agent.update.service >/dev/null 2>&1 || true
fi
/usr/lib/oarbank/oarbank-launcher remove --scope system || true
if command -v loginctl >/dev/null 2>&1; then
    loginctl disable-linger oarbank 2>/dev/null || true
fi
exit 0
