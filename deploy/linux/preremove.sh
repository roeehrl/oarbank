#!/bin/sh
# Before the package goes: stop and remove the service (the node's home stays; `oarbank-launcher remove --scope system
# --purge` deletes it). On an upgrade (deb: "upgrade", rpm: $1 >= 1) nothing happens.
set -eu
case "${1:-}" in
    upgrade|1|2) exit 0 ;;
esac
/usr/lib/oarbank/oarbank-launcher remove --scope system || true
