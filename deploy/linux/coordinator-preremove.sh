#!/bin/sh
# deb prerm: remove/deconfigure; rpm preun: 0 for removal, >=1 for replacement.
# Failed cleanup must fail the transaction BEFORE the package files disappear.
set -eu
case "${1:-}" in
    remove|deconfigure|0) ;;
    upgrade|failed-upgrade|[1-9]*) exit 0 ;;
    *) exit 0 ;;
esac
exec /opt/oarbank/coordinator/python/bin/python3 -I -B /usr/lib/oarbank/coordinator-remove.py
