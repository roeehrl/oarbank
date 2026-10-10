#!/bin/sh
# deb prerm: remove/deconfigure; rpm preun: 0 for removal, >=1 for replacement.
# Failed cleanup must fail the transaction BEFORE the package files disappear.
# Removal stops and removes the system services (the home, the oarbankd account and the oarbank-admin group stay),
# then any per-user units of an earlier release that still run this payload (coordinator-remove.py).
set -eu
case "${1:-}" in
    remove|deconfigure|0) ;;
    upgrade|failed-upgrade|[1-9]*) exit 0 ;;
    *) exit 0 ;;
esac
/bin/bash /opt/oarbank/coordinator/install-oarbankd.sh --uninstall --keep-programs
exec /opt/oarbank/coordinator/python/bin/python3 -I -B /usr/lib/oarbank/coordinator-remove.py
