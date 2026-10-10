#!/bin/sh
# deb postinst (configure) / rpm %post: the coordinator as a system service (docs/design/coordinator-system-service.md).
#   - An upgrade of the system service (its record exists): the units are written again from the record and restart on
#     the new payload (install-oarbankd.sh --refresh).
#   - An earlier release's per-user coordinator (systemd user units that run this package's payload): it moves to the
#     system service (oarbank coordinator migrate; its keys are already files in its home), and is left as it was if
#     that fails (/var/lib/oarbank/coordinator-migration.json says why).
#   - A first install: nothing more; the setup wizard starts the services (pkexec asks for an administrator once).
# Never fails the transaction: the programs are installed whatever happens here.
set -u
ROOT=/opt/oarbank/coordinator
RECORD=/etc/oarbank/coordinator-service.json
if [ -f "$RECORD" ]; then
    /bin/bash "$ROOT/install-oarbankd.sh" --refresh || echo "Oarbank: the coordinator's services could not be refreshed; run: sudo $ROOT/install-oarbankd.sh --refresh"
    exit 0
fi
"$ROOT/bin/oarbank" coordinator migrate --run --from-installer --build "$ROOT" \
    || echo "Oarbank: the move to a system service did not complete; the per-user coordinator runs as before (/var/lib/oarbank/coordinator-migration.json)"
exit 0
