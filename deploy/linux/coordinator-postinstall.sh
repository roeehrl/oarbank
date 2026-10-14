#!/bin/sh
# deb postinst (configure) / rpm %post: the coordinator as a system service (docs/design/coordinator-system-service.md).
#   - An upgrade of the system service (its record exists): the units are written again from the record and restart on
#     the new payload (install-oarbankd.sh --refresh --installed: this payload, also after a coordinator self-update
#     ran another build). The refresh also pins the update runner's trust from the home's owner keys when none is
#     pinned yet (oarbank-coordupdate trust --from-home; fleet-updates.md, D58).
#   - An earlier release's per-user coordinator (systemd user units that run this package's payload): it moves to the
#     system service (oarbank coordinator migrate; its keys are already files in its home), and is left as it was if
#     that fails (/var/lib/oarbank/coordinator-migration.json says why).
#   - A first install: nothing more; the setup wizard starts the services (pkexec asks for an administrator once).
#   - Whichever it was, a system service with no update trust yet gets it here (oarbank-coordupdate trust --from-home),
#     also after a migration, whose copied database may get its owner anchors only once the new build opened it. A home
#     with no owner keys yet leaves the pin pending; the runner makes it at the first update request.
# Never fails the transaction: the programs are installed whatever happens here.
set -u
ROOT=/opt/oarbank/coordinator
RECORD=/etc/oarbank/coordinator-service.json
DATA=/var/lib/oarbank
pin_trust() {
    [ -f "$RECORD" ] && [ -f "$DATA/coordinator/oarbank.sqlite3" ] || return 0
    [ -f "$DATA/coordinator-update/trust.json" ] && return 0
    "$ROOT/bin/oarbank-coordupdate" trust --from-home --home "$DATA/coordinator" --state "$DATA/coordinator-update" >/dev/null 2>&1 \
        && echo "Oarbank: the coordinator's update trust is pinned" \
        || echo "Oarbank: the coordinator has no owner keys yet; its update runner pins them at the first update"
}
if [ -f "$RECORD" ]; then
    /bin/bash "$ROOT/install-oarbankd.sh" --refresh --installed "$ROOT" || echo "Oarbank: the coordinator's services could not be refreshed; run: sudo $ROOT/install-oarbankd.sh --refresh"
    pin_trust
    exit 0
fi
"$ROOT/bin/oarbank" coordinator migrate --run --from-installer --build "$ROOT" \
    && pin_trust \
    || echo "Oarbank: the move to a system service did not complete; the per-user coordinator runs as before (/var/lib/oarbank/coordinator-migration.json)"
exit 0
