#!/bin/sh
# Oarbank agent package: runs as root after install or upgrade.
#
# A first install configures the node when /etc/oarbank holds what it needs (an admin or configuration management
# writes these before installing):
#   join-code     an Oarbank join code (OB1-…); deleted once copied into the agent's home
#   coordinator   or a coordinator URL (the owner then approves the node)
# The node runs as a system service (systemd) under the dedicated account `oarbank`. An upgrade restarts the service
# on the new launcher; the agent's own version is the coordinator's to change (self-update).
set -eu
ETC=/etc/oarbank
L=/usr/lib/oarbank/oarbank-launcher
UNIT=dev.codonic.oarbank.agent.service

if [ -f /var/lib/oarbank/agent/agent.json ]; then
    systemctl try-restart "$UNIT" 2>/dev/null || true
    echo "Oarbank: upgraded; the service restarted on the new launcher"
    exit 0
fi
set --
[ -f "$ETC/join-code" ] && set -- "$@" --join-code-file "$ETC/join-code"
[ -f "$ETC/coordinator" ] && set -- "$@" --coordinator "$(cat "$ETC/coordinator")"
if [ $# -eq 0 ]; then
    echo "Oarbank: installed. Finish with: sudo oarbank-launcher setup --scope system --join-code <code>"
    exit 0
fi
"$L" setup --scope system "$@"
rm -f "$ETC/join-code"
