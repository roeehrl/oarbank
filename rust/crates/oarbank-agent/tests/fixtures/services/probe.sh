#!/bin/sh
# A fake service-protocol-1 probe for the agent's tests: healthy unless <probe>.health says otherwise.
D="$OARBANK_MODULE_DATA"
[ "$1" = fingerprint ] || exit 64
echo "$*" >> "$D/$OARBANK_SERVICE.calls"
h=healthy
[ -f "$D/$OARBANK_SERVICE.health" ] && h=$(cat "$D/$OARBANK_SERVICE.health")
printf '{"service_protocol":{"supported":[1]},"health":"%s","attrs":{"version":"17"}}\n' "$h"
