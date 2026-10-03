#!/bin/sh
# A fake service-protocol-1 service for the agent's tests. Its state is files in its data directory, named after
# the service: <svc>.up (running), <svc>.ready (the daemon is ready), <svc>.calls (every op it was asked).
# Test switches: <svc>.fail_start, <svc>.health, <svc>.no_running (fingerprint omits "running"), <svc>.owned.
D="$OARBANK_MODULE_DATA"
S="$OARBANK_SERVICE"
echo "$*" >> "$D/$S.calls"
running() { [ -f "$D/$S.up" ]; }
case "$1" in
fingerprint)
  h=healthy
  [ -f "$D/$S.health" ] && h=$(cat "$D/$S.health")
  if running; then r=true; else r=false; fi
  if [ -f "$D/$S.no_running" ]; then
    printf '{"service_protocol":{"supported":[1]},"health":"%s","pools":{"vmpool":4},"reserve":{"mem_gb":8}}\n' "$h"
  else
    printf '{"service_protocol":{"supported":[1]},"health":"%s","pools":{"vmpool":4},"reserve":{"mem_gb":8},"running":%s}\n' "$h" "$r"
  fi
  ;;
start)
  if [ -f "$D/$S.fail_start" ]; then echo "start refused" >&2; exit 1; fi
  {
    echo "service=$OARBANK_SERVICE"
    echo "node=$OARBANK_NODE_ID"
    echo "module=$OARBANK_MODULE"
    echo "cwd=$(pwd -P)"
    echo "settings=$(cat "$OARBANK_SETTINGS_FILE")"
    echo "limits=$(cat "$OARBANK_LIMITS_FILE")"
  } > "$D/$S.env"
  if ( : > "$PWD/escaped" ) 2>/dev/null; then echo allowed > "$D/$S.escape"; else echo denied > "$D/$S.escape"; fi
  if ! running; then
    : > "$D/$S.up"
    rm -f "$D/$S.ready"
    # the daemon: ready after a second, up while the flag exists; it stays in the start op's process group
    ( sleep 1; : > "$D/$S.ready"; while [ -f "$D/$S.up" ]; do sleep 0.2; done; rm -f "$D/$S.ready" ) </dev/null >/dev/null 2>&1 &
    echo $! > "$D/$S.pid"
  fi
  echo '{"ok":true}'
  ;;
stop)
  rm -f "$D/$S.up" "$D/$S.ready"
  echo '{"ok":true}'
  ;;
status)
  if running; then echo '{"running":true}'; else echo '{"running":false}'; fi
  ;;
ready)
  if running && [ -f "$D/$S.ready" ]; then echo '{"running":true,"ready":true}'; else echo '{"running":false,"ready":false}'; fi
  ;;
list_owned)
  if [ -f "$D/$S.owned" ]; then cat "$D/$S.owned"; else echo '{"objects":[]}'; fi
  ;;
destroy)
  echo "$2" >> "$D/$S.destroyed"
  echo '{"ok":true}'
  ;;
*)
  exit 64
  ;;
esac
