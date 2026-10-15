#!/bin/sh
# A module runner's cleanup stage for cleanup.rs's tests: `run --spec S --workdir W --out R`. It notes the reason and the
# attempt id in the module data directory; a `fail` file there makes it fail with failure.json, a `hang` file makes it
# outlast its timeout.
spec="$3"
work="$5"
data="$OARBANK_MODULE_DATA"
if [ -e "$data/hang" ]; then
    sleep 30
fi
if [ -e "$data/fail" ]; then
    printf '{"reason": "m/still_registered", "detail": "the registry said no"}' > "$work/failure.json"
    exit 1
fi
reason=$(sed -n 's/.*"reason": *"\([a-z]*\)".*/\1/p' "$spec")
printf '%s %s %s\n' "$reason" "$OARBANK_ATTEMPT_ID" "$(cat "$OARBANK_TOOLS_FILE")" >> "$data/released"
exit 0
