#!/usr/bin/env bash
# Nightly-scale sweep of the seeded fault-injecting simulator across fleet shapes.
# Usage: scripts/sim-sweep.sh [seeds-per-shape]   (default 2000; exits non-zero on any failing seed)
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-2000}"
PY="${PY:-.venv/bin/python}"
rc=0
while read -r label args; do
  [ -z "$label" ] && continue
  printf '== %-10s ' "$label"
  # shellcheck disable=SC2086
  if ! $PY -m oarbank.sim --seeds "$N" $args | tail -1; then rc=1; fi
done <<'SHAPES'
two      --nodes 2 --profile harsh
three    --nodes 3 --profile harsh
four     --nodes 4 --profile harsh --configs 5 --datasets 12
six      --nodes 6 --profile harsh --configs 8 --datasets 20
mild     --nodes 4 --profile mild
split4   --nodes 4 --profile harsh --split --configs 4 --datasets 8
split5c  --nodes 5 --profile harsh --split --bad-mode consistent
SHAPES
exit $rc
