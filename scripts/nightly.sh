#!/bin/bash
# oarbank nightly: every verification layer, chaos and the agent end to end included. Writes a markdown report to
# $OARBANK_NIGHTLY_DIR (default ~/Library/Application Support/Oarbank/nightly/<date>.md) and exits non-zero if anything
# failed. Never touches a running coordinator: every test uses scratch homes and free ports.
#
#   scripts/nightly.sh            # everything
#   QUICK=1 scripts/nightly.sh    # skip the long stateful and simulator sweeps
set -u -o pipefail
cd "$(dirname "$0")/.."
OUT_DIR="${OARBANK_NIGHTLY_DIR:-$HOME/Library/Application Support/Oarbank/nightly}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/$(date +%Y-%m-%d).md"
A11Y="${OARBANK_A11Y_NODE_MODULES:-$HOME/.cache/oarbank-a11y/node_modules}"
fails=0

step() {   # step <name> <command...>
  local name="$1"; shift
  local t0=$(date +%s) log="$OUT_DIR/$(date +%Y-%m-%d)-${name// /_}.log"
  if "$@" >"$log" 2>&1; then status="pass"; else status="FAIL"; fails=$((fails + 1)); fi
  printf '| %s | %s | %ss | %s |\n' "$name" "$status" "$(( $(date +%s) - t0 ))" "$(tail -1 "$log" | tr '|' '/' | cut -c1-120)" >>"$REPORT"
}

{
  echo "# oarbank nightly $(date '+%Y-%m-%d %H:%M')"
  echo
  echo "core $(git rev-parse --short HEAD), SDK $(git -C vendor/oarbank-sdk rev-parse --short HEAD)"
  echo
  echo "| Step | Result | Time | Last line |"
  echo "|---|---|---|---|"
} >"$REPORT"

if [ ! -d "$A11Y/axe-core" ]; then
  mkdir -p "$(dirname "$A11Y")" && (cd "$(dirname "$A11Y")" && npm init -y >/dev/null 2>&1; npm install --silent axe-core@4 jsdom@25) >/dev/null 2>&1
fi

step "core suite" uv run pytest -q --ignore=tests/rust
step "chaos" uv run pytest -q -m chaos tests/chaos
step "accessibility (axe)" env OARBANK_A11Y_NODE_MODULES="$A11Y" uv run pytest -q tests/test_accessibility.py
step "SDK suite" uv run pytest -q vendor/oarbank-sdk/tests
step "toy conformance" uv run oarbank-sdk conform vendor/oarbank-sdk/examples/toy
step "agent (Rust)" bash -c "cd rust && cargo test --workspace --locked"
step "agent end to end" uv run pytest -q tests/rust
if [ -z "${QUICK:-}" ]; then
  step "stateful (thorough)" env OARBANK_THOROUGH=1 uv run pytest -q tests/test_stateful.py
  step "simulator sweep (fleet shapes, chaos)" env PY=".venv/bin/python" scripts/sim-sweep.sh 100
fi
step "parity (zero gaps)" uv run python -c "from oarbank.contracts import parity; g = parity.gaps(); print(len(g), 'gaps'); raise SystemExit(bool(g))"

{
  echo
  if [ "$fails" -eq 0 ]; then echo "**All steps passed.**"; else echo "**$fails step(s) failed.** Logs are next to this report."; fi
} >>"$REPORT"
echo "$REPORT"
exit $(( fails > 0 ))
