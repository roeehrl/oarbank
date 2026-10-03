#!/usr/bin/env bash
# Model-check OarbankLease.tla under every config and compare each outcome with the expected one.
#
#   ./run_tlc.sh            run every config
#   ./run_tlc.sh a_nofence  run only the configs whose name contains "a_nofence"
#   QUICK=1 ./run_tlc.sh    skip the four slowest configs (about 13 of the 21 minutes)
#
# A line says PASS when TLC's outcome matches the expectation: "ok" (no violation) for the
# reference protocol, and the named invariant / temporal-property violation for each weakened
# variant and each finding. Full TLC output (with counterexample traces) goes to out/<cfg>.log.
set -u
cd "$(dirname "$0")"

JAVA="${JAVA:-/opt/homebrew/opt/openjdk@17/bin/java}"
JAR="${JAR:-tla2tools.jar}"
WORKERS="${WORKERS:-auto}"
HEAP="${HEAP:-12g}"
FILTER="${1:-}"
SLOW=" OarbankLease OarbankLease_execfail OarbankLease_liveness OarbankLease_stalled_goldens_dispute_liveness "

# config                                           expected outcome
CONFIGS=(
  "OarbankLease                                      ok"
  "OarbankLease_replica                              ok"
  "OarbankLease_3nodes                               ok"
  "OarbankLease_3nodes_always_wrong                  ok"
  "OarbankLease_double_vote                          ok"
  "OarbankLease_double_vote_3nodes                   ok"
  "OarbankLease_execfail                             ok"
  "OarbankLease_liveness                             ok"
  "OarbankLease_liveness_always_wrong                ok"
  "OarbankLease_replica_liveness                     ok"
  "OarbankLease_3nodes_liveness                      ok"
  "OarbankLease_stalled_goldens_liveness             ok"
  "OarbankLease_stalled_goldens_dispute_liveness     ok"
  "OarbankLease_failing_goldens                      ok"
  "OarbankLease_failing_goldens_liveness             ok"
  "OarbankLease_witness_LateCompletionWins           inv:W_LateCompletionWins"
  "OarbankLease_witness_DisputeOpened                inv:W_DisputeOpened"
  "OarbankLease_witness_StrandedDisputeQuarantined   inv:W_StrandedDisputeQuarantined"
  "OarbankLease_witness_StaleCompletionRejected      inv:W_StaleCompletionRejected"
  "OarbankLease_witness_RetriedJobDoneAgain          inv:W_RetriedJobDoneAgain"
  "OarbankLease_witness_RevokedCertRejected          inv:W_RevokedCertRejected"
  "OarbankLease_witness_SelfInconsistentConvicted    inv:W_SelfInconsistentConvicted"
  "OarbankLease_witness_PartyLateVoteFenced          inv:W_PartyLateVoteFenced"
  "OarbankLease_witness_TieBreakConvicts             inv:W_TieBreakConvicts"
  "OarbankLease_witness_ReplicaDisagrees             inv:W_ReplicaDisagrees"
  "OarbankLease_witness_ReplicaCancelledByReaper     inv:W_ReplicaCancelledByReaper"
  "OarbankLease_witness_GoldenFailed                 inv:W_GoldenFailed"
  "OarbankLease_witness_GraceExpiredReplicaCancelled inv:W_GraceExpiredReplicaCancelled"
  "OarbankLease_a_nofence                            inv:StaleNeverCanonical"
  "OarbankLease_b_noreturn                           inv:NoLostJob"
  "OarbankLease_b_noreturn_liveness                  liveness"
  "OarbankLease_c_nodemote                           inv:CanonicalGenCurrent"
  "OarbankLease_c_nodemote_one                       inv:OneCanonical"
  "OarbankLease_d_nonatomic                          inv:DoneHasCanonical"
  "OarbankLease_e_no_quarantine_fence                inv:NoCanonicalFromQuarantined"
  "OarbankLease_f_breaker_keeps_generation           inv:LiveOnReadyCertified"
  "OarbankLease_f_breaker_keeps_generation_canon     inv:NoCanonicalFromUncertified"
  "OarbankLease_g_strict_failed_here                 liveness"
  "OarbankLease_h_claim_snapshot                     inv:QuarantinedNoGrant"
  "OarbankLease_h_claim_snapshot_revoked             inv:LiveOnReadyCertified"
  "OarbankLease_i_double_vote                        inv:NoHonestConviction"
  "OarbankLease_i_double_vote_3nodes                 inv:NoHonestConviction"
  "OarbankLease_i_double_vote_always_wrong           inv:NoHonestConviction"
  "OarbankLease_i1_party_fence_only                  ok"
  "OarbankLease_i2_gen_bump_only                     ok"
  "OarbankLease_i3_no_self_inconsistency             ok"
  "OarbankLease_k_no_settled_fence                   inv:SettledNotRevived"
  "OarbankLease_l_replica_stranded                   liveness"
  "OarbankLease_l1_reap_cancel_only                  ok"
  "OarbankLease_l2_eligible_check_only               liveness"
  "OarbankLease_m_replica_behind_stalled_certifying liveness"
  "OarbankLease_m_dispute_behind_stalled_certifying liveness"
  "OarbankLease_n_golden_sets_pile_up                inv:GoldenSetsBounded"
  "OarbankLease_n_golden_retry_loop                  inv:GoldenFailuresBounded"
  "OarbankLease_module_faults                        ok"
  "OarbankLease_module_faults_liveness               ok"
  "OarbankLease_o_no_await_lease                     inv:ModuleFaultsNotCharged"
)

if [ ! -f "$JAR" ]; then
  echo "missing $JAR: download https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar" >&2
  echo "(sha1 bee4a54f3ee3d4afc347c3240ec2d9e93b075104)" >&2
  exit 2
fi

mkdir -p out
fail=0
printf '%-50s %-34s %-34s %-6s %12s %12s %6s %8s\n' CONFIG EXPECTED GOT RESULT GENERATED DISTINCT DEPTH TIME
for row in "${CONFIGS[@]}"; do
  read -r cfg expected <<<"$row"
  if [ -n "$FILTER" ] && [[ "$cfg" != *"$FILTER"* ]]; then continue; fi
  if [ -n "${QUICK:-}" ] && [[ "$SLOW" == *" $cfg "* ]]; then continue; fi
  log="out/$cfg.log"
  meta="$(mktemp -d "${TMPDIR:-/tmp}/tlc-meta.XXXXXX")"
  start=$(date +%s)
  "$JAVA" -XX:+UseParallelGC -Xmx"$HEAP" -cp "$JAR" tlc2.TLC \
      -workers "$WORKERS" -deadlock -cleanup -metadir "$meta" \
      -config "$cfg.cfg" OarbankLease.tla >"$log" 2>&1
  secs=$(( $(date +%s) - start ))
  rm -rf "$meta"

  if grep -q "Model checking completed. No error has been found." "$log"; then
    got="ok"
  elif inv=$(grep -oE "Invariant [A-Za-z0-9_]+ is violated" "$log" | head -1) && [ -n "$inv" ]; then
    got="inv:$(echo "$inv" | awk '{print $2}')"
  elif grep -q "Temporal properties were violated" "$log"; then
    got="liveness"
  else
    got="error"
  fi
  gen=$(grep -oE "^[0-9,]+ states generated" "$log" | tail -1 | awk '{print $1}')
  dist=$(grep -oE "[0-9,]+ distinct states found" "$log" | tail -1 | awk '{print $1}')
  if [ "$got" = "ok" ]; then   # depth of the state graph; for a violation, the counterexample length
    depth=$(grep -oE "depth of the complete state graph search is [0-9]+" "$log" | awk '{print $NF}')
  else
    depth=$(grep -cE "^State [0-9]+:" "$log")
  fi
  if [ "$got" = "$expected" ]; then res=PASS; else res=FAIL; fail=1; fi
  printf '%-50s %-34s %-34s %-6s %12s %12s %6s %7ss\n' "$cfg" "$expected" "$got" "$res" "${gen:-?}" "${dist:-?}" "${depth:-?}" "$secs"
done
exit $fail
