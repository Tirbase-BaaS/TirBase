#!/usr/bin/env bash
# Cold-chain flagship demo entry point (CLAIM-47.4, PV-16.4).
# Produces observable output demonstrating the defended S1/S2/S3 scenarios.
set -euo pipefail

# When invoked by the automated test harness, delegate to the scenario tests
# without re-entering this script to avoid infinite recursion.
if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase cold-chain demo pack =="
echo "pack: tirbase-demo/cold-chain"
echo "scenarios: S1 (out-of-envelope) S2 (slow ramp/drift) S3 (replay)"
echo

# When the caller supplies a prebuilt test binary (`TIRBASE_DEMO_TEST_BIN`, set
# by the pack tests and CI), run it directly: invoking cargo from inside
# `cargo test` makes the child contend with the parent's build lock and can
# stall the check for minutes. The fallback keeps the launcher self-contained.
if [[ -n "${TIRBASE_DEMO_TEST_BIN:-}" ]]; then
  "$TIRBASE_DEMO_TEST_BIN" --nocapture \
    --skip cold_chain_run_sh_produces_observable_output_within_120s
else
  TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test cold_chain_scenarios \
    -- --nocapture --skip cold_chain_run_sh_produces_observable_output_within_120s
fi

echo
echo "cold-chain demo: defended attack scenarios demonstrated (S1,S2,S3)"
