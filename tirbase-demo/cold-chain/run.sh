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

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test cold_chain_scenarios \
  -- --nocapture --skip cold_chain_run_sh_produces_observable_output_within_120s

echo
echo "cold-chain demo: defended attack scenarios demonstrated (S1,S2,S3)"
