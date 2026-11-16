#!/usr/bin/env bash
# Logistics node CRDT BaaS demo entry point (CLAIM-48.3, PV-16.2).
# Demonstrates defended S10 (revoked delta) and S12 (partition+rejoin convergence).
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Run one demo check. When the caller supplies a prebuilt test binary
# (`TIRBASE_DEMO_TEST_BIN`, set by the pack tests and CI), run it directly:
# invoking cargo from inside `cargo test` makes the child contend with the
# parent's build lock and can stall the check for minutes. The fallback keeps
# the launcher self-contained for anyone who copies the pack out of this repo.
run_check() {
  local test_name="$1"
  if [[ -n "${TIRBASE_DEMO_TEST_BIN:-}" ]]; then
    "$TIRBASE_DEMO_TEST_BIN" "$test_name" --nocapture
  else
    TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs \
      "$test_name" -- --nocapture
  fi
}

echo "== TirBase logistics-node demo pack =="
echo "pack: tirbase-demo/logistics-node"
echo "scenarios: S10 (revoked delta propagation) S12 (partition+rejoin convergence)"
echo

run_check logistics_node_s10_revoked_delta_defended
run_check logistics_node_s12_partition_rejoin_converges

echo
echo "logistics-node demo: defended attack scenarios demonstrated (S10,S12)"
