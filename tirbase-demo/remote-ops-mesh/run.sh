#!/usr/bin/env bash
# Remote-ops mesh demo entry point (CLAIM-48.5, PV-16.2).
# Demonstrates defended S12 (partition+rejoin convergence).
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

echo "== TirBase remote-ops-mesh demo pack =="
echo "pack: tirbase-demo/remote-ops-mesh"
echo "scenarios: S12 (partition+rejoin convergence)"
echo

run_check remote_ops_mesh_s12_partition_rejoin_converges

echo
echo "remote-ops-mesh demo: defended attack scenarios demonstrated (S12)"
