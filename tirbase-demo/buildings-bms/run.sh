#!/usr/bin/env bash
# Buildings/BMS demo entry point (CLAIM-48.4, PV-16.2).
# Demonstrates defended S1 (out-of-envelope) and S2 (slow ramp/drift) scenarios.
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

echo "== TirBase buildings-bms demo pack =="
echo "pack: tirbase-demo/buildings-bms"
echo "scenarios: S1 (out-of-envelope) S2 (slow ramp/drift)"
echo "note: BACnet simulator placeholder (profile/register map documented)"
echo

run_check buildings_bms_s1_out_of_envelope_defended
run_check buildings_bms_s2_slow_ramp_defended

echo
echo "buildings-bms demo: defended attack scenarios demonstrated (S1,S2)"
