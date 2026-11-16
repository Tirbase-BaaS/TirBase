#!/usr/bin/env bash
# Water/pumping station demo entry point (CLAIM-48.2, PV-16.2).
# Demonstrates defended S1 (out-of-envelope) and S3 (replay) scenarios.
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

echo "== TirBase water-pumping demo pack =="
echo "pack: tirbase-demo/water-pumping"
echo "scenarios: S1 (out-of-envelope) S3 (replay)"
echo

run_check water_pumping_s1_out_of_envelope_defended
run_check water_pumping_s3_replay_defended

echo
echo "water-pumping demo: defended attack scenarios demonstrated (S1,S3)"
