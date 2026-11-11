#!/usr/bin/env bash
# Water/pumping station demo entry point (CLAIM-48.2, PV-16.2).
# Demonstrates defended S1 (out-of-envelope) and S3 (replay) scenarios.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase water-pumping demo pack =="
echo "pack: tirbase-demo/water-pumping"
echo "scenarios: S1 (out-of-envelope) S3 (replay)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs water_pumping_s1_out_of_envelope_defended -- --nocapture
TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs water_pumping_s3_replay_defended -- --nocapture

echo
echo "water-pumping demo: defended attack scenarios demonstrated (S1,S3)"
