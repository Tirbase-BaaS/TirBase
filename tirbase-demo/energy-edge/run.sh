#!/usr/bin/env bash
# Energy edge demo entry point (CLAIM-48.1, PV-16.2).
# Demonstrates defended S1 (out-of-envelope) and S2 (slow ramp/drift) scenarios.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase energy-edge demo pack =="
echo "pack: tirbase-demo/energy-edge"
echo "scenarios: S1 (out-of-envelope) S2 (slow ramp/drift)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs energy_edge_s1_out_of_envelope_defended -- --nocapture
TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs energy_edge_s2_slow_ramp_defended -- --nocapture

echo
echo "energy-edge demo: defended attack scenarios demonstrated (S1,S2)"
