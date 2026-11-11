#!/usr/bin/env bash
# Logistics node CRDT BaaS demo entry point (CLAIM-48.3, PV-16.2).
# Demonstrates defended S10 (revoked delta) and S12 (partition+rejoin convergence).
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase logistics-node demo pack =="
echo "pack: tirbase-demo/logistics-node"
echo "scenarios: S10 (revoked delta propagation) S12 (partition+rejoin convergence)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs logistics_node_s10_revoked_delta_defended -- --nocapture
TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs logistics_node_s12_partition_rejoin_converges -- --nocapture

echo
echo "logistics-node demo: defended attack scenarios demonstrated (S10,S12)"
