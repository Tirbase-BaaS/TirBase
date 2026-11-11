#!/usr/bin/env bash
# Remote-ops mesh demo entry point (CLAIM-48.5, PV-16.2).
# Demonstrates defended S12 (partition+rejoin convergence).
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase remote-ops-mesh demo pack =="
echo "pack: tirbase-demo/remote-ops-mesh"
echo "scenarios: S12 (partition+rejoin convergence)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs remote_ops_mesh_s12_partition_rejoin_converges -- --nocapture

echo
echo "remote-ops-mesh demo: defended attack scenarios demonstrated (S12)"
