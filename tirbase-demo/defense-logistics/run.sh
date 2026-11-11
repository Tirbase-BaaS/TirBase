#!/usr/bin/env bash
# Defense-logistics demo entry point (CLAIM-48.6, PV-16.2).
# Demonstrates defended S3 (replay) in M-of-N movement orders simulation.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== TirBase defense-logistics demo pack =="
echo "pack: tirbase-demo/defense-logistics"
echo "scenarios: S3 (replay) — M-of-N movement orders simulation"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test vertical_demo_packs defense_logistics_s3_replay_defended -- --nocapture

echo
echo "defense-logistics demo: defended attack scenarios demonstrated (S3)"
