#!/usr/bin/env bash
# Pharma GDP pack entry point (pack format v1, CC-10).
#
# Prints the pack's storage classes, MKT parameters, and release code set, then
# runs the pack's structural checks. The pack itself is data only; this launcher
# is the sole executable file a pack may contain.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

PACK_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PACK_DIR/../.." && pwd)"
cd "$ROOT"

echo "== TirBase pharma GDP pack =="
echo "pack: tirbase-demo/pharma-gdp"
echo "lot: LOT-2026-1115-0042 (Amoxicillin 500 mg capsules)"
echo "storage classes: 2-8 C cold chain, frozen, controlled room 15-25 C"
echo "MKT: dH = 83144 J/mol, R = 8.314 J/(mol K), reported hourly from 5 min samples"
echo "release codes: GDP-REL-001, GDP-BLK-002/003/005, GDP-HLD-004, GDP-REJ-006/007"
echo "scenarios:"
echo "  S2  transient excursion (accepted but held), cumulative drift (rejected),"
echo "      sensor failure (envelope + drift refused, release blocked)"
echo "release checks: clear, transient hold, cumulative reject, calibration expiry,"
echo "      lane risk, sensor failure, MKT exceeded"
echo

# Run one demo check. When the caller supplies a prebuilt test binary
# (`TIRBASE_DEMO_TEST_BIN`, set by the pack tests and CI), run it directly:
# invoking cargo from inside `cargo test` makes the child contend with the
# parent's build lock and can stall the check for minutes. The fallback keeps
# the launcher self-contained for anyone who copies the pack out of this repo.
if [[ -n "${TIRBASE_DEMO_TEST_BIN:-}" ]]; then
  "$TIRBASE_DEMO_TEST_BIN" --nocapture
else
  TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test pharma_gdp_pack_structure -- --nocapture
fi

echo
echo "pharma-gdp pack: structure valid; excursion vs drift distinguished, calibration expiry blocks release"
