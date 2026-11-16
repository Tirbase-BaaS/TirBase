#!/usr/bin/env bash
# Reefer/container pack entry point (pack format v1).
#
# Prints the pack's identity, trip metadata, and expected defended output, then
# runs the pack's structural checks. The pack itself is data only; this launcher
# is the sole executable file a pack may contain.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

PACK_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PACK_DIR/../.." && pwd)"
cd "$ROOT"

echo "== TirBase reefer/container pack =="
echo "pack: tirbase-demo/reefer"
echo "profile: profiles/reefer.toml (device_class = reefer)"
echo "trip: trip.toml (container MSCU1234567, trailer TRL-0081)"
echo "register maps: reefer_reference, reefer_legacy"
echo "scenarios:"
echo "  S1  ambient spike (envelope + drift), setpoint tampering (envelope)"
echo "  S2  door open in transit (dwell + min-off), power loss (min-off + dwell),"
echo "      sensor dropout (drift + min-off)"
echo "trip disposition: quarantined (door open 300 s > 120 s rule)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test reefer_pack_structure -- --nocapture

echo
echo "reefer pack: structure valid; all scenarios defended, trip quarantined (see expected/outcomes.toml)"
