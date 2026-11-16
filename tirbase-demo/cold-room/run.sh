#!/usr/bin/env bash
# Cold-room pack entry point (pack format v1).
#
# Prints the pack's structure and the expected defended output, then runs the
# pack's structural and gateway integration checks. The pack itself is data
# only; this launcher is the sole executable file a pack may contain.
set -euo pipefail

if [[ "${TIRBASE_DEMO_INNER:-}" == "1" ]]; then
  exit 0
fi

PACK_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PACK_DIR/../.." && pwd)"
cd "$ROOT"

echo "== TirBase cold-room pack =="
echo "pack: tirbase-demo/cold-room"
echo "profile: profiles/cold_room.toml (device_class = cold_room)"
echo "register maps: cold_room_reference, cold_room_legacy"
echo "scenarios:"
echo "  S1  out-of-envelope setpoint, defrost manipulation"
echo "  S2  slow ramp (drift), door abuse (dwell + min-off), compressor short cycling (min-off)"
echo "  S3  captured command replay (idempotency)"
echo

TIRBASE_DEMO_INNER=1 cargo test -p tirbase-demo --test cold_room_pack_structure -- --nocapture

echo
echo "cold-room pack: structure valid; all scenarios defended (see expected/outcomes.toml)"
