#!/usr/bin/env bash
# CLAIM-40.1 / PV-12.6 / PV-6.6, PV-6.8, PV-10.5:
# Every untrusted-input parser across crates must have a registered cargo-fuzz
# target with committed seed corpus; CI smoke runs enforce <=60s per target.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# (crate_dir, target_name) required fuzz targets.
REQUIRED=(
  "tirbase-core:automerge_delta_decode"
  "tirbase-core:fragment_reassembly"
  "tirbase-drivers:modbus_frame"
  "tirbase-drivers:mqtt_frame"
  "tirbase-drivers:register_map_parse"
  "tirbase-guard:envelope_profile_parse"
  "tirbase-guard:command_message_parse"
)

missing=0
for entry in "${REQUIRED[@]}"; do
  crate="${entry%%:*}"
  target="${entry##*:}"
  tpath="$crate/fuzz/fuzz_targets/${target}.rs"
  cpath="$crate/fuzz/corpus/${target}"
  if [[ ! -f "$tpath" ]]; then
    echo "ERROR [CLAIM-40.1]: missing fuzz target $tpath" >&2
    missing=1
  fi
  if [[ ! -d "$cpath" ]]; then
    echo "ERROR [CLAIM-40.1]: missing corpus dir $cpath" >&2
    missing=1
  elif [[ -z "$(ls -A "$cpath" 2>/dev/null)" ]]; then
    echo "ERROR [CLAIM-40.1]: corpus dir has no committed seeds: $cpath" >&2
    missing=1
  fi
done

# Ensure root fuzz/ mirror targets exist as well (production caller: fuzz/fuzz_targets/ across all crates).
for t in automerge_delta_decode fragment_reassembly; do
  [[ -f "fuzz/fuzz_targets/${t}.rs" ]] || { echo "ERROR [CLAIM-40.1]: missing root fuzz target fuzz/fuzz_targets/${t}.rs" >&2; missing=1; }
  [[ -d "fuzz/corpus/${t}" && -n "$(ls -A "fuzz/corpus/${t}" 2>/dev/null)" ]] || { echo "ERROR [CLAIM-40.1]: missing root corpus fuzz/corpus/${t}" >&2; missing=1; }
done

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "OK [CLAIM-40.1]: ${#REQUIRED[@]} fuzz targets present with committed seed corpora (plus root fuzz mirrors)."
