#!/usr/bin/env bash
# check-state-inventory.sh — State inventory annotation completeness (CLAIM-31.2, PV-9.1)
#
# Production code must declare authoritative in-memory structures with a
# `STATE-INVENTORY:` marker, and each marker token/group must be registered in
# docs/state-inventory.md (PERSISTED/RECONSTRUCTIBLE).
#
# Usage: bash scripts/check-state-inventory.sh [INVENTORY_PATH]
set -euo pipefail

INVENTORY="${1:-docs/state-inventory.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

if [[ ! -f "$INVENTORY" ]]; then
  echo "ERROR: State inventory not found at '$INVENTORY'" >&2
  exit 1
fi

SOURCE_ROOTS=(
  "tirbase-core/src"
  "tirbase-guard/src"
  "tirbase-gateway/src"
  "tirbase-drivers/src"
)

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
MARKERS="$TMP_DIR/markers.txt"
: > "$MARKERS"

# Extract marker tokens (first token after STATE-INVENTORY:) from production .rs files.
for root in "${SOURCE_ROOTS[@]}"; do
  [[ -d "$root" ]] || continue
  while IFS= read -r f; do
    [[ "$f" == */tests/* ]] && continue
    # print "file<TAB>token" for each marker
    perl -ne 'if (/STATE-INVENTORY:\s*([A-Za-z0-9_., -]+)/) { $t=$1; $t=~s/[ ,].*//; print "$ARGV\t$t\n" if $t ne "" }' "$f" >> "$MARKERS" 2>/dev/null || true
  done < <(find "$root" -name "*.rs" -type f)
done

if [[ ! -s "$MARKERS" ]]; then
  echo "ERROR: No STATE-INVENTORY markers found in production source. Add markers and docs/state-inventory.md entries (CLAIM-31.2)." >&2
  exit 1
fi

fail=0
while IFS=$'\t' read -r file token; do
  [[ -z "${token:-}" ]] && continue
  token="${token%$'\r'}"
  if ! grep -Fq "$token" "$INVENTORY"; then
    echo "ERROR: STATE-INVENTORY marker '$token' in $file is not registered in $INVENTORY" >&2
    fail=1
  fi
done < "$MARKERS"

count=$(wc -l < "$MARKERS" | tr -d ' ')
if [[ "$fail" -ne 0 ]]; then
  echo "Fix: add a PERSISTED/RECONSTRUCTIBLE entry for each marker to $INVENTORY (PV-9.1, CLAIM-31.2)." >&2
  exit 1
fi

echo "OK: $count STATE-INVENTORY marker(s) are registered in $INVENTORY."
