#!/usr/bin/env bash
# scripts/check-public-api.sh
# Verifies that the public API of each library crate matches its committed manifest.
# Usage: bash scripts/check-public-api.sh
# Exits non-zero if any crate's public API has changed.
#
# To update a manifest after an intentional API addition:
#   cargo +nightly public-api -p <crate> > <crate>/public-api.txt
# then commit the updated file.
set -euo pipefail

# Library crates only — tirbase-admin and tirbase-gateway are binary-only crates
# with no lib target; cargo-public-api requires a lib target.
CRATES=(
  tirbase-types
  tirbase-core
  tirbase-guard
  tirbase-drivers
  tirbase-sim
  tirbase-demo
)

FAIL=0

for CRATE in "${CRATES[@]}"; do
  MANIFEST="${CRATE}/public-api.txt"

  if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: Missing public API manifest: $MANIFEST"
    echo "       Run: cargo +nightly public-api -p ${CRATE} > ${MANIFEST}"
    FAIL=1
    continue
  fi

  # Generate current public API into a temp file.
  # Stderr is redirected separately so that compiler warnings don't pollute
  # the API listing used for comparison.
  CURRENT=$(mktemp)
  ERR=$(mktemp)
  if ! cargo +nightly public-api -p "${CRATE}" > "$CURRENT" 2>"$ERR"; then
    echo "ERROR: cargo public-api failed for ${CRATE}"
    cat "$ERR"
    FAIL=1
    rm -f "$CURRENT" "$ERR"
    continue
  fi
  rm -f "$ERR"

  # Diff: lines in CURRENT but not in MANIFEST are new (unapproved) items
  ADDED=$(comm -23 <(sort "$CURRENT") <(sort "$MANIFEST") || true)
  # Lines in MANIFEST but not in CURRENT are removed items
  REMOVED=$(comm -13 <(sort "$CURRENT") <(sort "$MANIFEST") || true)

  if [[ -n "$ADDED" ]]; then
    echo "FAIL [${CRATE}]: New public API items not in manifest:"
    echo "$ADDED" | sed 's/^/  + /'
    echo ""
    echo "  To approve: run 'cargo +nightly public-api -p ${CRATE} > ${CRATE}/public-api.txt'"
    echo "  and commit the updated manifest."
    FAIL=1
  fi

  if [[ -n "$REMOVED" ]]; then
    echo "WARN [${CRATE}]: Public API items removed (breaking change):"
    echo "$REMOVED" | sed 's/^/  - /'
    echo "  Update the manifest: cargo +nightly public-api -p ${CRATE} > ${CRATE}/public-api.txt"
    FAIL=1
  fi

  if [[ -z "$ADDED" && -z "$REMOVED" ]]; then
    echo "OK   [${CRATE}]: public API matches manifest"
  fi

  rm -f "$CURRENT"
done

exit $FAIL
