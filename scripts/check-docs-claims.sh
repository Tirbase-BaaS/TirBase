#!/usr/bin/env bash
# check-docs-claims.sh — verify the documentation claims that have no runtime caller.
#
# These claims (CLAIM-3.4, 3.8, 3.9, 3.10, 3.12) are deliverables, so their
# evidence is the document itself. This script turns each one into an executable
# gate: the document must exist and must still contain the sections/entries the
# claim promises. Deleting a section, an invariant row, or a unit row fails CI.
#
# Usage: bash scripts/check-docs-claims.sh
# Exit codes: 0 — all documentation claims are satisfied; 1 — a gap was found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

failures=0

fail() {
  echo "ERROR: $*" >&2
  failures=$((failures + 1))
}

require_file() {
  [[ -f "$1" ]] || fail "required document '$1' is missing"
}

require_heading() {
  local file="$1"
  shift
  require_file "$file"
  [[ -f "$file" ]] || return 0
  for heading in "$@"; do
    if ! grep -qiE "^#{1,4}[[:space:]]+.*${heading}" "$file"; then
      fail "'$file' is missing the '$heading' section promised by its claim"
    fi
  done
}

# CLAIM-3.4 — threat model sections.
require_heading "docs/THREAT_MODEL.md" \
  "asset" "actor" "trust boundar" "failure mode" "non-goal" \
  "residual risk" "out.of.scope" "non-goal" "owner.decision"

# CLAIM-3.8 — system invariant catalogue INV-1 .. INV-16.
require_file "docs/system-invariants.md"
if [[ -f docs/system-invariants.md ]]; then
  for n in $(seq 1 16); do
    grep -q "INV-$n\b" docs/system-invariants.md \
      || fail "docs/system-invariants.md does not define INV-$n"
  done
fi

# CLAIM-3.9 — every SecurityEvent category and reason code is catalogued.
require_file "docs/security-event-catalog.md"
if [[ -f docs/security-event-catalog.md ]]; then
  grep -q "ReasonCode" docs/security-event-catalog.md \
    || fail "docs/security-event-catalog.md does not enumerate reason codes"
  grep -qiE "categor" docs/security-event-catalog.md \
    || fail "docs/security-event-catalog.md does not enumerate event categories"
fi

# CLAIM-3.10 — initial unit registry rows.
require_file "docs/unit-registry.md"
if [[ -f docs/unit-registry.md ]]; then
  for unit in degC Pa rpm bar kW percent boolean kPa m3h V A Hz; do
    grep -q "\\b${unit}\\b" docs/unit-registry.md \
      || fail "docs/unit-registry.md does not define unit '$unit'"
  done
fi

# CLAIM-3.12 — freshness policy documented and exercised in tirbase-sim.
require_file "docs/freshness-policy.md"
require_file "tirbase-sim/src/scenarios/s19_s23_s31_time.rs"
if [[ -f tirbase-sim/src/scenarios/s19_s23_s31_time.rs ]]; then
  grep -q "FreshnessState::Unverified" tirbase-sim/src/scenarios/s19_s23_s31_time.rs \
    || fail "the freshness scenario no longer exercises FreshnessState::Unverified"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "FAILED: $failures documentation claim gap(s)." >&2
  exit 1
fi

echo "OK: documentation claims (CLAIM-3.4, 3.8, 3.9, 3.10, 3.12) are satisfied."
