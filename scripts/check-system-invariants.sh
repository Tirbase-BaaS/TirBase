#!/usr/bin/env bash
# check-system-invariants.sh — System invariants catalog completeness check
# (CLAIM-17.1..CLAIM-17.8, PV-23.1, PV-23.2).
#
# Fails if docs/system-invariants.md is missing any INV-1 through INV-16
# registration row, or if the tirbase-sim InvariantChecker production caller
# is missing. This is the CI catalog check referenced by task 17 wiring
# mutation checks: removing any INV-N entry from system-invariants.md must
# fail CI.
#
# Usage: bash scripts/check-system-invariants.sh [CATALOG_PATH]
set -euo pipefail

CATALOG="${1:-docs/system-invariants.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

if [[ ! -f "$CATALOG" ]]; then
  echo "ERROR: system invariants catalog not found at '$CATALOG'" >&2
  exit 1
fi

fail=0
for n in $(seq 1 16); do
  if ! grep -Eq "^\| INV-${n} \|" "$CATALOG"; then
    echo "ERROR: missing INV-${n} registration row in ${CATALOG}" >&2
    fail=1
  fi
done

# Verify tirbase-sim calls the checks via InvariantChecker (CLAIM-17.1..17.8,
# CLAIM-38.6). The production caller lives in tirbase-sim/src/invariants.rs.
if [[ ! -f "tirbase-sim/src/invariants.rs" ]]; then
  echo "ERROR: missing tirbase-sim/src/invariants.rs (InvariantChecker production caller)" >&2
  fail=1
elif ! grep -Eq 'pub (struct|fn) InvariantChecker|impl InvariantChecker' tirbase-sim/src/invariants.rs; then
  echo "ERROR: tirbase-sim/src/invariants.rs does not define InvariantChecker" >&2
  fail=1
fi

# Every INV must be referenced by the checker implementation.
for n in $(seq 1 16); do
  if [[ -f "tirbase-sim/src/invariants.rs" ]] && ! grep -Eq "INV[-_]?${n}\b|Inv${n}\b|check_inv_?${n}\b" tirbase-sim/src/invariants.rs; then
    echo "ERROR: tirbase-sim/src/invariants.rs does not reference INV-${n}" >&2
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "" >&2
  echo "Fix: restore the missing INV registration row(s) / InvariantChecker wiring." >&2
  echo "     See PV-23.1, PV-23.2, and tasks 17.1-17.8 / 38.6." >&2
  exit 1
fi

echo "OK: docs/system-invariants.md registers INV-1..INV-16 and tirbase-sim InvariantChecker references each check."
