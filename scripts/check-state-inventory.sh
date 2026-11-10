#!/usr/bin/env bash
# check-state-inventory.sh — State inventory completeness (CLAIM-31.1/31.2, PV-9.1)
#
# The gate derives the list of stateful types from production source instead of
# trusting hand-written annotations: every named-field `struct` under the
# production source roots must have a row in docs/state-inventory.md that names
# both the struct and its file.  Adding an unlisted struct fails the gate.
#
# Usage: bash scripts/check-state-inventory.sh [INVENTORY_PATH]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

INVENTORY="${1:-docs/state-inventory.md}"

if [[ ! -f "$INVENTORY" ]]; then
  echo "ERROR: State inventory not found at '$INVENTORY'" >&2
  exit 1
fi

exec python3 "${SCRIPT_DIR}/state_inventory_scan.py" --check "$INVENTORY"
