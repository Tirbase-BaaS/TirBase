#!/usr/bin/env bash
# check-geiger.sh — CLAIM-2.4
#
# Usage:
#   check-geiger.sh <new-report.json> [baseline.json]
#
# Counts the total unsafe blocks in a `cargo geiger --output-format Json`
# report and compares it to the previous baseline. If the count has
# increased the script exits with status 1 and prints the old vs. new
# counts.  If no baseline is supplied the script exits 0 (first run) and
# prints the initial count.
#
# The script counts ONLY the "used" unsafe counters so that unused dead-code
# blocks do not mask real regressions.  The JSON structure produced by
# cargo-geiger looks like:
#
#   {
#     "packages": [
#       {
#         "unsafety": {
#           "used": {
#             "exprs": { "safe": N, "unsafe_": N },
#             "item_impls": { "safe": N, "unsafe_": N },
#             "item_traits": { "safe": N, "unsafe_": N },
#             "methods": { "safe": N, "unsafe_": N }
#           },
#           ...
#         }
#       }
#     ]
#   }
#
# We sum every `unsafe_` field inside every `used` block across all packages.

set -euo pipefail

NEW_REPORT="${1:-}"
BASELINE="${2:-}"

if [[ -z "$NEW_REPORT" ]]; then
    echo "Usage: $0 <new-report.json> [baseline.json]" >&2
    exit 2
fi

if [[ ! -f "$NEW_REPORT" ]]; then
    echo "ERROR: new report file not found: $NEW_REPORT" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Count total used-unsafe entries in a geiger JSON report.
# ---------------------------------------------------------------------------
count_unsafe() {
    local file="$1"
    # Sum all `unsafe_` values that live inside a `used` object.
    # python3 is available on the GitHub-hosted ubuntu-latest runner.
    python3 - "$file" <<'PYEOF'
import json, sys

def count(obj):
    total = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "used":
                # v is a dict like {"exprs": {...}, "item_impls": {...}, ...}
                for category_counts in v.values():
                    if isinstance(category_counts, dict):
                        total += category_counts.get("unsafe_", 0)
            else:
                total += count(v)
    elif isinstance(obj, list):
        for item in obj:
            total += count(item)
    return total

with open(sys.argv[1]) as f:
    data = json.load(f)

print(count(data))
PYEOF
}

NEW_COUNT=$(count_unsafe "$NEW_REPORT")
echo "cargo-geiger: current unsafe block count = ${NEW_COUNT}"

# ---------------------------------------------------------------------------
# First run: no baseline available.
# ---------------------------------------------------------------------------
if [[ -z "$BASELINE" || ! -f "$BASELINE" ]]; then
    echo "No baseline found — this is the first run. Saving count ${NEW_COUNT} as the new baseline."
    # The CI step saves NEW_REPORT as the artifact; nothing more to do here.
    exit 0
fi

BASELINE_COUNT=$(count_unsafe "$BASELINE")
echo "cargo-geiger: baseline unsafe block count = ${BASELINE_COUNT}"

# ---------------------------------------------------------------------------
# Gate: fail on net increase.
# ---------------------------------------------------------------------------
if [[ "$NEW_COUNT" -gt "$BASELINE_COUNT" ]]; then
    echo ""
    echo "FAIL [CLAIM-2.4]: unsafe block count increased."
    echo "  Baseline : ${BASELINE_COUNT}"
    echo "  Current  : ${NEW_COUNT}"
    echo "  Delta    : +$((NEW_COUNT - BASELINE_COUNT))"
    echo ""
    echo "Resolve by:"
    echo "  1. Removing the new unsafe block(s), or"
    echo "  2. Placing them in an FFI-boundary crate as permitted by PV-1.11, or"
    echo "  3. Obtaining explicit approval and updating the baseline artifact."
    exit 1
fi

if [[ "$NEW_COUNT" -lt "$BASELINE_COUNT" ]]; then
    echo "unsafe block count decreased by $((BASELINE_COUNT - NEW_COUNT)) — well done."
fi

echo "PASS [CLAIM-2.4]: unsafe block count has not increased (${NEW_COUNT})."
exit 0
