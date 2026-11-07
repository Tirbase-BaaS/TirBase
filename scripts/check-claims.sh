#!/usr/bin/env bash
# check-claims.sh — Validate CLAIMS.md registry (CLAIM-3.1, PV-2.2)
#
# Parses CLAIMS.md and fails with a descriptive error if any row whose Status
# column contains exactly "Proven" has an empty or missing Test Identifier.
#
# Usage: bash scripts/check-claims.sh [path/to/CLAIMS.md]
#
# Exit codes:
#   0 — all Proven claims have a non-empty test identifier
#   1 — one or more Proven claims are missing a test identifier

set -euo pipefail

CLAIMS_FILE="${1:-CLAIMS.md}"

if [[ ! -f "$CLAIMS_FILE" ]]; then
  echo "ERROR: CLAIMS.md not found at '$CLAIMS_FILE'" >&2
  echo "       Run this script from the workspace root or pass the path as an argument." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Parse the markdown table.
#
# Expected format (columns separated by '|'):
#   | Claim ID | Claim Text | Status | Test Identifier |
#
# Rules:
#   - Lines that are header rows (contain "Claim ID") are skipped.
#   - Lines that are separator rows (contain only '-', '|', ' ') are skipped.
#   - Comment lines (starting with '<!--') are skipped.
#   - All other '|'-delimited lines are treated as data rows.
#   - Status is column 3 (0-indexed: col index 3 after splitting on '|').
#   - Test Identifier is column 4.
#   - Whitespace is stripped from both fields before comparison.
# ---------------------------------------------------------------------------

failing_claims=()

while IFS= read -r line; do
  # Skip blank lines, HTML comments, and lines that are not table rows.
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*\<\!-- ]] && continue
  [[ "$line" != *\|* ]] && continue

  # Skip the header row and separator rows (cells contain only dashes/spaces).
  [[ "$line" =~ ^\|[[:space:]]*Claim[[:space:]]+ID ]] && continue
  [[ "$line" =~ ^\|[-|[:space:]]+\|$ ]] && continue
  # Also skip lines where every cell is purely dashes/spaces (table separators
  # that do not end with a trailing '|' in some markdown flavours).
  stripped="${line//|/}"
  stripped="${stripped// /}"
  stripped="${stripped//-/}"
  [[ -z "$stripped" ]] && continue

  # Split on '|'. After splitting "| A | B | C | D |" we get:
  #   col[0]=""  col[1]="A"  col[2]="B"  col[3]="C"  col[4]="D"  col[5]=""
  IFS='|' read -ra cols <<< "$line"

  # We need at least 5 elements (indices 0-4) for a valid data row.
  if [[ "${#cols[@]}" -lt 5 ]]; then
    continue
  fi

  claim_id="$(echo "${cols[1]}" | xargs)"   # trim whitespace
  status="$(echo "${cols[3]}" | xargs)"
  test_id="$(echo "${cols[4]}" | xargs)"

  # Only check rows whose Status is exactly "Proven" (case-sensitive).
  [[ "$status" != "Proven" ]] && continue

  # Skip if no claim ID (malformed row).
  [[ -z "$claim_id" ]] && continue

  if [[ -z "$test_id" ]]; then
    failing_claims+=("$claim_id")
  fi

done < "$CLAIMS_FILE"

# ---------------------------------------------------------------------------
# Report results.
# ---------------------------------------------------------------------------

if [[ "${#failing_claims[@]}" -eq 0 ]]; then
  # Count total Proven claims for a useful success message.
  proven_count=$(grep -c '| Proven |' "$CLAIMS_FILE" || true)
  echo "OK: All ${proven_count} Proven claim(s) in ${CLAIMS_FILE} have a test identifier."
  exit 0
fi

echo "ERROR: The following Proven claim(s) in '${CLAIMS_FILE}' are missing a test identifier:" >&2
echo "" >&2
for cid in "${failing_claims[@]}"; do
  echo "  - ${cid}" >&2
done
echo "" >&2
echo "Fix: add a non-empty Test Identifier to each row above, or change its Status to 'Planned'." >&2
echo "     See PV-2.2 and task 3.1 for the requirement." >&2
exit 1
