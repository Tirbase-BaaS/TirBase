#!/usr/bin/env bash
# check-claim-markers.sh — [CLAIM-{id}] marker scan in documentation (CLAIM-3.2, PV-2.3)
#
# Scans documentation files for [CLAIM-{id}] markers and fails CI if any
# marker references a Planned claim without explicitly stating it as planned on
# the same line.
#
# Usage: bash scripts/check-claim-markers.sh [path/to/CLAIMS.md]
#
# Exit codes:
#   0 — no violations found
#   1 — one or more Planned claim markers found without a planned qualifier

set -euo pipefail

CLAIMS_FILE="${1:-CLAIMS.md}"
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$CLAIMS_FILE" ]]; then
  echo "ERROR: CLAIMS.md not found at '$CLAIMS_FILE'" >&2
  echo "       Run this script from the workspace root or pass the path as an argument." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Build a newline-separated list of all claim IDs whose status is
#         "Planned".  Stored in a temp file for bash-3-compatible lookup.
# ---------------------------------------------------------------------------
# Uses the same pipe-separated table parsing logic as check-claims.sh.
# Column layout after splitting on '|':
#   col[0]=""  col[1]="Claim ID"  col[2]="Claim Text"  col[3]="Status"  col[4]="Test ID"  col[5]=""

planned_ids_file="$(mktemp)"
trap 'rm -f "$planned_ids_file"' EXIT

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^[[:space:]]*\<\!-- ]] && continue
  [[ "$line" != *\|* ]] && continue
  [[ "$line" =~ ^\|[[:space:]]*Claim[[:space:]]+ID ]] && continue
  [[ "$line" =~ ^\|[-|[:space:]]+\|$ ]] && continue
  stripped="${line//|/}"
  stripped="${stripped// /}"
  stripped="${stripped//-/}"
  [[ -z "$stripped" ]] && continue

  IFS='|' read -ra cols <<< "$line"
  [[ "${#cols[@]}" -lt 5 ]] && continue

  claim_id="$(echo "${cols[1]}" | xargs)"
  status="$(echo "${cols[3]}" | xargs)"

  [[ -z "$claim_id" ]] && continue
  [[ "$status" != "Planned" ]] && continue

  echo "$claim_id" >> "$planned_ids_file"
done < "$CLAIMS_FILE"

planned_count="$(wc -l < "$planned_ids_file" | xargs)"
echo "Found ${planned_count} Planned claim(s) in ${CLAIMS_FILE}."

# Helper: check whether a given claim ID is in the Planned set.
is_planned() {
  grep -qxF "$1" "$planned_ids_file"
}

# ---------------------------------------------------------------------------
# Step 2: Collect documentation files to scan.
# ---------------------------------------------------------------------------
# Scan: root-level *.md, docs/**/*.md, .kiro/specs/**/*.md
# Exclude: CLAIMS.md itself (source of truth), tasks.md (structured non-prose)

scan_files_raw="$(mktemp)"
trap 'rm -f "$planned_ids_file" "$scan_files_raw"' EXIT

cd "$WORKSPACE_ROOT"

# Root-level markdown files
find . -maxdepth 1 -name "*.md" -type f 2>/dev/null >> "$scan_files_raw" || true
# docs/ markdown files
find docs -name "*.md" -type f 2>/dev/null >> "$scan_files_raw" || true
# .kiro/specs/ markdown files
find .kiro/specs -name "*.md" -type f 2>/dev/null >> "$scan_files_raw" || true

# Filter: exclude CLAIMS.md and any tasks.md
filtered_files="$(mktemp)"
trap 'rm -f "$planned_ids_file" "$scan_files_raw" "$filtered_files"' EXIT

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  normalized_f="${f#./}"
  [[ "$normalized_f" == "CLAIMS.md" ]] && continue
  basename_f="$(basename "$normalized_f")"
  [[ "$basename_f" == "tasks.md" ]] && continue
  echo "$f" >> "$filtered_files"
done < "$scan_files_raw"

file_count="$(wc -l < "$filtered_files" | xargs)"
echo "Scanning ${file_count} documentation file(s) for [CLAIM-{id}] markers..."

# ---------------------------------------------------------------------------
# Step 3: Scan each file for [CLAIM-{id}] markers and check qualifiers.
# ---------------------------------------------------------------------------
# Qualifiers that indicate a Planned claim is acceptably documented (case-insensitive,
# checked against the same line as the marker):
#   planned, not yet, todo, future, in progress, upcoming, will be, status: planned

MARKER_PATTERN='\[CLAIM-[A-Za-z0-9._-]*\]'

violations_file="$(mktemp)"
trap 'rm -f "$planned_ids_file" "$scan_files_raw" "$filtered_files" "$violations_file"' EXIT

while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  full_path="$WORKSPACE_ROOT/$file"
  [[ ! -f "$full_path" ]] && continue

  # Find all lines containing at least one [CLAIM-*] marker.
  while IFS= read -r match_line; do
    [[ -z "$match_line" ]] && continue

    # match_line format from grep -n: "LINE_NUMBER:LINE_CONTENT"
    line_num="${match_line%%:*}"
    line_content="${match_line#*:}"

    # Extract all [CLAIM-{id}] markers from this line.
    markers="$(echo "$line_content" | grep -oE "$MARKER_PATTERN" || true)"
    [[ -z "$markers" ]] && continue

    while IFS= read -r marker; do
      [[ -z "$marker" ]] && continue

      # Strip surrounding brackets: [CLAIM-G1.1] → CLAIM-G1.1
      claim_id="${marker:1:${#marker}-2}"

      # Only check Planned claims.
      is_planned "$claim_id" || continue

      # Check whether the line contains a planned qualifier (case-insensitive).
      if echo "$line_content" | grep -qiE \
          '(planned|not yet|todo|future|in progress|upcoming|will be|status:[[:space:]]*planned)'; then
        # Qualifier found — this reference is acceptable.
        continue
      fi

      # No qualifier found — record violation as "file:linenum: CLAIM-ID"
      # Normalize: strip leading "./" for cleaner output.
      display_file="${file#./}"
      echo "${display_file}:${line_num}: ${claim_id}" >> "$violations_file"
    done <<< "$markers"
  done < <(grep -n "$MARKER_PATTERN" "$full_path" 2>/dev/null || true)
done < "$filtered_files"

# ---------------------------------------------------------------------------
# Step 4: Report results.
# ---------------------------------------------------------------------------

violation_count="$(wc -l < "$violations_file" | xargs)"

if [[ "$violation_count" -eq 0 ]]; then
  echo "OK: No undeclared Planned claim references found."
  exit 0
fi

echo "" >&2
echo "ERROR: The following documentation lines reference a Planned claim without" >&2
echo "       stating it as planned (CLAIM-3.2, PV-2.3):" >&2
echo "" >&2
while IFS= read -r v; do
  echo "  ${v}" >&2
done < "$violations_file"
echo "" >&2
echo "Fix: Add a planned qualifier on the same line as the marker, e.g.:" >&2
echo '     "[CLAIM-4.1] (planned) will add tirbase-types crate"' >&2
echo "" >&2
echo "Accepted qualifiers (case-insensitive): planned, not yet, todo, future," >&2
echo "  in progress, upcoming, will be, status: planned" >&2
exit 1
