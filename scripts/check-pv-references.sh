#!/usr/bin/env bash
# check-pv-references.sh — PV-X.Y reference integrity check (CLAIM-5.9, PV-1.7)
#
# Parses all `_Requirements: PV-X.Y_` markers in tasks.md and verifies that
# each cited PV requirement exists in requirements.md.  Fails CI if any
# referenced PV-X.Y is orphaned (i.e. the combination of section number X and
# acceptance criterion number Y does not exist in requirements.md).
#
# How PV-X.Y identifiers are declared in requirements.md:
#   Section headers:          ### PV-X: <title>
#   Acceptance criteria:      1. THE System SHALL ...
#                             2. WHEN ...
#   The identifier PV-X.Y is implied by section X, AC number Y.
#
# Usage: bash scripts/check-pv-references.sh [tasks_file] [requirements_file]
#
# Defaults:
#   tasks_file:        .kiro/specs/tirbase-master-enhancement/tasks.md
#   requirements_file: .kiro/specs/tirbase-master-enhancement/requirements.md
#
# Exit codes:
#   0 — all PV references in tasks.md exist in requirements.md
#   1 — one or more orphaned references found

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKSPACE_ROOT"

TASKS_FILE="${1:-.kiro/specs/tirbase-master-enhancement/tasks.md}"
REQS_FILE="${2:-.kiro/specs/tirbase-master-enhancement/requirements.md}"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [[ ! -f "$TASKS_FILE" ]]; then
  echo "ERROR: tasks.md not found at '$TASKS_FILE'" >&2
  echo "       Run from the workspace root or pass the path as an argument." >&2
  exit 1
fi

if [[ ! -f "$REQS_FILE" ]]; then
  echo "ERROR: requirements.md not found at '$REQS_FILE'" >&2
  echo "       Run from the workspace root or pass the path as an argument." >&2
  exit 1
fi

echo "Checking PV references..."
echo "  tasks.md:        $TASKS_FILE"
echo "  requirements.md: $REQS_FILE"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Build the set of declared PV-X.Y identifiers from requirements.md.
#
# A PV-X.Y is considered declared when:
#   - A section header "### PV-X:" exists  (X is the section number)
#   - A numbered AC line "Y. ..." appears inside that section's
#     "#### Acceptance Criteria" block  (Y is the criterion number)
#
# Temp files are used to remain compatible with bash 3 (macOS default shell).
# ---------------------------------------------------------------------------
declared_file="$(mktemp)"
trap 'rm -f "$declared_file"' EXIT

current_section=""
in_ac_block="false"

while IFS= read -r line; do
  # --- Detect a PV section header: ### PV-<N>: <title> ---
  if echo "$line" | grep -qE '^### PV-[0-9]+:'; then
    current_section="$(echo "$line" | grep -oE 'PV-[0-9]+' | head -1 | sed 's/PV-//')"
    in_ac_block="false"
    continue
  fi

  # --- Reset on any top-level or second-level heading (## or #) ---
  if echo "$line" | grep -qE '^#{1,2} '; then
    current_section=""
    in_ac_block="false"
    continue
  fi

  # --- Detect start of Acceptance Criteria block ---
  if echo "$line" | grep -qE '^#### Acceptance Criteria'; then
    in_ac_block="true"
    continue
  fi

  # --- Detect start of any other #### block (ends the AC block) ---
  if echo "$line" | grep -qE '^#### '; then
    in_ac_block="false"
    continue
  fi

  # --- Record a declared PV-X.Y when inside an AC block ---
  if [[ "$in_ac_block" == "true" && -n "$current_section" ]]; then
    if echo "$line" | grep -qE '^[0-9]+\. '; then
      ac_num="$(echo "$line" | grep -oE '^[0-9]+' | head -1)"
      echo "PV-${current_section}.${ac_num}" >> "$declared_file"
    fi
  fi
done < "$REQS_FILE"

declared_count="$(wc -l < "$declared_file" | tr -d '[:space:]')"
echo "Found ${declared_count} declared PV-X.Y acceptance criteria in requirements.md."

# ---------------------------------------------------------------------------
# Step 2: Extract all PV-X.Y references from _Requirements: ..._  lines in
# tasks.md.  Only lines containing the _Requirements: marker are scanned so
# that incidental PV mentions in prose or comments are not checked.
# ---------------------------------------------------------------------------
referenced_file="$(mktemp)"
trap 'rm -f "$declared_file" "$referenced_file"' EXIT

# Match lines of the form:   - _Requirements: PV-7.11, PV-22.3_
# (possibly with multiple PV IDs, possibly alongside non-PV IDs like RD-7)
grep '_Requirements:' "$TASKS_FILE" \
  | grep -oE 'PV-[0-9]+\.[0-9]+' \
  | sort -u \
  > "$referenced_file" || true

referenced_count="$(wc -l < "$referenced_file" | tr -d '[:space:]')"
echo "Found ${referenced_count} distinct PV-X.Y references in _Requirements: markers."
echo ""

# ---------------------------------------------------------------------------
# Step 3: Identify orphaned references (referenced but not declared).
# ---------------------------------------------------------------------------
orphaned_file="$(mktemp)"
trap 'rm -f "$declared_file" "$referenced_file" "$orphaned_file"' EXIT

# `comm -23` requires both files to be sorted; $declared_file may have dupes,
# so sort and deduplicate it first.
sorted_declared="$(mktemp)"
trap 'rm -f "$declared_file" "$referenced_file" "$orphaned_file" "$sorted_declared"' EXIT
sort -u "$declared_file" > "$sorted_declared"

comm -23 \
  <(sort "$referenced_file") \
  "$sorted_declared" \
  > "$orphaned_file" || true

orphaned_count="$(wc -l < "$orphaned_file" | tr -d '[:space:]')"

# ---------------------------------------------------------------------------
# Step 4: Report results.
# ---------------------------------------------------------------------------
if [[ "$orphaned_count" -eq 0 ]]; then
  echo "OK: All PV references in tasks.md exist in requirements.md."
  exit 0
fi

echo "ERROR: The following PV requirement IDs are referenced in tasks.md but" >&2
echo "       do not exist as declared acceptance criteria in requirements.md:" >&2
echo "" >&2
while IFS= read -r orphan; do
  [[ -z "$orphan" ]] && continue
  # Find which _Requirements: lines cite this orphan for diagnostic context
  context="$(grep '_Requirements:.*'"${orphan}"'' "$TASKS_FILE" | head -3 | sed 's/^[[:space:]]*/    /')"
  echo "  ${orphan}" >&2
  if [[ -n "$context" ]]; then
    echo "$context" >&2
  fi
  echo "" >&2
done < "$orphaned_file"
echo "Fix: Add the missing acceptance criteria to requirements.md, or correct" >&2
echo "     the PV-X.Y identifier in the _Requirements: marker in tasks.md." >&2
exit 1
