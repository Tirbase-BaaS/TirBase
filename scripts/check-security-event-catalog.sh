#!/usr/bin/env bash
# check-security-event-catalog.sh — Security event catalog completeness check (CLAIM-3.9, PV-7.11)
#
# Parses docs/security-event-catalog.md to build the allowed set of
# SecurityEventCategory variants and ReasonCode variants, then scans production
# Rust source files for any `SecurityEventCategory::Variant` or
# `ReasonCode::Variant` references not present in the catalog.
#
# Production source roots scanned (tests/ subdirectories excluded):
# tirbase-core/src/
# tirbase-guard/src/
# tirbase-gateway/src/
# tirbase-drivers/src/
# tirbase-admin/src/
#
# Usage: bash scripts/check-security-event-catalog.sh [CATALOG_PATH]
#
# Exit codes:
# 0 — all production references are listed in the catalog (or no references found)
# 1 — one or more unlisted references found, or catalog file missing

set -euo pipefail

CATALOG="${1:-docs/security-event-catalog.md}"

# ---------------------------------------------------------------------------
# Locate workspace root (the directory that contains the workspace Cargo.toml)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

if [[ ! -f "$CATALOG" ]]; then
  echo "ERROR: Security event catalog not found at '$CATALOG'" >&2
  echo "       Run this script from the workspace root or pass the path as an argument." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Temporary files for the allowed sets (avoids bash 4 associative arrays so
# the script works with bash 3 on macOS and older CI images)
# ---------------------------------------------------------------------------
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

ALLOWED_CATEGORIES_FILE="$TMP_DIR/categories.txt"     # one CategoryName per line
ALLOWED_REASON_CODES_FILE="$TMP_DIR/reason_codes.txt" # one ReasonCode per line

touch "$ALLOWED_CATEGORIES_FILE" "$ALLOWED_REASON_CODES_FILE"

# ---------------------------------------------------------------------------
# Parse catalog
#
# The catalog uses the format:
# ## Category: <CategoryName>
# | Reason Code | ... |
# | ActualCode | ... |
#
# We collect every CategoryName from the "## Category:" headings and every
# first-column value from the data rows under each heading.
# ---------------------------------------------------------------------------

current_category=""

while IFS= read -r line; do
 # Match category headers: ## Category: FooBar
  if [[ "$line" =~ ^##[[:space:]]Category:[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)$ ]]; then
    current_category="${BASH_REMATCH[1]}"
    echo "$current_category" >> "$ALLOWED_CATEGORIES_FILE"
    continue
  fi

 # Skip non-table lines
  [[ "$line" != *\|* ]] && continue

 # Skip separator rows (only dashes, pipes, spaces)
  stripped="${line//|/}"
  stripped="${stripped// /}"
  stripped="${stripped//-/}"
  [[ -z "$stripped" ]] && continue

 # Split on '|' and extract first column (reason code)
  IFS='|' read -ra cols <<< "$line"
  [[ "${#cols[@]}" -lt 2 ]] && continue
  reason_code="$(echo "${cols[1]}" | tr -d '[:space:]')"

 # Skip header row and empty cells
  [[ -z "$reason_code" ]] && continue
  [[ "$reason_code" == "ReasonCode" ]] && continue

  echo "$reason_code" >> "$ALLOWED_REASON_CODES_FILE"
done < "$CATALOG"

# Deduplicate
sort -u -o "$ALLOWED_CATEGORIES_FILE" "$ALLOWED_CATEGORIES_FILE"
sort -u -o "$ALLOWED_REASON_CODES_FILE" "$ALLOWED_REASON_CODES_FILE"

CATALOG_CATEGORY_COUNT=$(wc -l < "$ALLOWED_CATEGORIES_FILE" | tr -d ' ')
CATALOG_REASON_COUNT=$(wc -l < "$ALLOWED_REASON_CODES_FILE" | tr -d ' ')

echo "Catalog: ${CATALOG_CATEGORY_COUNT} categories, ${CATALOG_REASON_COUNT} reason code(s) loaded from '${CATALOG}'"

# ---------------------------------------------------------------------------
# Collect production source files
# Exclude files under any 'tests' subdirectory.
# ---------------------------------------------------------------------------

SOURCE_ROOTS=(
  "tirbase-core/src"
  "tirbase-guard/src"
  "tirbase-gateway/src"
  "tirbase-drivers/src"
  "tirbase-admin/src"
)

PRODUCTION_FILES_LIST="$TMP_DIR/production_files.txt"
touch "$PRODUCTION_FILES_LIST"

for root in "${SOURCE_ROOTS[@]}"; do
  if [[ -d "$root" ]]; then
    find "$root" -name "*.rs" -type f 2>/dev/null | while IFS= read -r f; do
 # Exclude files inside a 'tests' subdirectory
      if [[ "$f" != */tests/* ]]; then
        echo "$f"
      fi
    done >> "$PRODUCTION_FILES_LIST"
  fi
done

file_count=$(wc -l < "$PRODUCTION_FILES_LIST" | tr -d ' ')
echo "Scanning: ${file_count} production Rust file(s) (tests/ excluded)"

if [[ "$file_count" -eq 0 ]]; then
  echo "OK: No production source files found to scan (crate stubs not yet created)."
  echo "    Catalog check passes vacuously — files will be enforced once crates are scaffolded."
  exit 0
fi

# ---------------------------------------------------------------------------
# Scan production files for SecurityEventCategory::Variant and ReasonCode::Variant
#
# For each .rs file we:
# 1. Strip content inside #[cfg(test)] mod blocks (best-effort awk approach).
# 2. Grep for the two enum-qualifier patterns.
# 3. Extract the variant name (the part after '::').
# 4. Check it against the catalog's allowed sets.
# ---------------------------------------------------------------------------

FAILING_CATEGORIES_FILE="$TMP_DIR/failing_categories.txt"
FAILING_REASONS_FILE="$TMP_DIR/failing_reasons.txt"
touch "$FAILING_CATEGORIES_FILE" "$FAILING_REASONS_FILE"

total_category_refs=0
total_reason_refs=0

while IFS= read -r src_file; do
  [[ -z "$src_file" ]] && continue

 # Strip cfg(test) blocks: skip from #[cfg(test)] until the matching closing
 # brace at depth 0. This handles the common pattern:
 # #[cfg(test)]
 # mod tests { ... }
  stripped_content=$(awk '
    BEGIN { skip=0; depth=0 }
    /^[[:space:]]*#\[cfg\(test\)\]/ { skip=1; next }
    skip && /{/ { depth++ }
    skip && /}/ {
      if (depth == 0) { skip=0; next }
      depth--
      next
    }
    skip { next }
    { print }
  ' "$src_file")

 # --- SecurityEventCategory references ---
  category_refs=$(echo "$stripped_content" | grep -oE 'SecurityEventCategory::[A-Za-z_][A-Za-z0-9_]*' || true)
  while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    variant="${match##*::}"
    total_category_refs=$(( total_category_refs + 1 ))
 # Check if variant is in the allowed categories file
    if ! grep -qxF "$variant" "$ALLOWED_CATEGORIES_FILE"; then
      echo "${src_file}: SecurityEventCategory::${variant}" >> "$FAILING_CATEGORIES_FILE"
    fi
  done <<< "$category_refs"

 # --- ReasonCode references ---
  reason_refs=$(echo "$stripped_content" | grep -oE 'ReasonCode::[A-Za-z_][A-Za-z0-9_]*' || true)
  while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    variant="${match##*::}"
    total_reason_refs=$(( total_reason_refs + 1 ))
    if ! grep -qxF "$variant" "$ALLOWED_REASON_CODES_FILE"; then
      echo "${src_file}: ReasonCode::${variant}" >> "$FAILING_REASONS_FILE"
    fi
  done <<< "$reason_refs"

done < "$PRODUCTION_FILES_LIST"

echo "Found: ${total_category_refs} SecurityEventCategory reference(s), ${total_reason_refs} ReasonCode reference(s) in production source"

# ---------------------------------------------------------------------------
# Report results
# ---------------------------------------------------------------------------

exit_code=0

failing_cat_count=$(wc -l < "$FAILING_CATEGORIES_FILE" | tr -d ' ')
failing_reason_count=$(wc -l < "$FAILING_REASONS_FILE" | tr -d ' ')

if [[ "$failing_cat_count" -gt 0 ]]; then
  echo "" >&2
  echo "ERROR: The following SecurityEventCategory variant(s) are not listed in '${CATALOG}':" >&2
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    echo "  - ${item}" >&2
  done < "$FAILING_CATEGORIES_FILE"
  echo "" >&2
  echo "Fix: add a '## Category: <Variant>' section to ${CATALOG} for each unlisted category." >&2
  exit_code=1
fi

if [[ "$failing_reason_count" -gt 0 ]]; then
  echo "" >&2
  echo "ERROR: The following ReasonCode variant(s) are not listed in '${CATALOG}':" >&2
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    echo "  - ${item}" >&2
  done < "$FAILING_REASONS_FILE"
  echo "" >&2
  echo "Fix: add a table row with the variant name under the appropriate Category section in ${CATALOG}." >&2
  exit_code=1
fi

if [[ "$exit_code" -eq 0 ]]; then
  echo "OK: All production SecurityEventCategory and ReasonCode references are listed in the catalog."
fi

exit "$exit_code"
