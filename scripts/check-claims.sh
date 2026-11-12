#!/usr/bin/env bash
# check-claims.sh — Validate CLAIMS.md registry (CLAIM-3.1, PV-2.2)
#
# Two checks run over the registry:
#
#   1. Every row whose Status column is exactly "Proven" must have a non-empty
#      Test Identifier.
#   2. Every test identifier cited by a Proven row must resolve to something
#      that actually exists in the repository: a `fn <name>` declaration, a
#      `mod <name>` declaration, or a `<name>.rs` file. This is what stops a
#      claim from citing a test that was never written (or was renamed).
#
# How identifiers are extracted
# -----------------------------
# A "cited test identifier" is any of:
#   - a `::name` path segment (module prefixes are stripped, so
#     `tirbase-gateway/tests/lease_ops.rs::claim_21_1_x` cites `claim_21_1_x`);
#   - a name inside a `{a,b}` brace group (e.g.
#     `security_log.rs::{set_witness_source,try_checkpoint}`);
#   - a backticked token that is itself a bare snake_case identifier
#     (`claim_31_3_open_icos_survive_simulated_crash`);
#   - for cells that contain no backticks at all, a comma-separated segment that
#     is a bare snake_case identifier.
#
# CI job names, cargo invocations, file paths, paths in prose and
# Production-symbol names with uppercase letters are not test identifiers and
# are ignored. Only lowercase snake_case names are resolved.
#
#   3. A Proven row may NOT cite a test annotated `#[ignore]`. An ignored test
#      never runs in CI, so it cannot prove anything; such a claim must be
#      Planned (or carry a separate CI job that actually executes it). This
#      closes the "Proven on an ignored HIL test" hole (CLAIM-52.2/52.3).
#
# Usage: bash scripts/check-claims.sh [path/to/CLAIMS.md]
#
# Exit codes:
#   0 — every Proven claim has a test identifier and every cited identifier exists
#   1 — a Proven claim is missing an identifier, or cites one that does not exist

set -euo pipefail

CLAIMS_FILE="${1:-CLAIMS.md}"

if [[ ! -f "$CLAIMS_FILE" ]]; then
  echo "ERROR: CLAIMS.md not found at '$CLAIMS_FILE'" >&2
  echo "       Run this script from the workspace root or pass the path as an argument." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$CLAIMS_FILE")" && pwd)"

# ---------------------------------------------------------------------------
# Build an index of every symbol a citation could legitimately resolve to.
#
#   - `fn <name>` / `mod <name>` declarations in any .rs file
#   - each .rs file's stem (cites like `tirbase-gateway/tests/task18_db_split.rs`
#     or `command_role_tests` naming a module)
# ---------------------------------------------------------------------------
if ! command -v grep >/dev/null 2>&1; then
  echo "ERROR: grep is required" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
symbols_file="$work_dir/symbols"

{
  grep -rhoE '\b(fn|mod)[[:space:]]+[a-z_][a-z0-9_]*' \
    --include='*.rs' --exclude-dir=target --exclude-dir=.git \
    -- "$REPO_ROOT" 2>/dev/null \
    | awk '{print $2}'
  find "$REPO_ROOT" -name '*.rs' -not -path '*/target/*' -not -path '*/.git/*' 2>/dev/null \
    | sed -e 's#.*/##' -e 's#\.rs$##'
} | sort -u > "$symbols_file"

# ---------------------------------------------------------------------------
# Index every `fn` declared immediately after `#[ignore...]` so a Proven row
# cannot rest on a test that never runs.
# ---------------------------------------------------------------------------
ignored_file="$work_dir/ignored"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$REPO_ROOT" > "$ignored_file" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
pat = re.compile(r"#\[ignore[^\]]*\]")
fn = re.compile(r"\bfn\s+([a-z_][a-z0-9_]*)")

# A workflow line that runs `--ignored` for a given test target does execute
# ignored tests, so an ignored test cited there IS executable evidence (for
# example the memory-budget gate). Collect those honored targets first.
workflow_lines = []
for wf in (root / ".github" / "workflows").glob("*.yml"):
    try:
        workflow_lines.extend(wf.read_text(errors="ignore").splitlines())
    except OSError:
        pass

for p in root.rglob("*.rs"):
    if "target" in p.parts or ".git" in p.parts:
        continue
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except OSError:
        continue
    for i, line in enumerate(lines):
        if not pat.search(line):
            continue
        for nxt in lines[i + 1 : i + 8]:
            m = fn.search(nxt)
            if not m:
                continue
            name = m.group(1)
            stem = p.stem
            honored = any(
                "--ignored" in wl and stem in wl for wl in workflow_lines
            )
            if not honored:
                print(name)
            break
PY
else
  : > "$ignored_file"
fi
sort -u -o "$ignored_file" "$ignored_file"

is_ignored() {
  [[ -s "$ignored_file" ]] && grep -Fqx -- "$1" "$ignored_file"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

has_symbol() {
  grep -Fqx -- "$1" "$symbols_file"
}

missing_ids=()
ignored_ids=()
missing_claims=()
checked_citations=0
proven_count=0

# Emit candidate identifiers for one Test Identifier cell.
extract_candidates() {
  local cell="$1"
  local span

  # `a::b::name` chains anywhere in the cell: keep the final segment only,
  # so `tirbase-gateway/tests/lease_ops.rs::claim_21_1_x` cites `claim_21_1_x`.
  grep -oE '([A-Za-z_][A-Za-z0-9_]*::)+[a-z_][A-Za-z0-9_]*' <<<"$cell" \
    | sed 's/.*:://' || true

  # `{a,b}` brace groups, but only inside backticked spans that name a Rust
  # file (e.g. `security_log.rs::{set_witness_source,try_checkpoint}`). Other
  # braces are struct literals or SQL/config placeholders, not citations.
  while IFS= read -r span; do
    [[ "$span" == *'.rs'* ]] || continue
    grep -oE '\{[^{}]*\}' <<<"$span" | tr -d '{}' | tr ',' '\n' \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\.rs$//' || true
  done < <(grep -oE '`[^`]*`' <<<"$cell" | tr -d '`' || true)

  # Backticked bare identifiers.
  grep -oE '`[a-z_][a-z0-9_]*`' <<<"$cell" | tr -d '`' || true

  # Unbackticked cells: treat comma-separated bare identifiers as citations.
  if [[ "$cell" != *'`'* ]]; then
    tr ',' '\n' <<<"$cell" \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
      | grep -E '^[a-z_][a-z0-9_]*$' || true
  fi
}

while IFS= read -r line; do
  # Skip blank lines, HTML comments, and lines that are not table rows.
  [[ -z "$line" ]] && continue
  [[ "$line" == *'<!--'* ]] && continue
  [[ "$line" == *'|'* ]] || continue

  # Skip the header row and separator rows (cells contain only dashes/spaces).
  [[ "$line" =~ ^\|[[:space:]]*Claim[[:space:]]+ID ]] && continue
  [[ "$line" =~ ^\|[-|[:space:]]+\|$ ]] && continue
  stripped="${line//|/}"
  stripped="${stripped//[[:space:]]/}"
  stripped="${stripped//-/}"
  [[ -z "$stripped" ]] && continue

  IFS='|' read -ra cols <<< "$line"

  # We need at least 5 elements (indices 0-4) for a valid data row.
  if [[ "${#cols[@]}" -lt 5 ]]; then
    continue
  fi

  claim_id="$(trim "${cols[1]}")"
  status="$(trim "${cols[3]}")"
  test_id="$(trim "${cols[4]}")"

  # Only Proven rows are gated (case-sensitive).
  [[ "$status" == "Proven" ]] || continue
  [[ -n "$claim_id" ]] || continue
  proven_count=$((proven_count + 1))

  if [[ -z "$test_id" ]]; then
    missing_claims+=("$claim_id")
    continue
  fi

  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    # Only lowercase snake_case names are treated as test identifiers.
    [[ "$candidate" =~ ^[a-z_][a-z0-9_]*$ ]] || continue
    # `tests` and `mod` name modules, not test functions.
    [[ "$candidate" == "tests" || "$candidate" == "mod" ]] && continue
    checked_citations=$((checked_citations + 1))
    if ! has_symbol "$candidate"; then
      missing_ids+=("${claim_id}: ${candidate}")
    elif is_ignored "$candidate"; then
      ignored_ids+=("${claim_id}: ${candidate} (#[ignore] — never executed by CI)")
    fi
  done < <(extract_candidates "$test_id" | awk 'NF' | sort -u)

done < "$CLAIMS_FILE"

# ---------------------------------------------------------------------------
# Report results.
# ---------------------------------------------------------------------------

status=0

if [[ "${#missing_claims[@]}" -gt 0 ]]; then
  echo "ERROR: The following Proven claim(s) in '${CLAIMS_FILE}' are missing a test identifier:" >&2
  echo "" >&2
  printf '  - %s\n' "${missing_claims[@]}" >&2
  echo "" >&2
  echo "Fix: add a non-empty Test Identifier to each row above, or change its Status to 'Planned'." >&2
  echo "     See PV-2.2 and task 3.1 for the requirement." >&2
  status=1
fi

if [[ "${#missing_ids[@]}" -gt 0 ]]; then
  echo "ERROR: The following cited test identifier(s) in '${CLAIMS_FILE}' do not exist in the repo:" >&2
  echo "       (no matching 'fn <name>', 'mod <name>' or '<name>.rs' was found)" >&2
  echo "" >&2
  printf '  - %s\n' "${missing_ids[@]}" >&2
  echo "" >&2
  echo "Fix: cite a real test function/module, or change the row's Status to 'Planned'." >&2
  status=1
fi

if [[ "${#ignored_ids[@]}" -gt 0 ]]; then
  echo "ERROR: The following Proven claim(s) cite a test marked #[ignore]:" >&2
  echo "       An ignored test never runs in CI and cannot prove a claim." >&2
  echo "" >&2
  printf '  - %s\n' "${ignored_ids[@]}" >&2
  echo "" >&2
  echo "Fix: change the row's Status to 'Planned', or cite a test that CI actually runs." >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  echo "OK: All ${proven_count} Proven claim(s) in ${CLAIMS_FILE} have a test identifier,"
  echo "    and all ${checked_citations} cited identifier reference(s) resolve to real code."
  exit 0
fi

exit 1
