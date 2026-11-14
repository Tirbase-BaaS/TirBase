#!/usr/bin/env bash
# check-claims.sh — Validate CLAIMS.md registry (CLAIM-3.1, PV-2.2)
#
# Two checks run over the registry:
#
# 1. Every row whose Status column is exactly "Proven" must have a non-empty
# Test Identifier.
# 2. Every test identifier cited by a gated row (Proven, Implemented and wired
# (unproven), Implemented but not wired) must resolve to something
# that actually exists in the repository: a `fn <name>` declaration, a
# `mod <name>` declaration, or a `<name>.rs` file. This is what stops a
# claim from citing a test that was never written (or was renamed).
#
# How identifiers are extracted
# -----------------------------
# A "cited test identifier" is any of:
# - a `::name` path segment (module prefixes are stripped, so
# `tirbase-gateway/tests/lease_ops.rs::claim_21_1_x` cites `claim_21_1_x`);
# - a name inside a `{a,b}` brace group (e.g.
# `security_log.rs::{set_witness_source,try_checkpoint}`);
# - a backticked token that is itself a bare snake_case identifier
# (`claim_31_3_open_icos_survive_simulated_crash`);
# - for cells that contain no backticks at all, a comma-separated segment that
# is a bare snake_case identifier.
#
# CI job names, cargo invocations, file paths, paths in prose and
# Production-symbol names with uppercase letters are not test identifiers and
# are ignored. Only lowercase snake_case names are resolved.
#
# 3. A Proven row may NOT cite a test annotated `#[ignore]`. An ignored test
# never runs in CI, so it cannot prove anything; such a claim must be
# Planned (or carry a separate CI job that actually executes it). This
# closes the "Proven on an ignored HIL test" hole (CLAIM-52.2/52.3).
#
# The schema half (five columns, closed status vocabulary, and production-caller
# reachability) is validated by scripts/check-claims-schema.py, which this script
# runs first.
#
# Usage: bash scripts/check-claims.sh [path/to/CLAIMS.md]
#
# Exit codes:
# 0 — every Proven claim has a test identifier and every cited identifier exists
# 1 — a Proven claim is missing an identifier, or cites one that does not exist

set -euo pipefail

CLAIMS_FILE="${1:-CLAIMS.md}"

if [[ ! -f "$CLAIMS_FILE" ]]; then
  echo "ERROR: CLAIMS.md not found at '$CLAIMS_FILE'" >&2
  echo "       Run this script from the workspace root or pass the path as an argument." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$CLAIMS_FILE")" && pwd)"

# Schema, status vocabulary, and production-caller evidence.
python3 "$REPO_ROOT/scripts/check-claims-schema.py" "$CLAIMS_FILE" || exit 1

# ---------------------------------------------------------------------------
# Build an index of every symbol a citation could legitimately resolve to.
#
# - `fn <name>` / `mod <name>` declarations in any .rs file
# - each .rs file's stem (cites like `tirbase-gateway/tests/db_split.rs`
# or `command_role_tests` naming a module)
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
    --exclude-dir=node_modules --exclude-dir=dist \
    --exclude-dir=build --exclude-dir=.venv \
    -- "$REPO_ROOT" 2>/dev/null \
    | awk '{print $2}'
 # `-prune`, not `-not -path`: `-not -path` still descends into target/
 # (hundreds of thousands of entries) and only filters the output.
  find "$REPO_ROOT" \
    \( -name target -o -name .git -o -name node_modules \
       -o -name dist -o -name build -o -name .venv \) -prune -o \
    -name '*.rs' -type f -print 2>/dev/null \
    | sed -e 's#.*/##' -e 's#\.rs$##'
} | sort -u > "$symbols_file"

# ---------------------------------------------------------------------------
# Index every `fn` declared immediately after `#[ignore...]` so a Proven row
# cannot rest on a test that never runs.
# ---------------------------------------------------------------------------
ignored_file="$work_dir/ignored"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$REPO_ROOT" > "$ignored_file" <<'PY'
import os, pathlib, re, sys
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

SKIP_DIRS = {"target", ".git", "node_modules", "dist", "build", ".venv"}

# os.walk prunes the skipped directories instead of descending into them.
paths = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for name in filenames:
        if name.endswith(".rs"):
            paths.append(pathlib.Path(dirpath) / name)

for p in paths:
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

# Citations are collected and resolved in one pass at the end: spawning a
# grep per citation cost ~44s of the script's runtime.
citations_file="$work_dir/citations"
: > "$citations_file"

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

missing_ids=()
ignored_ids=()
missing_claims=()
checked_citations=0
proven_count=0

# Emit candidate identifiers for one Test Identifier cell.
#
# One awk process per cell, not a chain of grep|sed|tr per cell: the pipeline
# version spawned ~8 processes for each of ~370 rows, which was the last
# remaining chunk of the script's runtime.
extract_candidates() {
  awk '
  {
    line = $0

    # `a::b::name` chains anywhere in the cell: keep the final segment only,
    # so `tirbase-gateway/tests/lease_ops.rs::claim_21_1_x` cites `claim_21_1_x`.
    rest = line
    while (match(rest, /([A-Za-z_][A-Za-z0-9_]*::)+[a-z_][A-Za-z0-9_]*/)) {
      tok = substr(rest, RSTART, RLENGTH)
      n = split(tok, seg, "::")
      print seg[n]
      rest = substr(rest, RSTART + RLENGTH)
    }

    # `{a,b}` brace groups, but only inside backticked spans that name a Rust
    # file (e.g. `security_log.rs::{set_witness_source,try_checkpoint}`).
    # Other braces are struct literals or SQL/config placeholders.
    rest = line
    while (match(rest, /`[^`]*`/)) {
      span = substr(rest, RSTART + 1, RLENGTH - 2)
      rest = substr(rest, RSTART + RLENGTH)
      if (index(span, ".rs") == 0) continue
      inner = span
      while (match(inner, "[{][^{}]*[}]")) {
        group = substr(inner, RSTART + 1, RLENGTH - 2)
        inner = substr(inner, RSTART + RLENGTH)
        n = split(group, item, ",")
        for (i = 1; i <= n; i++) {
          val = item[i]
          gsub(/^[[:space:]]+/, "", val)
          gsub(/[[:space:]]+$/, "", val)
          sub(/\.rs$/, "", val)
          print val
        }
      }
    }

    # Backticked bare identifiers.
    rest = line
    while (match(rest, /`[a-z_][a-z0-9_]*`/)) {
      print substr(rest, RSTART + 1, RLENGTH - 2)
      rest = substr(rest, RSTART + RLENGTH)
    }

    # Unbackticked cells: comma-separated bare identifiers are citations.
    if (index(line, "`") == 0) {
      n = split(line, item, ",")
      for (i = 1; i <= n; i++) {
        val = item[i]
        gsub(/^[[:space:]]+/, "", val)
        gsub(/[[:space:]]+$/, "", val)
        if (val ~ /^[a-z_][a-z0-9_]*$/) print val
      }
    }
  }
' <<<"$1"
}

# Rows are exported by the pipe-aware Python parser: a naive `IFS='|'` split
# truncates any row whose claim text contains a pipe inside a code span, which
# silently skipped those rows instead of gating them.
while IFS=$'\t' read -r claim_id status test_id; do

 # Only rows that claim executable evidence are gated.
  case "$status" in
    Proven|"Implemented and wired (unproven)"|"Implemented but not wired") ;;
    *) continue ;;
  esac
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
    printf '%s\t%s\t%s\n' "$claim_id" "$candidate" "$status" >> "$citations_file"
  done < <(extract_candidates "$test_id" | awk 'NF' | sort -u)

done < <(python3 "$REPO_ROOT/scripts/check-claims-schema.py" --emit-rows "$CLAIMS_FILE")

# Resolve every collected citation against the symbol index in a single awk
# pass, preserving claim order in the diagnostics.
while IFS=$'\t' read -r claim_id candidate verdict; do
  case "$verdict" in
    missing) missing_ids+=("${claim_id}: ${candidate}") ;;
    ignored) ignored_ids+=("${claim_id}: ${candidate} (#[ignore] — never executed by CI)") ;;
  esac
done < <(awk -F'\t' -v syms="$symbols_file" -v igns="$ignored_file" '
  FILENAME == syms { sym[$0] = 1; next }
  FILENAME == igns { ign[$0] = 1; next }
  {
    if (!($2 in sym))                 print $1 "\t" $2 "\tmissing"
    # "Implemented and wired (unproven)" exists precisely for evidence written
    # but not executed in CI (hardware-gated tests), so an ignored test is only
    # fatal for a Proven row.
    else if (($2 in ign) && $3 == "Proven") print $1 "\t" $2 "\tignored"
  }
' "$symbols_file" "$ignored_file" "$citations_file")

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
  echo "     See PV-2.2 for the requirement." >&2
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
  echo "OK: All ${proven_count} gated claim(s) in ${CLAIMS_FILE} have a test identifier,"
  echo "    and all ${checked_citations} cited identifier reference(s) resolve to real code."
  exit 0
fi

exit 1
