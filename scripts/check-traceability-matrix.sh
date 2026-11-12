#!/usr/bin/env bash
# check-traceability-matrix.sh — Verify named test/file paths in docs/traceability-matrix.md exist (PV-1.7, CLAIM-56.2)
set -euo pipefail

MATRIX_FILE="${1:-docs/traceability-matrix.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$WORKSPACE_ROOT"

if [[ ! -f "$MATRIX_FILE" ]]; then
  echo "ERROR: traceability matrix not found at '$MATRIX_FILE'" >&2
  exit 1
fi

# Extract backticked paths from the Test Location column and elsewhere in table rows.
# Consider tokens that look like repo paths (contain '/' or end with .rs/.toml/.md/.yml/.sh/.tla).
paths=()
while IFS= read -r line; do
  [[ -n "$line" ]] && paths+=("$line")
done < <(
  grep -oE '`[^`]+`' "$MATRIX_FILE" \
    | tr -d '`' \
    | tr ',' '\n' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | grep -E '(/|\.rs$|\.toml$|\.md$|\.yml$|\.yaml$|\.sh$|\.tla$)' \
    | grep -vE '^(PV-|INV-|S[0-9]|CLAIM-|ReasonCode|tirbase-|docs/traceability-matrix\.md$)$' \
    | sort -u
)

# Always require the matrix itself and key artifacts referenced by -56.
required=(
  "docs/traceability-matrix.md"
  "docs/crypto-review-scope.md"
  "docs/pentest-scope.md"
  "docs/security-findings.md"
  "docs/runbooks/lockdown.md"
  "docs/runbooks/tamper.md"
  "docs/runbooks/restore.md"
  "docs/runbooks/key-compromise.md"
  "docs/runbooks/crash-loop.md"
  "docs/runbooks/time-anchor-failure.md"
  "tirbase-sim/tests/runbook_fault_verification.rs"
  "tirbase-guard/src/auth_matrix.rs"
  "tirbase-guard/tests/auth_matrix.rs"
)

for r in "${required[@]}"; do
  paths+=("$r")
done

# Normalize, dedupe, and filter to plausible repo-relative paths.
seen_list=$'\n'
missing=()
checked=0
for p in "${paths[@]}"; do
  [[ -z "$p" ]] && continue
 # Skip inline notes/placeholders
  [[ "$p" == *" "* ]] && continue
  [[ "$p" == \`* ]] && continue
 # Normalize leading ./
  p="${p#./}"
 # Skip external/absolute-looking tokens
  [[ "$p" == /* ]] && continue
  [[ "$p" == http* ]] && continue
  [[ "$p" == \** ]] && continue
 # Only verify repo paths we care about
  if [[ "$p" != */* && "$p" != *.md && "$p" != *.rs && "$p" != *.toml && "$p" != *.yml && "$p" != *.yaml && "$p" != *.sh && "$p" != *.tla ]]; then
    continue
  fi
  case "$seen_list" in
    *$'\n'"$p"$'\n'*) continue ;;
  esac
  seen_list="${seen_list}${p}"$'\n'

  resolved="$p"
 # Workflow shorthand: if ".github/workflows/" not present but ends with .yml and file exists there.
  if [[ "$p" != .github/* && "$p" == *.yml && ! -e "$p" && -e ".github/workflows/$p" ]]; then
    resolved=".github/workflows/$p"
  fi

  checked=$((checked + 1))
  if [[ ! -e "$resolved" ]]; then
    missing+=("$p")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: traceability matrix names path(s) that do not exist:" >&2
  for m in "${missing[@]}"; do
    echo "  - $m" >&2
  done
  exit 1
fi

echo "OK: traceability matrix paths exist (${checked} unique path references checked)."
