#!/usr/bin/env bash
# check-licence-fixtures.sh — negative-fixture harness for the F-01 gates.
#
# Proves that each licence gate actually fails on a violating fixture:
#   * SPDX header removed / mismatched
#   * Cargo.toml licence disagrees with LICENSING.md
#   * AGPL dependency reachable from an Apache crate
#   * executable code inside a data-only pack
#   * expired or incomplete licence exception
#
# Usage: bash scripts/check-licence-fixtures.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES="${ROOT}/tests/licence-fixtures"
PYTHON="${PYTHON:-python3}"

passed=0
failed=0

render_output() {
  sed 's/^/    /' "$1"
}

expect_pass() {
  local name="$1"
  shift
  local log
  log="$(mktemp)"
  if "$@" >"$log" 2>&1; then
    echo "PASS (expected success): ${name}"
    passed=$((passed + 1))
  else
    echo "FAIL: ${name} was expected to pass but the gate rejected it"
    render_output "$log"
    failed=$((failed + 1))
  fi
  rm -f "$log"
}

expect_fail() {
  local name="$1"
  local needle="$2"
  shift 2
  local log
  log="$(mktemp)"
  if "$@" >"$log" 2>&1; then
    echo "FAIL: ${name} was expected to fail but the gate passed"
    render_output "$log"
    failed=$((failed + 1))
  elif ! grep -Fq -- "$needle" "$log"; then
    echo "FAIL: ${name} failed for the wrong reason (missing: ${needle})"
    render_output "$log"
    failed=$((failed + 1))
  else
    echo "PASS (expected failure): ${name}"
    passed=$((passed + 1))
  fi
  rm -f "$log"
}

# ── SPDX headers ─────────────────────────────────────────────────────────────
expect_pass "SPDX header present and matching" \
  "$PYTHON" "${SCRIPT_DIR}/check-spdx-headers.py" "${FIXTURES}/spdx/valid"

expect_fail "SPDX header removed" "missing '// SPDX-License-Identifier" \
  "$PYTHON" "${SCRIPT_DIR}/check-spdx-headers.py" "${FIXTURES}/spdx/missing-header"

expect_fail "SPDX identifier mismatches manifest licence" "does not match the declared licence" \
  "$PYTHON" "${SCRIPT_DIR}/check-spdx-headers.py" "${FIXTURES}/spdx/wrong-licence"

# ── Cargo.toml licence matrix ────────────────────────────────────────────────
expect_pass "Cargo manifest matches LICENSING.md" \
  "$PYTHON" "${SCRIPT_DIR}/check-licence-matrix.py" \
  --root "${FIXTURES}/licence-matrix/valid" \
  --licensing "${FIXTURES}/licence-matrix/valid/LICENSING.md"

expect_fail "Cargo manifest licence disagrees with matrix" "does not match LICENSING.md" \
  "$PYTHON" "${SCRIPT_DIR}/check-licence-matrix.py" \
  --root "${FIXTURES}/licence-matrix/mismatch" \
  --licensing "${FIXTURES}/licence-matrix/mismatch/LICENSING.md"

# ── AGPL-free Apache graphs ──────────────────────────────────────────────────
expect_pass "Apache dependency graph is AGPL-free" \
  "$PYTHON" "${SCRIPT_DIR}/check-agpl-free.py" --metadata "${FIXTURES}/agpl/clean.json"

expect_pass "AGPL package reachable only through dev-dependencies" \
  "$PYTHON" "${SCRIPT_DIR}/check-agpl-free.py" --metadata "${FIXTURES}/agpl/dev-only-agpl.json"

expect_fail "AGPL dependency reachable from an Apache crate" "AGPL dependency" \
  "$PYTHON" "${SCRIPT_DIR}/check-agpl-free.py" --metadata "${FIXTURES}/agpl/violating.json"

# ── Data-only pack purity ────────────────────────────────────────────────────
expect_pass "data-only pack with declared launcher" \
  "$PYTHON" "${SCRIPT_DIR}/check-pack-purity.py" --packs-dir "${FIXTURES}/pack/clean"

expect_fail "pack containing executable code" "executable/code file in a data-only pack" \
  "$PYTHON" "${SCRIPT_DIR}/check-pack-purity.py" --packs-dir "${FIXTURES}/pack/executable"

# ── Licence exceptions ───────────────────────────────────────────────────────
expect_pass "complete, unexpired licence exception" \
  "$PYTHON" "${SCRIPT_DIR}/check-licence-exceptions.py" \
  --registry "${FIXTURES}/exceptions/valid.toml" \
  --deny "${FIXTURES}/exceptions/valid-deny.toml" \
  --today 2026-11-13

expect_fail "expired licence exception" "expired on" \
  "$PYTHON" "${SCRIPT_DIR}/check-licence-exceptions.py" \
  --registry "${FIXTURES}/exceptions/expired.toml" \
  --deny "${FIXTURES}/exceptions/expired-deny.toml" \
  --today 2026-11-13

expect_fail "licence exception without an owner" "missing required field 'owner'" \
  "$PYTHON" "${SCRIPT_DIR}/check-licence-exceptions.py" \
  --registry "${FIXTURES}/exceptions/missing-owner.toml" \
  --deny "${FIXTURES}/exceptions/missing-owner-deny.toml" \
  --today 2026-11-13

echo
if [[ "$failed" -ne 0 ]]; then
  echo "FAIL: ${failed} fixture expectation(s) not met (${passed} passed)." >&2
  exit 1
fi

echo "OK: all ${passed} licence-gate fixture expectations met (positive and negative)."
