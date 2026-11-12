#!/usr/bin/env bash
# check-size-budget.sh — binary size and RSS budget gate (PV-11.4)
#
# Enforces the numerical budgets in deploy/budgets.toml. Per PV-15.7 the
# numerical values are NOT set until the measure-first task (44.2 / PV-15.2)
# records baselines; a budget of 0 means "not set yet" and the gate records the
# measurement without failing. Per PV-15.2 a budget is set at 120% of the
# measured baseline, so exceeding a set budget IS the regression gate.
#
# Usage:
# check-size-budget.sh binary-size <path> <target> # target e.g. aarch64-unknown-linux-gnu
# check-size-budget.sh rss <peak_kib>
# check-size-budget.sh --self-test # proves the failure paths
#
# Exit codes: 0 pass / budget not set, 1 over budget or bad usage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUDGETS="${REPO_ROOT}/deploy/budgets.toml"

if [[ ! -f "$BUDGETS" ]]; then
  echo "ERROR: budget file not found: $BUDGETS" >&2
  exit 1
fi

# Read `key = value` from the TOML file for a given section, ignoring comments.
budget_value() {
  local section="$1" key="$2"
  awk -v section="$section" -v key="$key" '
    /^[[:space:]]*\[/ {
      s = $0
      gsub(/[][[:space:]]/, "", s)
      current = s
      next
    }
    current == section {
      line = $0
      sub(/#.*/, "", line)
      if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        sub(/^[^=]*=[[:space:]]*/, "", line)
        gsub(/[[:space:]]/, "", line)
        print line
        exit
      }
    }
  ' "$BUDGETS"
}

measurement_line() {
  local kind="$1" value="$2" budget="$3" unit="$4"
  if [[ "$budget" == "0" ]]; then
    echo "MEASURED ${kind}=${value}${unit} (no numerical budget set — task 44.2 / PV-15.7 measure-first pending)"
  else
    echo "MEASURED ${kind}=${value}${unit} budget=${budget}${unit}"
  fi
}

check_budget() {
  local kind="$1" value="$2" budget="$3" unit="$4"
  measurement_line "$kind" "$value" "$budget" "$unit"
  if [[ "$budget" != "0" ]] && (( value > budget )); then
    echo "FAIL: ${kind} regression — ${value}${unit} exceeds the ${budget}${unit} budget (PV-11.4, PV-15.2)" >&2
    return 1
  fi
  echo "OK: ${kind} within budget"
  return 0
}

run_self_test() {
  local tmp
  tmp="$(mktemp -d)"

  local fake_budgets="$tmp/budgets.toml"
  cat > "$fake_budgets" <<'EOF'
[binary]
test_target = 100
[rss]
boot_peak_kib = 200
EOF

  local failures=0
  assert_exit() {
    local expected="$1" label="$2"
    shift 2
    set +e
    "$@" >/dev/null 2>&1
    local actual=$?
    set -e
    if [[ "$actual" -ne "$expected" ]]; then
      echo "SELF-TEST FAIL: $label (expected exit $expected, got $actual)" >&2
      failures=$((failures + 1))
    else
      echo "SELF-TEST OK: $label"
    fi
  }

 # Over-budget binary must fail; at-budget must pass.
  assert_exit 1 "binary size over budget fails" env TIRBASE_BUDGETS_FILE="$fake_budgets" \
    bash "$0" binary-size "$tmp/oversized" test-target --size-bytes 101
  assert_exit 0 "binary size at budget passes" env TIRBASE_BUDGETS_FILE="$fake_budgets" \
    bash "$0" binary-size "$tmp/exact" test-target --size-bytes 100
 # Over-budget RSS must fail; under-budget must pass.
  assert_exit 1 "RSS over budget fails" env TIRBASE_BUDGETS_FILE="$fake_budgets" \
    bash "$0" rss 201 --budget-file "$fake_budgets"
  assert_exit 0 "RSS under budget passes" env TIRBASE_BUDGETS_FILE="$fake_budgets" \
    bash "$0" rss 199 --budget-file "$fake_budgets"

  rm -rf "$tmp"

  if [[ "$failures" -ne 0 ]]; then
    echo "SELF-TEST FAILED: $failures check(s) did not behave as required" >&2
    return 1
  fi
  echo "SELF-TEST PASSED: the gate fails on over-budget size and RSS measurements"
  return 0
}

# Allow the self-test to point at a synthetic budget file.
if [[ -n "${TIRBASE_BUDGETS_FILE:-}" ]]; then
  BUDGETS="$TIRBASE_BUDGETS_FILE"
fi

mode="${1:-}"
shift || true

case "$mode" in
  binary-size)
    path="${1:-}"
    target="${2:-}"
    size_override=""
    if [[ "${3:-}" == "--size-bytes" ]]; then
      size_override="${4:-}"
    fi
    if [[ -z "$target" ]]; then
      echo "ERROR: usage: $0 binary-size <path> <target> [--size-bytes N]" >&2
      exit 1
    fi
    if [[ -n "$size_override" ]]; then
      size="$size_override"
    else
      if [[ ! -f "$path" ]]; then
        echo "ERROR: binary not found: $path" >&2
        exit 1
      fi
      size="$(wc -c < "$path" | tr -d '[:space:]')"
    fi
    key="${target//-/_}"
    budget="$(budget_value binary "$key")"
    budget="${budget:-0}"
    check_budget "binary_size[$target]" "$size" "$budget" " bytes"
    ;;
  rss)
    value="${1:-}"
    if [[ "${2:-}" == "--budget-file" && -n "${3:-}" ]]; then
      BUDGETS="$3"
    fi
    if [[ -z "$value" ]]; then
      echo "ERROR: usage: $0 rss <peak_kib>" >&2
      exit 1
    fi
    budget="$(budget_value rss boot_peak_kib)"
    budget="${budget:-0}"
    check_budget "boot_peak_rss" "$value" "$budget" " KiB"
    ;;
  --self-test)
    run_self_test
    ;;
  *)
    echo "ERROR: usage: $0 {binary-size <path> <target> | rss <peak_kib> | --self-test}" >&2
    exit 1
    ;;
esac
