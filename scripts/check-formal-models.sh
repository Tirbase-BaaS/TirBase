#!/usr/bin/env bash
# check-formal-models.sh — model-check every TLA+ spec (CLAIM-51.1–51.4, PV-26.1).
#
# Requires a JVM and `tla2tools.jar` (downloaded by the `formal-models` CI job).
# Usage: bash scripts/check-formal-models.sh /path/to/tla2tools.jar
#
# Exits non-zero if TLC finds a violated invariant/property, or if TLC cannot
# start (a missing tool is a failure, never a silent pass).
set -euo pipefail

JAR="${1:-tla2tools.jar}"
if [[ ! -f "$JAR" ]]; then
  echo "ERROR: tla2tools.jar not found at '$JAR'" >&2
  exit 1
fi
JAR="$(cd "$(dirname "$JAR")" && pwd)/$(basename "$JAR")"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORMAL_DIR="$REPO_ROOT/formal"
SPECS=(policy_lifecycle command_freshness ledger_recovery single_writer_lease)

status=0
for spec in "${SPECS[@]}"; do
  cfg="$FORMAL_DIR/$spec.cfg"
  tla="$FORMAL_DIR/$spec.tla"
  if [[ ! -f "$cfg" || ! -f "$tla" ]]; then
    echo "ERROR: missing $spec.cfg or $spec.tla" >&2
    status=1
    continue
  fi
  echo "== TLC: $spec =="
 # TLC writes its state trace next to the spec; run from a scratch dir to keep
 # the repository clean.
  work="$(mktemp -d)"
  cp "$cfg" "$tla" "$work/"
  if ( cd "$work" && java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
        -config "$spec.cfg" "$spec.tla" -workers 2 -cleanup ); then
    echo "OK: $spec model check passed"
  else
    echo "ERROR: TLC reported a violation or failed to run for $spec" >&2
    status=1
  fi
  rm -rf "$work"
done

exit "$status"
