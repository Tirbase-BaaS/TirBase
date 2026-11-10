#!/usr/bin/env bash
# CI gate: systemd-analyze security exposure score <= 3.0 (CLAIM-35.3, PV-11.1)
set -euo pipefail

UNIT="${1:-deploy/systemd/tirbase-gateway.service}"

if ! command -v systemd-analyze >/dev/null 2>&1; then
  echo "ERROR: systemd-analyze not found; required for CLAIM-35.3 gate" >&2
  exit 1
fi

# systemd-analyze security prints an exposure score; use --threshold for gating.
# Lower is better; 10 is maximally exposed.
if systemd-analyze security --threshold=3.0 "$UNIT"; then
  echo "OK: $UNIT exposure score <= 3.0"
  exit 0
else
  echo "ERROR: $UNIT failed systemd-analyze security exposure gate (threshold 3.0)" >&2
  systemd-analyze security "$UNIT" || true
  exit 1
fi
