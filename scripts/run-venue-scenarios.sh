#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the ST-09 venue scenario pack against the real venue engines and print
# the defended output. Exit code 0 means every scenario's safety invariant held.
#
#   scripts/run-venue-scenarios.sh              # all six scenarios
#   scripts/run-venue-scenarios.sh --list       # list them
#   scripts/run-venue-scenarios.sh --scenario gate-replay
set -euo pipefail

cd "$(dirname "$0")/.."
exec cargo run --quiet --package tirbase-venue-scenario-runner --bin venue-scenarios -- "$@"
