#!/usr/bin/env bash
# Offline POS scenario pack entry point (POS pack format v1).
#
# The pack is data only. This launcher is its sole executable: it prints the
# declared scenarios, then runs the Apache structural checks and the AGPL
# gateway integration checks that execute them against tirbase-pos.
set -euo pipefail

PACK_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PACK_DIR/../.." && pwd)"
cd "$ROOT"

echo "== TirBase offline POS scenario pack =="
echo "pack: tirbase-demo/pos-offline"
echo "licence: Apache-2.0 (data only; run.sh is the only executable)"
echo "scenarios:"
echo "  01 double charge on reconnect"
echo "  02 replayed refund"
echo "  03 split-bill conflict"
echo "  04 offline price change"
echo "  05 void after capture"
echo "  06 duplicate KDS ticket"
echo

cargo test -p tirbase-demo --test pos_offline_pack_structure -- --nocapture
cargo test -p tirbase-gateway --test pos_offline_scenarios -- --nocapture

echo
echo "offline POS pack: structure valid; every scenario defended (see expected/outcomes.toml)"
