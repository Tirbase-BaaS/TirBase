#!/usr/bin/env bash
set -euo pipefail

# Cross-build parity gate (Property 1, Req 1.4).
#
# Runs the same canonical ordered Delta sequence (including a signed
# Migration_Delta, an RGA list write, revocation, and a contamination-tagged
# write) through tirbase-core built with --features "native,parity-probe" and
# --features "wasm,parity-probe" (real wasm32 target), then diffs the emitted
# SHA-256 state hashes. A mismatch means the native and WASM builds diverged on
# identical input and fails this script, so CI rejects the change.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say() { printf '%s\n' "cross-build-parity: $*" >&2; }
die() { printf 'cross-build-parity: error: %s\n' "$*" >&2; exit 1; }

say "running native parity probe"
NATIVE_OUT="$(cargo test -p tirbase-core --no-default-features --features "native,parity-probe" --lib parity_probe -- --nocapture 2>&1)" || {
  printf '%s\n' "$NATIVE_OUT" >&2
  die "native parity probe failed"
}
NATIVE_HASH="$(printf '%s\n' "$NATIVE_OUT" | sed -n 's/^PARITY_HASH=//p' | tail -n 1)"
[ -n "$NATIVE_HASH" ] || { printf '%s\n' "$NATIVE_OUT" >&2; die "could not parse native PARITY_HASH"; }
say "native PARITY_HASH=$NATIVE_HASH"

command -v wasm-pack >/dev/null 2>&1 || die "wasm-pack is required for the WASM parity probe"
command -v node >/dev/null 2>&1 || die "node is required for the WASM parity probe"

OUT_DIR="${ROOT}/target/parity-wasm-pkg"
rm -rf "$OUT_DIR"
say "building WASM parity probe (wasm32 nodejs target)"
wasm-pack build tirbase-core \
  --target nodejs \
  --out-dir "$OUT_DIR" \
  --no-default-features \
  --features "wasm,parity-probe" >/dev/null

say "running WASM parity probe"
WASM_HASH="$(node -e "const m = require(process.argv[1]); process.stdout.write(m.core_cross_build_parity_hash());" "$OUT_DIR/tirbase_core.js")"
[ -n "$WASM_HASH" ] || die "WASM probe produced no hash"
say "wasm   PARITY_HASH=$WASM_HASH"

if [ "$NATIVE_HASH" != "$WASM_HASH" ]; then
  die "PARITY HASH MISMATCH: native=$NATIVE_HASH wasm=$WASM_HASH"
fi

say "OK: native and WASM parity hashes match ($NATIVE_HASH)"
