#!/usr/bin/env bash
#
# Run tirbase-core's in-browser WASM test suite (`#[wasm_bindgen_test]`).
#
# These tests compile the crate for wasm32-unknown-unknown and execute it in a
# real headless browser, so they cover code paths the native suite cannot:
#
#   * the IndexedDB-backed `LocalStore` (open / write / reload / query / cursor
#     scans) — a browser is the only place IndexedDB exists;
#   * `CoreHandle::receive_inbound_wasm` and the other WASM entry points, driven
#     through the same public `wasm_exports` functions the TypeScript SDK calls;
#   * the WASM clock (`performance.now()` / `Date.now()`), which is a different
#     implementation from the native one (`std::time::Instant` panics on
#     wasm32-unknown-unknown).
#
# Prerequisites (the script checks each and explains how to fix it):
#
#   1. `rustup target add wasm32-unknown-unknown`
#   2. `wasm-bindgen-cli` whose version matches the `wasm-bindgen` crate in
#      Cargo.lock — `cargo binstall wasm-bindgen-cli@<version>`
#   3. a ChromeDriver matching the installed Chrome.  On macOS/Linux this can be
#      fetched without root, e.g.
#        npx @puppeteer/browsers install chromedriver@stable --path ~/.cache/chromedriver
#      The script also honours `$CHROMEDRIVER` (absolute path to the binary).
#
# Extra arguments are forwarded to `cargo test`, so a single test can be run with
#   scripts/wasm-test.sh -- tests::wasm_tests::test_local_store_persists_across_reopen --exact
#
set -euo pipefail

cd "$(dirname "$0")/.."

say() { printf '%s\n' "wasm-test: $*" >&2; }
die() {
    printf 'wasm-test: error: %s\n' "$*" >&2
    exit 1
}

# ─── 1. wasm32 target ─────────────────────────────────────────────────────────
if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
    die "the wasm32-unknown-unknown target is not installed; run: rustup target add wasm32-unknown-unknown"
fi

# ─── 2. wasm-bindgen CLI matching the locked crate ────────────────────────────
# wasm-bindgen bakes a schema version into the generated glue; the runner and
# the crate must agree exactly or every test fails with a bindgen-format error.
want_bindgen="$(
    awk '/^name = "wasm-bindgen"$/ { getline; print $3 }' Cargo.lock |
        tr -d '"' | head -n 1
)"
have_bindgen="$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)"
if [[ -z "${have_bindgen}" ]]; then
    die "wasm-bindgen-test-runner is not on PATH; run: cargo binstall wasm-bindgen-cli@${want_bindgen}"
fi
if [[ "${have_bindgen}" != "${want_bindgen}" ]]; then
    die "wasm-bindgen CLI is ${have_bindgen} but Cargo.lock pins ${want_bindgen}; run: cargo binstall wasm-bindgen-cli@${want_bindgen}"
fi
command -v wasm-bindgen-test-runner >/dev/null ||
    die "wasm-bindgen-test-runner is not on PATH; run: cargo binstall wasm-bindgen-cli@${want_bindgen}"

# ─── 3. ChromeDriver ──────────────────────────────────────────────────────────
find_driver() {
    if [[ -n "${CHROMEDRIVER:-}" && -x "${CHROMEDRIVER}" ]]; then
        printf '%s\n' "${CHROMEDRIVER}"
        return 0
    fi
    if command -v chromedriver >/dev/null; then
        command -v chromedriver
        return 0
    fi
    # `npx @puppeteer/browsers install chromedriver@...` layout.
    local candidate
    candidate="$(find "${HOME}/.cache/chromedriver" -type f -name chromedriver -perm -u+x 2>/dev/null | sort | tail -n 1)"
    if [[ -n "${candidate}" ]]; then
        printf '%s\n' "${candidate}"
        return 0
    fi
    return 1
}

driver="$(find_driver)" || die "no ChromeDriver found. Install one matching your Chrome, e.g.:
    npx @puppeteer/browsers install chromedriver@stable --path ~/.cache/chromedriver
  or set CHROMEDRIVER=/absolute/path/to/chromedriver
  (see https://googlechromelabs.github.io/chrome-for-testing/)"
export PATH="$(dirname "${driver}"):${PATH}"
say "using ChromeDriver: ${driver} ($("${driver}" --version 2>/dev/null || echo version unknown))"

# `proptest` is a native dev-dependency, but `--all-targets`-style dependency
# resolution can still pull getrandom 0.3 into the wasm test build; it requires
# its backend to be selected explicitly.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg getrandom_backend=\"wasm_js\""

# Cargo cannot execute a wasm binary directly; this runner loads it into the
# browser and reports results back to libtest.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="wasm-bindgen-test-runner"
export WASM_BINDGEN_TEST_BROWSER="${WASM_BINDGEN_TEST_BROWSER:-chrome}"

say "running tirbase-core wasm tests in headless ${WASM_BINDGEN_TEST_BROWSER}"
exec cargo test -p tirbase-core \
    --no-default-features --features wasm \
    --target wasm32-unknown-unknown \
    --lib "$@"
