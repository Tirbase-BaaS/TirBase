//! Test suites.
//!
//! The suites are split by compilation target rather than by feature:
//!
//! * [`wasm_tests`] is the in-browser `#[wasm_bindgen_test]` suite, compiled
//!   for `wasm32-unknown-unknown` and executed by `scripts/wasm-test.sh`.
//! * [`api_parity`], [`convergence_tests`] and [`properties`] are host suites.
//!   They must be excluded from the `wasm32-unknown-unknown` test build (their
//!   `proptest`/SQLite dependencies do not exist there) but must stay available
//!   on a host build regardless of feature, because `convergence_tests` carries
//!   the `wasm_convergence` half of the cross-build parity check, which is
//!   compiled with `--features wasm`.

#[cfg(not(target_arch = "wasm32"))]
pub mod api_parity;
#[cfg(not(target_arch = "wasm32"))]
pub mod convergence_tests;
#[cfg(not(target_arch = "wasm32"))]
pub mod properties;
pub mod wasm_tests;
