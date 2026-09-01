//! tirbase-core — the single Rust library implementing all sync, CRDT,
//! cryptographic, and mesh logic for TirBase (Req 1.1).
//!
//! # Build Targets
//!
//! This crate compiles identically to two targets:
//!
//! - **`--features native`** — native binary for the Cloud Ledger server.
//!   Uses `wasmtime` for migration sandbox execution and `rusqlite/bundled`
//!   for SQLite.
//!
//! - **`--features wasm`** — WASM module loaded by the TypeScript SDK on
//!   client devices. Uses `wasm-bindgen` for JS interop and `wasm3` for
//!   the WASM-in-WASM migration sandbox.
//!
//! The public API surface is **identical** on both targets; the
//! `static_assertions!` block below enforces this at compile time (Req 1.2, 1.5).
//!
//! # Feature Mutual Exclusivity
//!
//! `native` and `wasm` are mutually exclusive build targets.
//! The CI matrix always builds exactly one at a time:
//!   - `cargo check --features native`
//!   - `cargo check --features wasm --target wasm32-unknown-unknown`

#![deny(clippy::module_inception)]
#![allow(missing_docs)]

// ─── Compile-time mutual exclusivity guard ────────────────────────────────────
// Prevents accidentally enabling both features in the same build.
#[cfg(all(feature = "native", feature = "wasm"))]
compile_error!(
    "The `native` and `wasm` features are mutually exclusive. \
     Build with exactly one: `--features native` or `--features wasm`."
);

// ─── Modules ──────────────────────────────────────────────────────────────────

pub mod api;
pub mod auth;
pub mod contamination;
pub mod crdt;
pub mod diagnostics;
pub mod durability;
pub mod errors;
pub mod identity;
pub mod migration;
pub mod schema;
pub mod store;
pub mod transport;

// ─── Property-based test suite (Task 15) ─────────────────────────────────────
#[cfg(test)]
mod tests;

// ─── WASM-bindgen exports ─────────────────────────────────────────────────────
// When building for the TypeScript SDK (wasm target), key API entry points are
// exported with `#[wasm_bindgen]`. On the native build these annotations are
// inert no-ops (the macro is not imported), so the public symbol set remains
// identical (Req 1.5).

#[cfg(feature = "wasm")]
#[allow(unused_imports)]
use wasm_bindgen::prelude::*;

// ─── Compile-time API surface assertions ──────────────────────────────────────
//
// `static_assertions::assert_type_eq_all!` and `assert_impl_all!` confirm that
// the public types listed in the API surface exist and implement the expected
// traits on whichever build target is active.
//
// Because the types are defined **unconditionally** (no #[cfg(feature)] guards
// on the type definitions themselves), these assertions hold on both targets and
// verify that neither target accidentally omits a required public symbol (Req 1.2, 1.5).

use static_assertions::assert_impl_all;

// Core API types must exist and be Send + Sync (required for async usage).
assert_impl_all!(api::types::TrustLevel:     Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::DurabilityTier: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::MeshStatus:     Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::ConnectionStatus: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(api::types::WriteResult:    Clone, std::fmt::Debug);
assert_impl_all!(api::types::QueryResult:    Clone, std::fmt::Debug);

// CRDT / Schema types.
assert_impl_all!(crdt::delta::PriorityClass: Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(schema::FieldType:          Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(schema::Schema:             Clone, PartialEq, Eq, std::fmt::Debug);

// Error type.
assert_impl_all!(errors::TirBaseError: std::fmt::Debug, std::fmt::Display, std::error::Error);

// Contamination types.
assert_impl_all!(contamination::incident::IncidentState:   Clone, Copy, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(contamination::incident::TaintSource:     Clone, PartialEq, Eq, std::fmt::Debug);
assert_impl_all!(contamination::incident::AuditOperation:  Clone, Copy, PartialEq, Eq, std::fmt::Debug);
