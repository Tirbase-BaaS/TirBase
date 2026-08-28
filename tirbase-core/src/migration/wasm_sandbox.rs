//! WASM sandbox gate — executes migration transforms in a restricted runtime (Req 18.4).
//!
//! On the native build:  uses `wasmtime` with a restricted linker.
//! On the WASM build:    uses `wasm3` as a WASM-in-WASM interpreter.
//!
//! The sandbox exposes only three host functions:
//!   - `read_row(table, key) -> value`
//!   - `write_row(table, key, value)`
//!   - `log_message(msg)`
//!
//! No network access, no file-system access outside the Local Store.

#![allow(dead_code, unused_variables, unused_imports)]

use crate::errors::TirBaseError;
use crate::migration::migration_delta::MigrationId;

/// Outcome of a sandbox migration execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    Success,
    TimedOut { timeout_secs: u64 },
    Aborted { reason: String },
}

/// Execute the migration transform inside the appropriate sandbox for this build target.
///
/// - `transform`: validated WASM bytecode.
/// - `migration_id`: the migration being executed (for revocation checks).
/// - `timeout_secs`: epoch-interrupt timeout (default: 30s per Req 18.4).
#[cfg(feature = "native")]
pub fn execute_migration(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    execute_native(transform, migration_id, timeout_secs)
}

#[cfg(feature = "wasm")]
pub fn execute_migration(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    execute_wasm_in_wasm(transform, migration_id, timeout_secs)
}

#[cfg(not(any(feature = "native", feature = "wasm")))]
pub fn execute_migration(
    _transform: &[u8],
    _migration_id: MigrationId,
    _timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    Err(TirBaseError::DeltaMalformed {
        reason: "no sandbox feature enabled".to_string(),
    })
}

/// Native build: execute via `wasmtime` with restricted capability config (Req 18.4).
#[cfg(feature = "native")]
fn execute_native(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    todo!("Task 8: implement wasmtime sandboxed execution")
}

/// WASM build: execute via `wasm3` interpreter (WASM-in-WASM design — design §Build Targets).
#[cfg(feature = "wasm")]
fn execute_wasm_in_wasm(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    todo!("Task 8: implement wasm3 sandboxed execution")
}
