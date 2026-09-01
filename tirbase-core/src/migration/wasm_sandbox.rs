//! WASM sandbox gate — executes migration transforms in a restricted runtime (Req 18.4).
//!
//! On the native build:  uses `wasmtime` with a restricted linker.
//! On the WASM build:    stub that returns Aborted (WASM-in-WASM deferred to a later task).
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

// ─── Public entry point ───────────────────────────────────────────────────────

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
    // WASM-in-WASM: the wasm3 path is deferred.
    // The interface is complete; the native path is the primary implementation.
    // TODO(task-future): embed a pure-Rust WASM interpreter for the browser target.
    Ok(MigrationResult::Aborted {
        reason: "wasm-in-wasm: not yet implemented in browser target".to_string(),
    })
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

// ─── Native implementation (wasmtime) ────────────────────────────────────────

#[cfg(feature = "native")]
fn execute_native(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use wasmtime::{Config, Engine, Linker, Module, Store};

    // ── 1. Build a restricted engine (no net, no component model) ─────────
    let mut config = Config::new();
    // Epoch-based interruption for timeout.
    config.epoch_interruption(true);
    // Disable WASI network access.
    config.wasm_component_model(false);

    let engine = Engine::new(&config).map_err(|e| TirBaseError::DeltaMalformed {
        reason: format!("wasmtime Engine::new failed: {e}"),
    })?;

    // ── 2. Parse the WASM module ──────────────────────────────────────────
    let module = match Module::new(&engine, transform) {
        Ok(m) => m,
        Err(e) => {
            return Ok(MigrationResult::Aborted {
                reason: format!("invalid WASM module: {e}"),
            });
        }
    };

    // ── 3. Build a restricted linker ─────────────────────────────────────
    // Only expose: read_row, write_row, log_message.
    // No WASI file-system or network imports are linked.
    let mut linker: Linker<MigrationHostState> = Linker::new(&engine);

    // host.log_message(ptr: i32, len: i32)
    linker
        .func_wrap(
            "host",
            "log_message",
            |mut caller: wasmtime::Caller<'_, MigrationHostState>, ptr: i32, len: i32| {
                let mem = caller.get_export("memory")
                    .and_then(|e| e.into_memory());

                if let Some(memory) = mem {
                    let data = memory.data(&caller);
                    let start = ptr as usize;
                    let end = start.saturating_add(len as usize);
                    if end <= data.len() {
                        if let Ok(msg) = std::str::from_utf8(&data[start..end]) {
                            eprintln!("[migration sandbox] {msg}");
                        }
                    }
                }
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker func_wrap log_message: {e}"),
        })?;

    // host.read_row(table_ptr, table_len, key_ptr, key_len, out_ptr, out_max) -> i32 (bytes written)
    // Stub: returns 0 bytes (empty value) for any key.
    linker
        .func_wrap(
            "host",
            "read_row",
            |_caller: wasmtime::Caller<'_, MigrationHostState>,
             _table_ptr: i32,
             _table_len: i32,
             _key_ptr: i32,
             _key_len: i32,
             _out_ptr: i32,
             _out_max: i32|
             -> i32 {
                // For the sandbox gate implementation, returns 0 (no data).
                // Full Local Store access requires the store handle injection (Task 8 follow-up).
                0i32
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker func_wrap read_row: {e}"),
        })?;

    // host.write_row(table_ptr, table_len, key_ptr, key_len, val_ptr, val_len)
    linker
        .func_wrap(
            "host",
            "write_row",
            |_caller: wasmtime::Caller<'_, MigrationHostState>,
             _table_ptr: i32,
             _table_len: i32,
             _key_ptr: i32,
             _key_len: i32,
             _val_ptr: i32,
             _val_len: i32| {
                // Stub: writes are accepted silently.
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker func_wrap write_row: {e}"),
        })?;

    // ── 4. Create the store with epoch deadline ────────────────────────────
    let mut store = Store::new(&engine, MigrationHostState::new(migration_id));
    store.set_epoch_deadline(1); // will be exceeded after `timeout_secs` real time

    // ── 5. Spawn a background thread to tick the epoch after the deadline ──
    let engine_clone = engine.clone();
    let timeout_duration = Duration::from_secs(timeout_secs.max(1));
    std::thread::spawn(move || {
        std::thread::sleep(timeout_duration);
        engine_clone.increment_epoch();
    });

    // ── 6. Instantiate and call "run" ─────────────────────────────────────
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return Ok(MigrationResult::Aborted {
                reason: format!("instantiation failed: {e}"),
            });
        }
    };

    // Look for an exported "run" function; if absent, try calling nothing (migration succeeds).
    let run_func = instance.get_func(&mut store, "run");

    match run_func {
        None => {
            // No "run" export — treat as successful no-op migration.
            return Ok(MigrationResult::Success);
        }
        Some(f) => {
            match f.call(&mut store, &[], &mut []) {
                Ok(_) => Ok(MigrationResult::Success),
                Err(e) => {
                    // Check for epoch interruption — wasmtime represents it as a
                    // Trap with TrapCode::Interrupt, or with a downcasted
                    // `wasmtime::Trap` enum value.
                    let is_timeout = {
                        // Try to extract a wasmtime Trap and check its code.
                        if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                            *trap == wasmtime::Trap::Interrupt
                        } else {
                            // Some wasmtime versions embed the interrupt as part of
                            // the anyhow error chain — check the debug string.
                            let debug_str = format!("{e:?}");
                            debug_str.contains("Interrupt")
                                || debug_str.contains("interrupt")
                                || debug_str.contains("epoch")
                        }
                    };

                    if is_timeout {
                        eprintln!(
                            "[migration sandbox] Migration {:?} timed out after {timeout_secs}s",
                            migration_id
                        );
                        Ok(MigrationResult::TimedOut { timeout_secs })
                    } else {
                        Ok(MigrationResult::Aborted {
                            reason: format!("trap during migration: {e}"),
                        })
                    }
                }
            }
        }
    }
}

// ─── MigrationHostState ───────────────────────────────────────────────────────

/// State passed through the wasmtime Store to host function implementations.
#[cfg(feature = "native")]
pub struct MigrationHostState {
    pub migration_id: MigrationId,
}

#[cfg(feature = "native")]
impl MigrationHostState {
    pub fn new(migration_id: MigrationId) -> Self {
        Self { migration_id }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    /// Minimal WAT that exports a "run" function which returns immediately.
    fn trivial_wasm() -> Vec<u8> {
        // (module (func (export "run")))
        // Hand-encoded WASM for the trivial no-op module.
        wat::parse_str(r#"(module (func (export "run")))"#).expect("parse trivial WAT")
    }

    /// WAT module that loops forever — for timeout testing.
    fn infinite_loop_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (func (export "run")
                (loop $inf
                  br $inf
                )
              )
            )
            "#,
        )
        .expect("parse infinite loop WAT")
    }

    /// WAT module that calls a host function.
    fn log_message_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (import "host" "log_message" (func $log (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "hello from sandbox")
              (func (export "run")
                i32.const 0
                i32.const 18
                call $log
              )
            )
            "#,
        )
        .expect("parse log_message WAT")
    }

    #[test]
    fn trivial_migration_succeeds() {
        let wasm = trivial_wasm();
        let result = execute_migration(&wasm, [0u8; 32], 30)
            .expect("execute_migration should not return Err");
        assert_eq!(result, MigrationResult::Success);
    }

    #[test]
    fn infinite_loop_times_out() {
        let wasm = infinite_loop_wasm();
        // Use a very short timeout (1 second) so the test doesn't hang.
        let result = execute_migration(&wasm, [0xFFu8; 32], 1)
            .expect("execute_migration should not return Err");
        assert!(
            matches!(result, MigrationResult::TimedOut { timeout_secs: 1 }),
            "expected TimedOut, got: {result:?}"
        );
    }

    #[test]
    fn log_message_host_function_accessible() {
        let wasm = log_message_wasm();
        let result = execute_migration(&wasm, [0x01u8; 32], 30)
            .expect("execute_migration should not return Err");
        assert_eq!(result, MigrationResult::Success, "log_message module should succeed");
    }

    #[test]
    fn invalid_wasm_bytes_returns_aborted() {
        let result = execute_migration(b"not-valid-wasm", [0u8; 32], 30)
            .expect("execute_migration should not return Err");
        assert!(
            matches!(result, MigrationResult::Aborted { .. }),
            "invalid WASM should produce Aborted: {result:?}"
        );
    }
}
