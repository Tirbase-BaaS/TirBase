//! WASM sandbox gate — executes migration transforms in a restricted runtime (Req 18.4).
//!
//! On the native build:  uses `wasmtime` with a restricted linker.
//! On the WASM build:    uses `wasmi` with fuel-metered execution, import validation, and real
//!                       `read_row`/`write_row` host functions (implemented in T20).
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
    /// The migration was revoked before it could commit: the transform may
    /// have been interrupted mid-flight (Req 18.6) or the revocation landed in
    /// the window between sandbox exit and the schema-hash commit.  In either
    /// case the schema must NOT advance to the target hash.
    Revoked { reason: String },
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Execute the migration transform inside the appropriate sandbox for this build target.
///
/// - `transform`: validated WASM bytecode.
/// - `migration_id`: the migration being executed (for revocation checks).
/// - `timeout_secs`: epoch-interrupt timeout (default: 30s per Req 18.4).
/// - `store`: handle to the local store for host function access (native only).
///
/// This standalone variant registers the run with a throwaway execution
/// registry, so nothing can externally interrupt it (it runs to completion or
/// its own epoch timeout) — matching the pre-interruptible behaviour.  The
/// interruptible CoreHandle migration pipeline uses
/// [`execute_migration_with_registry`] instead.
#[cfg(feature = "native")]
pub fn execute_migration(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
    store: &std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
) -> Result<MigrationResult, TirBaseError> {
    let registry = MigrationExecutionRegistry::default();
    execute_native(transform, migration_id, timeout_secs, store, &registry)
}

// ─── In-flight execution registry (Req 18.6 interruption) ─────────────────────
//
// The wasmtime sandbox for a running migration registers its `Engine` here
// (keyed by migration id) *before* invoking the transform.  A migration
// revocation that clears the registry's in-progress flag then calls
// `interrupt(id)`, which increments the engine's epoch — the same mechanism
// the epoch timeout uses — so the running transform traps at the next wasm
// instruction boundary instead of running to completion behind the revoker.
// This registry lives outside the `SchemaMigrationEngine` lock, so it is
// reachable while a transform is executing off-lock.

/// Registry of interrupt handles for sandbox runs currently in flight.
///
/// Native: each entry holds a clone of the run's `wasmtime::Engine`;
/// interrupting increments that engine's epoch counter, forcing any `Store`
/// with a reached epoch deadline (the sandbox sets deadline 1) to trap.
#[cfg(feature = "native")]
#[derive(Debug, Default)]
pub struct MigrationExecutionRegistry {
    inner: std::sync::Mutex<std::collections::HashMap<MigrationId, wasmtime::Engine>>,
}

#[cfg(feature = "native")]
impl MigrationExecutionRegistry {
    /// Register the engine executing `migration_id`.  Returns `true` if the
    /// id was not already registered (a duplicate registration is a bug).
    pub fn register(&self, migration_id: MigrationId, engine: wasmtime::Engine) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.insert(migration_id, engine).is_none()
    }

    /// Remove `migration_id` from the registry (called when the run exits,
    /// regardless of outcome).
    pub fn unregister(&self, migration_id: &MigrationId) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(migration_id);
        }
    }

    /// Whether `migration_id` currently has a registered in-flight run.
    pub fn is_in_flight(&self, migration_id: &MigrationId) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.contains_key(migration_id),
            Err(_) => false,
        }
    }

    /// Number of in-flight runs currently registered.
    pub fn len(&self) -> usize {
        match self.inner.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    /// Interrupt the in-flight run of `migration_id`, if any: increments the
    /// run's wasmtime engine epoch so the sandbox traps promptly.
    ///
    /// Returns `true` when a registered run was interrupted.
    pub fn interrupt(&self, migration_id: &MigrationId) -> bool {
        let engine = match self.inner.lock() {
            Ok(guard) => guard.get(migration_id).cloned(),
            Err(_) => None,
        };
        match engine {
            Some(engine) => {
                engine.increment_epoch();
                true
            }
            None => false,
        }
    }
}

/// Execute `migration_id`'s transform while registered in `registry`, so a
/// concurrent migration revocation can interrupt it via an epoch interrupt
/// (Req 18.6).  All other behaviour — restricted linker, epoch timeout,
/// host functions — is identical to [`execute_migration`].
#[cfg(feature = "native")]
pub fn execute_migration_with_registry(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
    store: &std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
    registry: &MigrationExecutionRegistry,
) -> Result<MigrationResult, TirBaseError> {
    execute_native(transform, migration_id, timeout_secs, store, registry)
}

// ─── WASM-in-WASM implementation (wasmi) ─────────────────────────────────────

/// An in-memory key-value store passed as host state to the migration sandbox.
///
/// Mirrors the interface the native `LocalStore` presents (`read_row`, `write_row`),
/// but backed by a plain `HashMap` so it compiles cleanly to `wasm32-unknown-unknown`.
#[cfg(feature = "wasm")]
pub struct InMemoryStoreHandle {
    /// table_name → (key → value bytes)
    tables: std::collections::HashMap<String, std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(feature = "wasm")]
impl InMemoryStoreHandle {
    pub fn new() -> Self {
        Self {
            tables: std::collections::HashMap::new(),
        }
    }

    pub fn read(&self, table: &str, key: &str) -> Option<&[u8]> {
        self.tables.get(table)?.get(key).map(|v| v.as_slice())
    }

    pub fn write(&mut self, table: &str, key: String, value: Vec<u8>) {
        self.tables
            .entry(table.to_string())
            .or_default()
            .insert(key, value);
    }
}

/// Default fuel limit: ~1,000,000 instructions, approximating the native 30-second epoch.
#[cfg(feature = "wasm")]
const DEFAULT_FUEL: u64 = 1_000_000;

/// Execute a migration transform inside a wasmi sandbox (Req 18.4 — WASM target).
///
/// Security guarantees mirror the native wasmtime path:
/// - Only `host::log_message`, `host::read_row`, and `host::write_row` are linked.
/// - Any module that imports anything else (e.g. `wasi_snapshot_preview1::fd_write`)
///   will fail at instantiation with `Err(MigrationCaSignatureInvalid)` (treated as
///   an untrusted module, consistent with the zero-trust gate in Req 18.3).
/// - Fuel metering limits execution to at most `DEFAULT_FUEL` instructions.
///
/// Returns:
/// - `Ok(MigrationResult::Success)` on clean `run` exit.
/// - `Ok(MigrationResult::TimedOut)` when fuel is exhausted (`TrapCode::OutOfFuel`).
/// - `Ok(MigrationResult::Aborted)` for other traps or invalid WASM.
/// - `Err(MigrationCaSignatureInvalid)` when the module has unauthorised imports.
#[cfg(feature = "wasm")]
pub fn execute_migration_wasm(
    transform: &[u8],
    store_handle: &mut InMemoryStoreHandle,
    timeout_ticks: u32,
) -> Result<MigrationResult, TirBaseError> {
    use wasmi::{Config, Engine, Linker, Module, Store};

    let fuel = if timeout_ticks == 0 {
        DEFAULT_FUEL
    } else {
        u64::from(timeout_ticks)
    };

    // ── 1. Build engine with fuel metering enabled ─────────────────────────
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);

    // ── 2. Parse and validate the module ──────────────────────────────────
    let module = match Module::new(&engine, transform) {
        Ok(m) => m,
        Err(e) => {
            return Ok(MigrationResult::Aborted {
                reason: format!("invalid WASM module: {e}"),
            });
        }
    };

    // ── 3. Validate imports — reject any import outside {host::*} ─────────
    for import in module.imports() {
        if import.module() != "host" {
            let migration_id_hex = hex::encode([0u8; 32]); // placeholder
            return Err(TirBaseError::MigrationCaSignatureInvalid {
                migration_id: format!(
                    "forbidden import: {}::{}",
                    import.module(),
                    import.name()
                ),
            });
        }
    }

    // ── 4. Build restricted linker ─────────────────────────────────────────
    let mut linker = Linker::<WasmHostState>::new(&engine);

    // host.log_message(ptr: i32, len: i32)
    linker
        .func_wrap(
            "host",
            "log_message",
            |caller: wasmi::Caller<'_, WasmHostState>, ptr: i32, len: i32| {
                let mem = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory());
                if let Some(memory) = mem {
                    let data = memory.data(&caller);
                    let start = ptr as usize;
                    let end = start.saturating_add(len as usize);
                    if end <= data.len() {
                        if let Ok(msg) = core::str::from_utf8(&data[start..end]) {
                            // In a browser/WASM context we don't have eprintln!
                            // The message is silently dropped; host can wire a JS console if needed.
                            let _ = msg;
                        }
                    }
                }
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker: log_message: {e}"),
        })?;

    // host.read_row(table_ptr, table_len, key_ptr, key_len, out_ptr, out_max) -> i32
    linker
        .func_wrap(
            "host",
            "read_row",
            |mut caller: wasmi::Caller<'_, WasmHostState>,
             table_ptr: i32,
             table_len: i32,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_max: i32|
             -> i32 {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };

                // Read table and key strings from Wasm memory.
                let table_start = table_ptr as usize;
                let table_len = table_len as usize;
                let key_start = key_ptr as usize;
                let key_len = key_len as usize;

                let mut table_buf = vec![0u8; table_len];
                let mut key_buf = vec![0u8; key_len];

                if mem.read(&caller, table_start, &mut table_buf).is_err() {
                    return 0;
                }
                if mem.read(&caller, key_start, &mut key_buf).is_err() {
                    return 0;
                }

                let table = match core::str::from_utf8(&table_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return 0,
                };
                let key = match core::str::from_utf8(&key_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return 0,
                };

                let value = match caller.data().store.read(&table, &key) {
                    Some(v) => v.to_vec(),
                    None => return 0,
                };

                let write_len = value.len().min(out_max as usize);
                if mem.write(&mut caller, out_ptr as usize, &value[..write_len]).is_err() {
                    return 0;
                }
                write_len as i32
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker: read_row: {e}"),
        })?;

    // host.write_row(table_ptr, table_len, key_ptr, key_len, val_ptr, val_len)
    linker
        .func_wrap(
            "host",
            "write_row",
            |mut caller: wasmi::Caller<'_, WasmHostState>,
             table_ptr: i32,
             table_len: i32,
             key_ptr: i32,
             key_len: i32,
             val_ptr: i32,
             val_len: i32| {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };

                let table_len = table_len as usize;
                let key_len = key_len as usize;
                let val_len = val_len as usize;

                let mut table_buf = vec![0u8; table_len];
                let mut key_buf = vec![0u8; key_len];
                let mut val_buf = vec![0u8; val_len];

                if mem.read(&caller, table_ptr as usize, &mut table_buf).is_err() {
                    return;
                }
                if mem.read(&caller, key_ptr as usize, &mut key_buf).is_err() {
                    return;
                }
                if mem.read(&caller, val_ptr as usize, &mut val_buf).is_err() {
                    return;
                }

                let table = match core::str::from_utf8(&table_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return,
                };
                let key = match core::str::from_utf8(&key_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return,
                };

                caller.data_mut().store.write(&table, key, val_buf);
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker: write_row: {e}"),
        })?;

    // ── 5. Instantiate and set fuel ────────────────────────────────────────
    // Move store_handle into a WasmHostState that the wasmi Store owns.
    // We'll extract it after execution by swapping it out.
    // Since InMemoryStoreHandle doesn't impl Clone, we temporarily replace it
    // with an empty one and move it back after the call.
    let mut temp_store_handle = InMemoryStoreHandle::new();
    core::mem::swap(store_handle, &mut temp_store_handle);

    let host_state = WasmHostState { store: temp_store_handle };
    let mut wasm_store = Store::new(&engine, host_state);
    wasm_store
        .set_fuel(fuel)
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("set_fuel failed: {e}"),
        })?;

    let instance = match linker
        .instantiate(&mut wasm_store, &module)
        .and_then(|pre| pre.start(&mut wasm_store))
    {
        Ok(i) => i,
        Err(e) => {
            // Restore store state before returning.
            *store_handle = wasm_store.into_data().store;
            return Ok(MigrationResult::Aborted {
                reason: format!("instantiation failed: {e}"),
            });
        }
    };

    // ── 6. Call "run" export ───────────────────────────────────────────────
    let run_func = instance.get_func(&wasm_store, "run");

    let result = match run_func {
        None => {
            // No "run" export — treat as successful no-op migration.
            Ok(MigrationResult::Success)
        }
        Some(f) => {
            let typed = f.typed::<(), ()>(&wasm_store);
            match typed {
                Ok(tf) => match tf.call(&mut wasm_store, ()) {
                    Ok(_) => Ok(MigrationResult::Success),
                    Err(e) => {
                        let is_out_of_fuel = {
                            let dbg = format!("{e:?}");
                            dbg.contains("OutOfFuel")
                        };
                        if is_out_of_fuel {
                            Ok(MigrationResult::TimedOut {
                                timeout_secs: fuel / 33_333, // approx secs at ~33k instr/ms
                            })
                        } else {
                            Ok(MigrationResult::Aborted {
                                reason: format!("trap during migration: {e}"),
                            })
                        }
                    }
                },
                Err(e) => Ok(MigrationResult::Aborted {
                    reason: format!("run export type mismatch: {e}"),
                }),
            }
        }
    };

    // Restore the (now potentially written-to) in-memory store.
    *store_handle = wasm_store.into_data().store;
    result
}

/// Host state carried through the wasmi Store for the migration sandbox.
#[cfg(feature = "wasm")]
struct WasmHostState {
    store: InMemoryStoreHandle,
}

/// Public shim so `mod.rs` can call `execute_migration()` on both targets
/// with the same signature as the native path.
///
/// On the WASM target this delegates to `execute_migration_wasm` with a
/// freshly-created `InMemoryStoreHandle` (the sandbox's writes are ephemeral,
/// which is correct behaviour: migration transform output is captured via
/// `write_row` callbacks, not persisted outside the engine boundary).
#[cfg(feature = "wasm")]
pub fn execute_migration(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
) -> Result<MigrationResult, TirBaseError> {
    let mut handle = InMemoryStoreHandle::new();
    let ticks = if timeout_secs == 0 {
        0u32
    } else {
        // Scale: 1 second ≈ 33,333 fuel ticks (rough approximation).
        (timeout_secs.min(u64::from(u32::MAX / 33_333)) * 33_333) as u32
    };
    execute_migration_wasm(transform, &mut handle, ticks)
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

/// RAII guard removing a run from the [`MigrationExecutionRegistry`] on every
/// exit path of [`execute_native`] (success, abort, timeout, panic-free error).
#[cfg(feature = "native")]
struct RegistryGuard<'a> {
    registry: &'a MigrationExecutionRegistry,
    migration_id: MigrationId,
    armed: bool,
}

#[cfg(feature = "native")]
impl Drop for RegistryGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.registry.unregister(&self.migration_id);
        }
    }
}

#[cfg(feature = "native")]
fn execute_native(
    transform: &[u8],
    migration_id: MigrationId,
    timeout_secs: u64,
    store: &std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
    registry: &MigrationExecutionRegistry,
) -> Result<MigrationResult, TirBaseError> {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use wasmtime::{Config, Engine, Linker, Module, Store};

    // ── 1. Build a restricted engine (no net, no component model) ─────────
    let mut config = Config::new();
    // Epoch-based interruption for timeout AND revocation (Req 18.6):
    // incrementing this engine's epoch (from the timeout thread or from a
    // migration revocation via the execution registry) makes the sandbox trap
    // at the next wasm instruction boundary.
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
    linker
        .func_wrap(
            "host",
            "read_row",
            |mut caller: wasmtime::Caller<'_, MigrationHostState>,
             table_ptr: i32,
             table_len: i32,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_max: i32|
             -> i32 {
                // 1. Get memory export
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };

                // 2. Read table string from WASM memory
                let mut table_buf = vec![0u8; table_len as usize];
                if mem.read(&caller, table_ptr as usize, &mut table_buf).is_err() {
                    return 0;
                }
                let table = match std::str::from_utf8(&table_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return 0,
                };

                // 3. Read key string from WASM memory
                let mut key_buf = vec![0u8; key_len as usize];
                if mem.read(&caller, key_ptr as usize, &mut key_buf).is_err() {
                    return 0;
                }
                let key = match std::str::from_utf8(&key_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return 0,
                };

                // 4. Call LocalStore::read
                let value_bytes = {
                    let store_guard = match caller.data().store.lock() {
                        Ok(s) => s,
                        Err(_) => return 0,
                    };
                    match store_guard.read(&table, &key) {
                        Ok(Some(val)) => {
                            match serde_json::to_vec(&val) {
                                Ok(b) => b,
                                Err(_) => return 0,
                            }
                        }
                        _ => return 0,
                    }
                };

                // 5. Write result into WASM memory up to out_max bytes
                let write_len = value_bytes.len().min(out_max as usize);
                if mem.write(&mut caller, out_ptr as usize, &value_bytes[..write_len]).is_err() {
                    return 0;
                }
                write_len as i32
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
            |mut caller: wasmtime::Caller<'_, MigrationHostState>,
             table_ptr: i32,
             table_len: i32,
             key_ptr: i32,
             key_len: i32,
             val_ptr: i32,
             val_len: i32| {
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return,
                };

                let mut table_buf = vec![0u8; table_len as usize];
                let mut key_buf = vec![0u8; key_len as usize];
                let mut val_buf = vec![0u8; val_len as usize];

                if mem.read(&caller, table_ptr as usize, &mut table_buf).is_err() { return; }
                if mem.read(&caller, key_ptr as usize, &mut key_buf).is_err() { return; }
                if mem.read(&caller, val_ptr as usize, &mut val_buf).is_err() { return; }

                let table = match std::str::from_utf8(&table_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return,
                };
                let key = match std::str::from_utf8(&key_buf) {
                    Ok(s) => s.to_string(),
                    Err(_) => return,
                };

                // Deserialise value bytes as serde_json::Value
                let value: serde_json::Value = match serde_json::from_slice(&val_buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };

                // Call LocalStore::write
                let mut store_guard = match caller.data().store.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let _ = store_guard.write(&table, &key, &value);
            },
        )
        .map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("linker func_wrap write_row: {e}"),
        })?;

    // ── 4. Create the store with epoch deadline ────────────────────────────
    //
    // NOTE (Req 18.6): the deadline is RELATIVE to the engine's current epoch
    // at the moment `set_epoch_deadline` runs — an epoch increment that lands
    // before this call is "forgiven" (the deadline slides forward past it).
    // The execution registry registration below therefore happens only AFTER
    // the deadline is armed, so a revocation interrupt that finds a registered
    // run is guaranteed to have been made after the deadline and traps at the
    // next epoch check in the guest code.
    let mut wt_store = Store::new(&engine, MigrationHostState::new(migration_id, store.clone()));
    wt_store.set_epoch_deadline(1); // will be exceeded after `timeout_secs` real time

    // Register this run's engine only now that the epoch deadline is armed; a
    // migration revocation that reaches it increments the epoch and traps the
    // transform promptly.  The guard deregisters on every exit path from here
    // on (instantiation failure, missing "run" export, trap, success).
    registry.register(migration_id, engine.clone());
    let registry_guard = RegistryGuard {
        registry,
        migration_id,
        armed: true,
    };

    // ── 5. Spawn a background thread to tick the epoch after the deadline ──
    let engine_clone = engine.clone();
    let timeout_duration = Duration::from_secs(timeout_secs.max(1));
    std::thread::spawn(move || {
        std::thread::sleep(timeout_duration);
        engine_clone.increment_epoch();
    });

    // ── 6. Instantiate and call "run" ─────────────────────────────────────
    let instance = match linker.instantiate(&mut wt_store, &module) {
        Ok(i) => i,
        Err(e) => {
            return Ok(MigrationResult::Aborted {
                reason: format!("instantiation failed: {e}"),
            });
        }
    };

    // Look for an exported "run" function; if absent, try calling nothing (migration succeeds).
    let run_func = instance.get_func(&mut wt_store, "run");

    match run_func {
        None => {
            // No "run" export — treat as successful no-op migration.
            return Ok(MigrationResult::Success);
        }
        Some(f) => {
            match f.call(&mut wt_store, &[], &mut []) {
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
                        // An epoch interrupt fired — either the {timeout_secs}s
                        // deadline elapsed or a migration revocation requested
                        // the interrupt (Req 18.6); the engine's revocation
                        // re-check distinguishes the two on commit.
                        eprintln!(
                            "[migration sandbox] Migration {:?} epoch-interrupted \
                             (timeout {timeout_secs}s or migration revocation)",
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
    pub store: std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
}

#[cfg(feature = "native")]
impl MigrationHostState {
    pub fn new(
        migration_id: MigrationId,
        store: std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>>,
    ) -> Self {
        Self { migration_id, store }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    /// Helper: create an in-memory LocalStore wrapped in Arc<Mutex<>>.
    fn test_store() -> std::sync::Arc<std::sync::Mutex<crate::store::LocalStore>> {
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::store::LocalStore::open(":memory:").expect("in-memory store"),
        ))
    }

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
        let result = execute_migration(&wasm, [0u8; 32], 30, &test_store())
            .expect("execute_migration should not return Err");
        assert_eq!(result, MigrationResult::Success);
    }

    #[test]
    fn infinite_loop_times_out() {
        let wasm = infinite_loop_wasm();
        // Use a very short timeout (1 second) so the test doesn't hang.
        let result = execute_migration(&wasm, [0xFFu8; 32], 1, &test_store())
            .expect("execute_migration should not return Err");
        assert!(
            matches!(result, MigrationResult::TimedOut { timeout_secs: 1 }),
            "expected TimedOut, got: {result:?}"
        );
    }

    #[test]
    fn log_message_host_function_accessible() {
        let wasm = log_message_wasm();
        let result = execute_migration(&wasm, [0x01u8; 32], 30, &test_store())
            .expect("execute_migration should not return Err");
        assert_eq!(result, MigrationResult::Success, "log_message module should succeed");
    }

    #[test]
    fn invalid_wasm_bytes_returns_aborted() {
        let result = execute_migration(b"not-valid-wasm", [0u8; 32], 30, &test_store())
            .expect("execute_migration should not return Err");
        assert!(
            matches!(result, MigrationResult::Aborted { .. }),
            "invalid WASM should produce Aborted: {result:?}"
        );
    }

    // ─── Test C: registry epoch-interrupt halts a running transform (Req 18.6) ──
    //
    // The migration revocation path interrupts an in-progress transform by
    // incrementing the epoch of the wasmtime Engine registered in the
    // `MigrationExecutionRegistry`.  This test drives that mechanism directly:
    // an infinite-loop transform with a 30 s timeout is interrupted via the
    // registry well before the timeout, and the sandbox run returns (trapped).
    #[test]
    fn registry_interrupt_halts_infinite_loop_before_timeout() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let wasm = infinite_loop_wasm();
        let migration_id: MigrationId = [0x5Eu8; 32];
        let store = test_store();
        let registry = Arc::new(MigrationExecutionRegistry::default());

        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let reg = registry.clone();
        let handle = std::thread::spawn(move || {
            flag.store(true, Ordering::SeqCst);
            execute_migration_with_registry(&wasm, migration_id, 30, &store, &reg)
        });

        // Wait until the run has registered its engine (i.e. is genuinely
        // executing) before interrupting — otherwise the interrupt would be a
        // no-op and the run would only stop at the 30 s timeout.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !registry.is_in_flight(&migration_id) {
            assert!(
                std::time::Instant::now() < deadline,
                "run never registered with the execution registry"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(started.load(Ordering::SeqCst), "run thread must have started");

        let t0 = std::time::Instant::now();
        assert!(
            registry.interrupt(&migration_id),
            "interrupt must find the registered in-flight run"
        );

        let result = handle.join().expect("run thread must not panic");
        let elapsed = t0.elapsed();

        assert!(
            !matches!(result, Ok(MigrationResult::Success)),
            "an interrupted transform must not report Success: {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "epoch interrupt must halt the transform in well under the 30 s timeout, took {elapsed:?}: {result:?}"
        );
        assert!(
            !registry.is_in_flight(&migration_id),
            "run must deregister from the registry on exit"
        );
    }

    // ─── Test A: read_row and write_row round-trip via WAT transform ──────────

    #[test]
    fn read_write_row_roundtrip_via_wasm_transform() {
        // WAT: reads from table="test", key="src", writes result to key="dst"
        let wat = r#"
            (module
              (import "host" "read_row"  (func $read  (param i32 i32 i32 i32 i32 i32) (result i32)))
              (import "host" "write_row" (func $write (param i32 i32 i32 i32 i32 i32)))
              (memory (export "memory") 1)

              ;; Memory layout:
              ;; 0..4   = "test"  (table name, 4 bytes)
              ;; 4..7   = "src"   (source key, 3 bytes)
              ;; 7..10  = "dst"   (dest key, 3 bytes)
              ;; 256..  = output buffer for read_row (up to 256 bytes)

              (data (i32.const 0)   "test")
              (data (i32.const 4)   "src")
              (data (i32.const 7)   "dst")

              (func (export "run")
                (local $n i32)
                ;; read_row("test", "src") → output at byte 256
                (local.set $n
                  (call $read
                    (i32.const 0)   ;; table_ptr
                    (i32.const 4)   ;; table_len
                    (i32.const 4)   ;; key_ptr
                    (i32.const 3)   ;; key_len
                    (i32.const 256) ;; out_ptr
                    (i32.const 256) ;; out_max
                  )
                )
                ;; write_row("test", "dst", bytes_at_256, n_bytes)
                (call $write
                  (i32.const 0)   ;; table_ptr
                  (i32.const 4)   ;; table_len
                  (i32.const 7)   ;; key_ptr
                  (i32.const 3)   ;; key_len
                  (i32.const 256) ;; val_ptr
                  (local.get $n)  ;; val_len
                )
              )
            )
        "#;

        let wasm = wat::parse_str(wat).expect("parse WAT");
        let store_handle = test_store();

        // Pre-populate the store with the source value.
        {
            let mut s = store_handle.lock().unwrap();
            s.write("test", "src", &serde_json::json!({"greeting": "hello"}))
                .expect("pre-populate store");
        }

        let result = execute_migration(&wasm, [0xABu8; 32], 30, &store_handle)
            .expect("execute_migration must not return Err");

        assert_eq!(result, MigrationResult::Success, "transform must succeed: {result:?}");

        // Verify the value was read and written to "dst"
        let s = store_handle.lock().unwrap();
        let dst_val = s
            .read("test", "dst")
            .expect("read dst")
            .expect("dst should exist after migration");
        let expected = serde_json::json!({"greeting": "hello"});
        assert_eq!(dst_val, expected, "dst value must equal src value (copy transform)");
    }

    // ─── Test B: Timeout during a store-read-heavy transform ─────────────────

    #[test]
    fn timeout_during_store_read_heavy_transform() {
        // A transform that loops calling read_row indefinitely.
        let wat = r#"
            (module
              (import "host" "read_row" (func $read (param i32 i32 i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "test")
              (data (i32.const 4) "key")
              (func (export "run")
                (loop $spin
                  (drop
                    (call $read
                      (i32.const 0) (i32.const 4)
                      (i32.const 4) (i32.const 3)
                      (i32.const 8) (i32.const 64)
                    )
                  )
                  br $spin
                )
              )
            )
        "#;

        let wasm = wat::parse_str(wat).expect("parse WAT");
        let store_handle = test_store();

        // Populate a key so read_row actually does real work.
        {
            let mut s = store_handle.lock().unwrap();
            s.write("test", "key", &serde_json::json!(42)).expect("write");
        }

        let result = execute_migration(&wasm, [0xCDu8; 32], 1, &store_handle)
            .expect("execute_migration must not return Err");

        assert!(
            matches!(result, MigrationResult::TimedOut { timeout_secs: 1 }),
            "spinning read_row transform must time out after 1s: {result:?}"
        );
    }
}

// ─── WASM-feature tests (wasmi sandbox) ──────────────────────────────────────

#[cfg(all(test, feature = "wasm"))]
mod wasm_tests {
    use super::*;

    /// Minimal valid WASM that exports `run` as a no-op.
    fn trivial_wasm() -> Vec<u8> {
        // (module (func (export "run")))
        wat::parse_str(r#"(module (func (export "run")))"#).expect("trivial WAT")
    }

    /// WASM module that spins in an infinite loop (fuel-exhaustion test).
    fn infinite_loop_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (func (export "run")
                   (loop $inf br $inf)
                 )
               )"#,
        )
        .expect("infinite loop WAT")
    }

    /// WASM module that imports a forbidden WASI function.
    fn forbidden_import_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "wasi_snapshot_preview1" "fd_write"
                   (func (param i32 i32 i32 i32) (result i32)))
                 (func (export "run"))
               )"#,
        )
        .expect("forbidden import WAT")
    }

    /// WASM module that uses the `host::log_message` host function.
    fn log_message_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "log_message" (func $log (param i32 i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "hello wasmi")
                 (func (export "run")
                   i32.const 0
                   i32.const 11
                   call $log
                 )
               )"#,
        )
        .expect("log_message WAT")
    }

    // ─── Test 1: valid minimal WASM executes successfully ─────────────────────

    #[test]
    fn wasm_trivial_migration_succeeds() {
        let wasm = trivial_wasm();
        let mut handle = InMemoryStoreHandle::new();
        let result = execute_migration_wasm(&wasm, &mut handle, 1_000_000)
            .expect("execute_migration_wasm must not return Err");
        assert_eq!(
            result,
            MigrationResult::Success,
            "trivial no-op WASM must succeed: {result:?}"
        );
    }

    // ─── Test 2: fuel exhaustion returns TimedOut ─────────────────────────────

    #[test]
    fn wasm_fuel_exhaustion_returns_timed_out() {
        let wasm = infinite_loop_wasm();
        let mut handle = InMemoryStoreHandle::new();
        // Use tiny fuel limit so it runs out quickly.
        let result = execute_migration_wasm(&wasm, &mut handle, 100)
            .expect("execute_migration_wasm must not return Err");
        assert!(
            matches!(result, MigrationResult::TimedOut { .. }),
            "infinite loop must produce TimedOut when fuel exhausts: {result:?}"
        );
    }

    // ─── Test 3: forbidden import causes instantiation failure ───────────────

    #[test]
    fn wasm_forbidden_import_rejected() {
        let wasm = forbidden_import_wasm();
        let mut handle = InMemoryStoreHandle::new();
        let result = execute_migration_wasm(&wasm, &mut handle, 1_000_000);
        assert!(
            matches!(
                result,
                Err(TirBaseError::MigrationCaSignatureInvalid { .. })
            ),
            "forbidden import must be rejected with MigrationCaSignatureInvalid: {result:?}"
        );
    }

    // ─── Test 4: log_message host function is accessible ─────────────────────

    #[test]
    fn wasm_log_message_host_function_accessible() {
        let wasm = log_message_wasm();
        let mut handle = InMemoryStoreHandle::new();
        let result = execute_migration_wasm(&wasm, &mut handle, 1_000_000)
            .expect("log_message module must not error");
        assert_eq!(result, MigrationResult::Success);
    }

    // ─── Test 5: invalid WASM bytes return Aborted ────────────────────────────

    #[test]
    fn wasm_invalid_bytes_returns_aborted() {
        let mut handle = InMemoryStoreHandle::new();
        let result = execute_migration_wasm(b"not-valid-wasm", &mut handle, 1_000_000)
            .expect("invalid WASM must not return Err");
        assert!(
            matches!(result, MigrationResult::Aborted { .. }),
            "invalid WASM must produce Aborted: {result:?}"
        );
    }

    // ─── Test 6: public execute_migration shim delegates to wasmi correctly ───

    #[test]
    fn wasm_execute_migration_shim_succeeds() {
        // Verify the public shim (same signature as native) works correctly.
        let wasm = trivial_wasm();
        let result = execute_migration(&wasm, [0u8; 32], 30)
            .expect("execute_migration shim must not return Err");
        assert_eq!(
            result,
            MigrationResult::Success,
            "shim must delegate to wasmi and succeed: {result:?}"
        );
    }
}
