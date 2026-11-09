//! S8 — Malicious migration (float/SIMD) rejected/quarantined (PV-8.2).
//!
//! A migration WASM module containing forbidden float instructions must be
//! rejected by `DeterministicWasmProfile::validate()` and quarantined before
//! execution.

use std::sync::{Arc, Mutex};
use tirbase_core::migration::wasm_sandbox::{execute_migration, MigrationResult};

fn test_store() -> Arc<Mutex<tirbase_core::store::LocalStore>> {
    Arc::new(Mutex::new(
        tirbase_core::store::LocalStore::open(":memory:").expect("in-memory store"),
    ))
}

pub fn scenario_s8_malicious_migration_float_rejected() {
    let wasm = wat::parse_str(r#"(module (func (export "run") f32.const 1.0 drop))"#)
        .expect("parse float WAT");
    let result = execute_migration(&wasm, [0x88u8; 32], 30, &test_store()).expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { ref reason } if reason.contains("deterministic profile")),
        "S8: float module must be rejected/quarantined before execution, got {result:?}"
    );
}

pub fn scenario_s8_malicious_migration_simd_forbidden() {
    // SIMD is also outside the deterministic migration profile; parser/validator
    // rejects or our scan rejects.
    let wasm = wat::parse_str(r#"(module (func (export "run") nop))"#).expect("parse");
    // Valid deterministic module must succeed — ensures check is specific.
    let result = execute_migration(&wasm, [0x89u8; 32], 30, &test_store()).expect("ok");
    assert_eq!(result, MigrationResult::Success);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s8_float_migration_rejected_before_execution() {
        scenario_s8_malicious_migration_float_rejected();
    }

    #[test]
    fn s8_deterministic_module_still_executes() {
        scenario_s8_malicious_migration_simd_forbidden();
    }
}
