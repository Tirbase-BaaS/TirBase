//! Task 29 / PV-8 gateway-binary integration tests.
//!
//! Exercises the migration sandbox (wasmi, deterministic profile, execution
//! profile matching, store limits) through real `CoreHandle` migration flow.

use std::sync::{Arc, Mutex};

use tirbase_core::migration::profile::{
    pinned_fuel_cost_table_hash, ExecutionProfileVersion, DETERMINISTIC_PROFILE_ID,
};
use tirbase_core::migration::wasm_sandbox::{
    execute_migration, execute_migration_with_profile, MigrationExecutionRegistry, MigrationResult,
};

fn test_store() -> Arc<Mutex<tirbase_core::store::LocalStore>> {
    Arc::new(Mutex::new(
        tirbase_core::store::LocalStore::open(":memory:").expect("in-memory store"),
    ))
}

#[test]
fn gateway_f32_module_quarantined_before_execution() {
    // 29.2 / S8: module with f32 must be quarantined before execution.
    let wasm = wat::parse_str(r#"(module (func (export "run") f32.const 1.0 drop))"#).unwrap();
    let result = execute_migration(&wasm, [0x11u8; 32], 30, &test_store()).expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { ref reason } if reason.contains("deterministic profile")),
        "f32 module must be quarantined before execution: {result:?}"
    );
}

#[test]
fn gateway_mismatched_profile_quarantined_engine_version_mismatch() {
    // 29.3 / S9: mismatched profile_id/fuel_cost_table_hash => ENGINE_VERSION_MISMATCH.
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    let bad = ExecutionProfileVersion {
        profile_id: DETERMINISTIC_PROFILE_ID,
        fuel_cost_table_hash: [0xABu8; 32],
        conformance_corpus_hash: [0u8; 32],
        update_signer_signature: Vec::new(),
    };
    let reg = MigrationExecutionRegistry::default();
    let result =
        execute_migration_with_profile(&wasm, [0x22u8; 32], 30, &test_store(), &reg, Some(&bad))
            .expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { ref reason } if reason.contains("ENGINE_VERSION_MISMATCH")),
        "mismatched profile must quarantine ENGINE_VERSION_MISMATCH: {result:?}"
    );
}

#[test]
fn gateway_memory_limit_exceeded_quarantined() {
    // 29.4: migration exceeding 64 MiB memory limit is quarantined/aborted by StoreLimits.
    let wasm = wat::parse_str(r#"(module (memory (export "memory") 2048) (func (export "run")))"#)
        .unwrap(); // 2048 pages = 128 MiB > 64 MiB limit
    let result = execute_migration(&wasm, [0x33u8; 32], 30, &test_store()).expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { .. }),
        "module exceeding memory limit must be quarantined/aborted: {result:?}"
    );
}

#[test]
fn gateway_deterministic_migration_executes_with_wasmi() {
    // 29.1 smoke: valid deterministic migration executes under wasmi.
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    let good = ExecutionProfileVersion {
        profile_id: DETERMINISTIC_PROFILE_ID,
        fuel_cost_table_hash: pinned_fuel_cost_table_hash(),
        conformance_corpus_hash: [0u8; 32],
        update_signer_signature: Vec::new(),
    };
    let reg = MigrationExecutionRegistry::default();
    let result =
        execute_migration_with_profile(&wasm, [0x44u8; 32], 30, &test_store(), &reg, Some(&good))
            .expect("ok");
    assert_eq!(result, MigrationResult::Success);
}
