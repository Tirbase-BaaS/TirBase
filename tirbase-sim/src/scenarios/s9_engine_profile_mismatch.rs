//! S9 — Migration execution profile / fuel-cost hash mismatch (PV-8.2a).
//!
//! A migration carrying an ExecutionProfileVersion whose `fuel_cost_table_hash`
//! (or `profile_id`) does not match the active pinned profile must be
//! quarantined/rejected with ENGINE_VERSION_MISMATCH before execution.

use std::sync::{Arc, Mutex};
use tirbase_core::migration::profile::{
    pinned_fuel_cost_table_hash, ExecutionProfileVersion, CONFORMANCE_CORPUS_HASH,
    DETERMINISTIC_PROFILE_ID,
};
use tirbase_core::migration::wasm_sandbox::{
    execute_migration_with_profile, MigrationExecutionRegistry, MigrationResult,
};

fn test_store() -> Arc<Mutex<tirbase_core::store::LocalStore>> {
    Arc::new(Mutex::new(
        tirbase_core::store::LocalStore::open(":memory:").expect("in-memory store"),
    ))
}

pub fn scenario_s9_engine_version_mismatch_quarantined() {
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).expect("parse");
    let bad = ExecutionProfileVersion {
        profile_id: DETERMINISTIC_PROFILE_ID,
        fuel_cost_table_hash: [0xEEu8; 32], // mismatched
        conformance_corpus_hash: CONFORMANCE_CORPUS_HASH,
        update_signer_signature: Vec::new(),
    };
    let reg = MigrationExecutionRegistry::default();
    let result =
        execute_migration_with_profile(&wasm, [0x99u8; 32], 30, &test_store(), &reg, Some(&bad))
            .expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { ref reason } if reason.contains("ENGINE_VERSION_MISMATCH")),
        "S9: mismatched fuel_cost_table_hash must be quarantined/rejected, got {result:?}"
    );
}

pub fn scenario_s9_profile_id_mismatch_quarantined() {
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).expect("parse");
    let bad = ExecutionProfileVersion {
        profile_id: *b"WRONG-PROFILE---",
        fuel_cost_table_hash: pinned_fuel_cost_table_hash(),
        conformance_corpus_hash: CONFORMANCE_CORPUS_HASH,
        update_signer_signature: Vec::new(),
    };
    let reg = MigrationExecutionRegistry::default();
    let result =
        execute_migration_with_profile(&wasm, [0x9Au8; 32], 30, &test_store(), &reg, Some(&bad))
            .expect("ok");
    assert!(
        matches!(result, MigrationResult::Aborted { ref reason } if reason.contains("ENGINE_VERSION_MISMATCH")),
        "S9: mismatched profile_id must be quarantined/rejected, got {result:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s9_fuel_cost_hash_mismatch_rejected() {
        scenario_s9_engine_version_mismatch_quarantined();
    }

    #[test]
    fn s9_profile_id_mismatch_rejected() {
        scenario_s9_profile_id_mismatch_quarantined();
    }
}
