// SPDX-License-Identifier: AGPL-3.0-only

//! S36 — Migration signed postcondition failure (PV-8.4, /30.11).
//!
//! A migration whose signed postconditions do not hold against shadow output
//! must fail closed: shadow is discarded and pre-execution projection state is
//! preserved. (S9 remains fuel-cost hash / engine-profile mismatch per 29.3.)

use std::sync::{Arc, Mutex};
use tirbase_core::migration::migration_delta::{
    MigrationKind, PostconditionCheck, SignedPostconditions,
};
use tirbase_core::migration::postcondition::field_checksum_hex;
use tirbase_core::migration::shadow::{run_shadow_migration_native, ShadowInputs, ShadowRunOutcome};
use tirbase_core::migration::wasm_sandbox::{MigrationExecutionRegistry, MigrationResult};

fn test_store() -> Arc<Mutex<tirbase_core::store::LocalStore>> {
    Arc::new(Mutex::new(
        tirbase_core::store::LocalStore::open(":memory:").expect("in-memory store"),
    ))
}

/// Migration writes `proj_mig_test/k1.value = "mutated"`; postcondition expects
/// row count 99 (impossible) — shadow discarded, pre-execution state preserved.
pub fn scenario_s36_postcondition_failure_preserves_pre_execution_state() {
    let store = test_store();
    {
        let mut s = store.lock().unwrap();
        s.write("mig_test", "k1", &serde_json::json!({"value":"original"}))
            .expect("seed");
    }
    let wasm = wat::parse_str(r#"
      (module
        (import "host" "write_row" (func $write (param i32 i32 i32 i32 i32 i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "mig_test")
        (data (i32.const 16) "k1")
        (data (i32.const 32) "{\"value\":\"mutated\"}")
        (func (export "run")
          (call $write (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 2) (i32.const 32) (i32.const 19))
        )
      )
    "#).expect("wat");
    let pc = SignedPostconditions {
        checks: vec![PostconditionCheck::RowCount {
            table: "mig_test".to_string(),
            expected: 99,
        }],
        signer_public_key: None,
        signature: Vec::new(), // unsigned checks allowed by shadow for explicit check sets in this harness
    };
    let sr = run_shadow_migration_native(
        &wasm,
        [0x36u8; 32],
        30,
        &store,
        &MigrationExecutionRegistry::default(),
        ShadowInputs {
            execution_profile: None,
            postconditions: Some(&pc),
            target_schema_hash: &[0x36u8; 32],
            target_schema: None,
        },
    )
    .expect("shadow run");
    assert!(
        matches!(
            sr.postconditions,
            Some(tirbase_core::migration::postcondition::PostconditionOutcome::Failed { .. })
        ),
        "S36: postcondition must fail, got {:?}",
        sr.postconditions
    );
    assert!(
        sr.shadow_projections.is_none(),
        "S36: shadow must be discarded"
    );
    let v = store
        .lock()
        .unwrap()
        .read("mig_test", "k1")
        .expect("read")
        .expect("row");
    assert_eq!(
        v.get("value").and_then(|x| x.as_str()),
        Some("original"),
        "S36: pre-execution state must be preserved"
    );
    let _ = MigrationKind::Legacy;
    let _ = ShadowRunOutcome {
        migration_result: MigrationResult::Success,
        postconditions: None,
        shadow_projections: None,
        quarantine_reason: None,
        quarantine_detail: None,
    };
}

/// Passing postcondition allows shadow commit path to produce projections (caller commits).
pub fn scenario_s36_postcondition_pass_produces_shadow_projections() {
    let store = test_store();
    {
        store
            .lock()
            .unwrap()
            .write("mig_test", "k1", &serde_json::json!({"value":"original"}))
            .unwrap();
    }
    let wasm = wat::parse_str(r#"(module (func (export "run")))"#).unwrap();
    let expected = field_checksum_hex(&store.lock().unwrap(), "mig_test", "value").unwrap();
    let pc = SignedPostconditions {
        checks: vec![PostconditionCheck::FieldChecksum {
            table: "mig_test".to_string(),
            field: "value".to_string(),
            expected_sha256_hex: expected,
        }],
        signer_public_key: None,
        signature: Vec::new(),
    };
    let sr = run_shadow_migration_native(
        &wasm,
        [0x37u8; 32],
        30,
        &store,
        &MigrationExecutionRegistry::default(),
        ShadowInputs {
            execution_profile: None,
            postconditions: Some(&pc),
            target_schema_hash: &[0x37u8; 32],
            target_schema: None,
        },
    )
    .unwrap();
    assert!(
        sr.shadow_projections.is_some(),
        "S36 control: passing postcondition must yield shadow projections"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s36_postcondition_failure_discards_shadow_preserves_state() {
        scenario_s36_postcondition_failure_preserves_pre_execution_state();
    }
    #[test]
    fn s36_postcondition_pass_yields_projections() {
        scenario_s36_postcondition_pass_produces_shadow_projections();
    }
}
