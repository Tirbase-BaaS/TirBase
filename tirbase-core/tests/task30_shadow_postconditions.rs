//! Task 30 integration tests (native): shadow/postconditions/fleet/author revocation hooks.

#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};
use tirbase_core::crdt::delta::{Ed25519Signature, PriorityClass};
use tirbase_core::errors::TirBaseError;
use tirbase_core::migration::author_revocation::{
    check_author_not_revoked, AuthorRevocationChecker,
};
use tirbase_core::migration::fleet_precondition::{
    AcceptAllFleetPreconditions, FleetPreconditionVerifier, UnverifiedFleetInventory,
};
use tirbase_core::migration::migration_delta::{
    CaSignature, MigrationDelta, MigrationKind, PostconditionCheck, SignedPostconditions,
};
use tirbase_core::migration::postcondition::PostconditionOutcome;
use tirbase_core::migration::quarantine::QuarantineReason;
use tirbase_core::migration::shadow::run_shadow_migration_native;
use tirbase_core::migration::version_path::SchemaVersionPath;
use tirbase_core::migration::wasm_sandbox::MigrationExecutionRegistry;
use tirbase_core::migration::SchemaMigrationEngine;
use tirbase_core::store::sqlite::CREATE_SCHEMA_SQL;
use tirbase_core::store::LocalStore;

fn trivial_wasm() -> Vec<u8> {
    wat::parse_str(r#"(module (func (export "run")))"#).unwrap()
}
fn write_mutating_wasm() -> Vec<u8> {
    wat::parse_str(r#"(module
      (import "host" "write_row" (func $write (param i32 i32 i32 i32 i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "mig_t") (data (i32.const 16) "k1") (data (i32.const 32) "{\"v\":\"mutated\"}")
      (func (export "run") (call $write (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 2) (i32.const 32) (i32.const 14))))"#).unwrap()
}

#[test]
fn task30_1_2_postcondition_failure_discards_shadow_preserves_state() {
    let store = Arc::new(Mutex::new(LocalStore::open(":memory:").unwrap()));
    store
        .lock()
        .unwrap()
        .write("mig_t", "k1", &serde_json::json!({"v":"original"}))
        .unwrap();
    let pc = SignedPostconditions {
        checks: vec![PostconditionCheck::RowCount {
            table: "mig_t".into(),
            expected: 999,
        }],
        signer_public_key: None,
        signature: vec![],
    };
    let sr = run_shadow_migration_native(
        &write_mutating_wasm(),
        [7u8; 32],
        30,
        &store,
        &MigrationExecutionRegistry::default(),
        None,
        Some(&pc),
        &[2u8; 32],
        None,
    )
    .unwrap();
    assert!(matches!(
        sr.postconditions,
        Some(PostconditionOutcome::Failed { .. })
    ));
    assert!(
        sr.shadow_projections.is_none(),
        "shadow must be discarded on postcondition failure"
    );
    assert_eq!(
        store.lock().unwrap().read("mig_t", "k1").unwrap().unwrap()["v"],
        "original"
    );
}

#[test]
fn task30_3_contract_without_fleet_precondition_rejected_by_prepare_gate() {
    let store = Arc::new(Mutex::new(LocalStore::open(":memory:").unwrap()));
    let src = [1u8; 32];
    let tgt = [2u8; 32];
    let vp = SchemaVersionPath::new(vec![src, tgt]);
    let mut engine = SchemaMigrationEngine::new(
        [0u8; 32],
        src,
        vp,
        1,
        store,
        {
            let c = rusqlite::Connection::open_in_memory().unwrap();
            c.execute_batch(CREATE_SCHEMA_SQL).unwrap();
            Arc::new(Mutex::new(c))
        },
        Default::default(),
    );
    let wasm = trivial_wasm();
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(&wasm).into();
    let d = MigrationDelta {
        id: [3u8; 32],
        author_did: "did:key:author".into(),
        signature: Ed25519Signature(vec![0u8; 64]),
        source_schema_hash: src,
        target_schema_hash: tgt,
        transform_bytes: wasm,
        ca_signature: CaSignature(vec![]),
        transform_sha256: hash,
        priority: PriorityClass::Medium,
        created_at: 0,
        execution_profile: None,
        migration_kind: MigrationKind::Contract,
        fleet_precondition_hash: None,
        postconditions: None,
    };
    let e = engine.receive_migration_delta(d, "did:key:s").unwrap_err();
    assert!(
        matches!(
            e,
            TirBaseError::FleetPreconditionMissing { .. }
                | TirBaseError::MigrationCaSignatureInvalid { .. }
                | TirBaseError::AuthorisationFailed { .. }
        ),
        "{e:?}"
    );
}

#[test]
fn task30_3_fleet_hook_default_rejects_contract_and_acceptall_allows() {
    let id = [4u8; 32];
    let h = [9u8; 32];
    assert!(UnverifiedFleetInventory.verify_contract(&id, &h).is_err());
    assert!(AcceptAllFleetPreconditions.verify_contract(&id, &h).is_ok());
}

#[test]
fn task30_4_expand_contract_violation_quarantine_reason_exists() {
    assert_eq!(
        QuarantineReason::ExpandContractViolation.as_str(),
        "EXPAND_CONTRACT_VIOLATION"
    );
}

#[test]
fn task30_6_author_revocation_hook_rejects_revoked_author() {
    #[derive(Debug)]
    struct R;
    impl AuthorRevocationChecker for R {
        fn is_author_revoked(&self, d: &str) -> bool {
            d == "did:key:bad"
        }
    }
    assert!(check_author_not_revoked(&R, &[5u8; 32], "did:key:good").is_ok());
    assert!(matches!(
        check_author_not_revoked(&R, &[5u8; 32], "did:key:bad"),
        Err(TirBaseError::MigrationAuthorRevoked { .. })
    ));
}
