//! Shadow-copy migration execution over projection tables (PV-8.4, Task 30.1/30.2/30.5).

#![allow(dead_code)]

use crate::errors::TirBaseError;
use crate::events::{emit_migration, ReasonCode, Severity};
use crate::migration::migration_delta::SignedPostconditions;
use crate::migration::postcondition::{evaluate_postconditions, PostconditionOutcome};
use crate::migration::quarantine::QuarantineReason;
use crate::migration::wasm_sandbox::{MigrationExecutionRegistry, MigrationResult};
use crate::schema::hash::SchemaIdentifierHash;
use crate::schema::Schema;
use crate::store::LocalStore;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct ShadowRunOutcome {
    pub migration_result: MigrationResult,
    pub postconditions: Option<PostconditionOutcome>,
    pub shadow_projections: Option<Vec<(String, Vec<(String, serde_json::Value)>)>>,
    /// Quarantine to record if present (caller records under engine lock).
    pub quarantine_reason: Option<QuarantineReason>,
    pub quarantine_detail: Option<String>,
}

#[cfg(feature = "native")]
pub fn run_shadow_migration_native(
    transform: &[u8],
    migration_id: [u8; 32],
    timeout_secs: u64,
    real_store: &Arc<Mutex<LocalStore>>,
    registry: &MigrationExecutionRegistry,
    execution_profile: Option<&crate::migration::profile::ExecutionProfileVersion>,
    postconditions: Option<&SignedPostconditions>,
    target_schema_hash: &SchemaIdentifierHash,
    target_schema: Option<&Schema>,
) -> Result<ShadowRunOutcome, TirBaseError> {
    let mid_hex = hex::encode(migration_id);
    let (proj_tables, snapshot) = {
        let store = real_store
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("shadow snapshot store lock poisoned: {e}"),
            })?;
        let tables = store.list_projection_tables()?;
        let mut snap = Vec::new();
        for t in &tables {
            snap.push((t.clone(), store.read_all_rows(t)?));
        }
        (tables, snap)
    };
    let mut shadow = LocalStore::open(":memory:")?;
    for (table, rows) in &snapshot {
        for (key, value) in rows {
            shadow.write(table, key, value)?;
        }
    }
    let shadow_arc = Arc::new(Mutex::new(shadow));
    let migration_result = crate::migration::wasm_sandbox::execute_migration_with_profile(
        transform,
        migration_id,
        timeout_secs,
        &shadow_arc,
        registry,
        execution_profile,
    )?;
    match &migration_result.clone() {
        MigrationResult::Success => {}
        MigrationResult::TimedOut { timeout_secs } => {
            emit_migration(Severity::Medium, ReasonCode::MigrationCancelled, Some(mid_hex),
                format!("[migration shadow] timed out/cancelled after {timeout_secs}s; pre-execution state preserved"));
            return Ok(ShadowRunOutcome {
                migration_result,
                postconditions: None,
                shadow_projections: None,
                quarantine_reason: Some(QuarantineReason::MigrationCancelled),
                quarantine_detail: Some("timed out/cancelled".into()),
            });
        }
        MigrationResult::Revoked { .. } => {
            return Ok(ShadowRunOutcome {
                migration_result,
                postconditions: None,
                shadow_projections: None,
                quarantine_reason: None,
                quarantine_detail: None,
            })
        }
        MigrationResult::Aborted {
            reason: ref abort_reason,
        } => {
            let reason = abort_reason.clone();
            let qr = if reason.contains("revoked")
                || reason.contains("interrupt")
                || reason.contains("cancel")
            {
                emit_migration(Severity::Medium, ReasonCode::MigrationCancelled, Some(mid_hex),
                    format!("[migration shadow] cancelled at fuel boundary: {reason}; pre-execution state preserved"));
                Some(QuarantineReason::MigrationCancelled)
            } else {
                None
            };
            return Ok(ShadowRunOutcome {
                migration_result,
                postconditions: None,
                shadow_projections: None,
                quarantine_reason: qr,
                quarantine_detail: Some(reason.clone()),
            });
        }
    }
    let pc_outcome = if let Some(pc) = postconditions {
        let shadow_guard = shadow_arc
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("shadow postcondition lock poisoned: {e}"),
            })?;
        let allow_unsigned =
            pc.signature.is_empty() && pc.signer_public_key.is_none() && !pc.checks.is_empty();
        let outcome = evaluate_postconditions(
            pc,
            &shadow_guard,
            target_schema_hash,
            target_schema,
            &mid_hex,
            allow_unsigned,
        )?;
        if matches!(outcome, PostconditionOutcome::Failed { .. }) {
            return Ok(ShadowRunOutcome {
                migration_result: MigrationResult::Success,
                postconditions: Some(outcome),
                shadow_projections: None,
                quarantine_reason: Some(QuarantineReason::PostconditionFailure),
                quarantine_detail: Some("signed postcondition failed".into()),
            });
        }
        Some(outcome)
    } else {
        emit_migration(Severity::Low, ReasonCode::MigrationApplied, Some(mid_hex.clone()),
            "[migration shadow] legacy migration without signed postconditions: shadow executed, implicit schema-hash target preserved".to_string());
        Some(PostconditionOutcome::Passed)
    };
    let mut shadow_projections = Vec::new();
    let shadow_guard = shadow_arc
        .lock()
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("shadow commit lock poisoned: {e}"),
        })?;
    let mut shadow_tables = shadow_guard.list_projection_tables()?;
    for t in proj_tables {
        if !shadow_tables.contains(&t) {
            shadow_tables.push(t);
        }
    }
    shadow_tables.sort();
    shadow_tables.dedup();
    for table in shadow_tables {
        shadow_projections.push((table.clone(), shadow_guard.read_all_rows(&table)?));
    }
    Ok(ShadowRunOutcome {
        migration_result: MigrationResult::Success,
        postconditions: pc_outcome,
        shadow_projections: Some(shadow_projections),
        quarantine_reason: None,
        quarantine_detail: None,
    })
}

#[cfg(feature = "native")]
pub fn commit_shadow_projections(
    real_store: &Arc<Mutex<LocalStore>>,
    projections: Vec<(String, Vec<(String, serde_json::Value)>)>,
) -> Result<(), TirBaseError> {
    let mut real = real_store
        .lock()
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("real store lock poisoned for shadow commit: {e}"),
        })?;
    for (table, rows) in projections {
        for (key, value) in rows {
            real.write(&table, &key, &value)?;
        }
    }
    Ok(())
}
