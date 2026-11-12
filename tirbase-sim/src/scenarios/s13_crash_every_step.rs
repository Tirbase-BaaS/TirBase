//! Scenario S13 — crash at every write boundary in the effects ledger.
//!
//! A crash after the durable `Actuating` write but before the terminal update
//! must never leave a row stuck in `Actuating` after boot reconciliation, and a
//! retried command must never actuate twice.
//!
//! The scenario uses the real gateway `SqliteStage16Store` and the real
//! `commit_dispatch_finalize` Stage 16–19 path, then injects crashed rows and
//! runs the production boot reconciler.

use std::io::Cursor;
use std::sync::Arc;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::db::applied_effects_ledger::{
    self, AppliedEffectRow, EffectState, ReadBackOutcome,
};
use tirbase_gateway::db::ledger_reconciliation::{reconcile_on_boot, LedgerReadBack};
use tirbase_gateway::guard::SqliteStage16Store;
use tirbase_guard::commit::{commit_dispatch_finalize, FinalizeContext};
use tirbase_guard::driver_proxy::DriverProxy;
use tirbase_guard::sign_command;
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

#[derive(Debug)]
struct ScriptedReadBack {
    outcomes: Vec<ReadBackOutcome>,
}

impl LedgerReadBack for ScriptedReadBack {
    fn read_back(
        &self,
        entry: &applied_effects_ledger::ActuatingEntry,
        _timeout: std::time::Duration,
    ) -> ReadBackOutcome {
        let index = (entry.entry_id[0] as usize) % self.outcomes.len().max(1);
        self.outcomes[index].clone()
    }
}

fn command(issuer: &InMemoryKeyProvider, idempotency_key: [u8; 16]) -> CommandMessage {
    let mut command = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-s13"),
        param: "speed".to_string(),
        desired_state: FixedPointValue::new(500, -1, UNIT_PERCENT),
        sequence_number: 1,
        idempotency_key,
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut command, issuer).expect("sign command");
    command
}

fn crash_row(step: u8) -> AppliedEffectRow {
    AppliedEffectRow {
        entry_id: [step.saturating_add(10); 16],
        issuer_did: "did:key:crash".to_string(),
        target_id: "pump-s13".to_string(),
        param: "speed".to_string(),
        desired_mantissa: 500,
        desired_exponent: -1,
        desired_unit_id: UNIT_PERCENT,
        sequence_number: step as u64,
        idempotency_key: [step; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        state: EffectState::Actuating,
        actuating_ts: 1_000 + step as i64,
        completion_ts: None,
        driver_response: None,
    }
}

/// S13 — every crash boundary resolves at boot and never double-actuates.
pub fn run_s13(seed: u64) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("tirbase-sim-s13-{}-{seed}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|error| format!("S13 tempdir: {error}"))?;
    let db_path = dir.join("primary.db");
    let result = run_s13_inner(seed, &db_path);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_s13_inner(seed: u64, db_path: &std::path::Path) -> Result<(), String> {
    let issuer = InMemoryKeyProvider::generate().map_err(|error| format!("S13 keygen: {error}"))?;
    let store = SqliteStage16Store::open(db_path).map_err(|error| format!("S13 store: {error}"))?;

 // Normal Stage 16–19 path: commit, dispatch, finalize.
    let cmd = command(&issuer, [seed as u8; 16]);
    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut wire));
    let mut driver = Cursor::new(b"OK".to_vec());
    let accepted = commit_dispatch_finalize(
        &store,
        &cmd,
        FinalizeContext {
            entry_id: [1u8; 16],
            actuating_ts: 1_000,
            now_est: 1_000,
            now_mono_secs: 1_000,
            completion_ts: 1_001,
        },
        &mut proxy,
        b"ACT",
        &mut driver,
    );
    if accepted["status"] != "accepted" || wire.is_empty() {
        return Err(format!(
            "S13 FAIL: healthy command not actuated: {accepted}"
        ));
    }

 // Retry after a crash between finalize and the client receiving the reply:
 // the idempotency record must return the original result with no actuation.
    let mut retry_wire = Vec::new();
    let mut retry_proxy = DriverProxy::new(Cursor::new(&mut retry_wire));
    let mut retry_driver = Cursor::new(b"OK".to_vec());
    let retried = commit_dispatch_finalize(
        &store,
        &cmd,
        FinalizeContext {
            entry_id: [2u8; 16],
            actuating_ts: 1_002,
            now_est: 1_000,
            now_mono_secs: 1_002,
            completion_ts: 1_003,
        },
        &mut retry_proxy,
        b"ACT",
        &mut retry_driver,
    );
    if retried["idempotency_cache_hit"] != true || !retry_wire.is_empty() {
        return Err(format!(
            "S13 FAIL: retry after crash actuated twice: {retried}"
        ));
    }

 // Crash at each durable write boundary: insert the `Actuating` row and stop
 // before the terminal update. The next boot must reconcile every row.
    let mut connection =
        rusqlite::Connection::open(db_path).map_err(|error| format!("S13 open ledger: {error}"))?;
    applied_effects_ledger::create_table(&connection)
        .map_err(|error| format!("S13 create ledger: {error}"))?;
    for step in 0..4u8 {
        let transaction = connection
            .transaction()
            .map_err(|error| format!("S13 tx: {error}"))?;
        applied_effects_ledger::insert_actuating_tx(&transaction, &crash_row(step))
            .map_err(|error| format!("S13 insert: {error}"))?;
        transaction
            .commit()
            .map_err(|error| format!("S13 commit: {error}"))?;
    }

    let outcomes = Arc::new(ScriptedReadBack {
        outcomes: vec![
            ReadBackOutcome::Matches,
            ReadBackOutcome::Mismatch {
                response: b"MISMATCH".to_vec(),
            },
            ReadBackOutcome::Timeout,
        ],
    });
    let summary = reconcile_on_boot(&connection, outcomes.as_ref(), 2_000)
        .map_err(|error| format!("S13 reconcile: {error}"))?;
    let remaining = applied_effects_ledger::list_actuating(&connection)
        .map_err(|error| format!("S13 list: {error}"))?;
    if !remaining.is_empty() {
        return Err(format!(
            "S13 FAIL: {} entries remain Actuating after reconciliation",
            remaining.len()
        ));
    }

    let mut states = std::collections::BTreeMap::new();
    for step in 0..4u8 {
        let state = applied_effects_ledger::get_state(&connection, &[step.saturating_add(10); 16])
            .map_err(|error| format!("S13 state: {error}"))?
            .as_deref()
            .and_then(EffectState::parse);
        states.insert(step, state);
    }
    let terminal = states
        .values()
        .filter(|state| state.map(EffectState::is_terminal).unwrap_or(false))
        .count();
    if terminal != 4 {
        return Err(format!(
            "S13 FAIL: not every crashed entry reached a terminal state: {states:?}"
        ));
    }
    if summary.actuating_unknown == 0 {
        return Err("S13 FAIL: timeout crash did not produce an Unknown entry".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s13_crash_at_every_step_reconciles() {
        run_s13(1).expect("S13");
    }
}
