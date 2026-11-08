//! `applied_effects_ledger` SQLite store (PV-5.1, CLAIM-15.1/19.1, INV-12).
//! The first durable state is `Actuating` (no `Intent`).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, Transaction};

pub const APPLIED_EFFECTS_LEDGER_TABLE: &str = "applied_effects_ledger";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Actuating,
    Complete,
    Failed,
    Unknown,
}
impl EffectState {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectState::Actuating => "Actuating",
            EffectState::Complete => "Complete",
            EffectState::Failed => "Failed",
            EffectState::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEffectRow {
    pub entry_id: [u8; 16],
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub desired_mantissa: i64,
    pub desired_exponent: i8,
    pub desired_unit_id: u16,
    pub sequence_number: u64,
    pub idempotency_key: [u8; 16],
    pub expiry_est: i64,
    pub policy_version: u64,
    pub enrollment_epoch: u64,
    pub state: EffectState,
    pub actuating_ts: i64,
    pub completion_ts: Option<i64>,
    pub driver_response: Option<Vec<u8>>,
}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {APPLIED_EFFECTS_LEDGER_TABLE} (
            entry_id          BLOB PRIMARY KEY,
            issuer_did        TEXT NOT NULL,
            target_id         TEXT NOT NULL,
            param             TEXT NOT NULL,
            desired_mantissa  INTEGER NOT NULL,
            desired_exponent  INTEGER NOT NULL,
            desired_unit_id   INTEGER NOT NULL,
            sequence_number   INTEGER NOT NULL,
            idempotency_key   BLOB NOT NULL,
            expiry_est        INTEGER NOT NULL,
            policy_version    INTEGER NOT NULL,
            enrollment_epoch  INTEGER NOT NULL DEFAULT 0,
            state             TEXT NOT NULL,
            actuating_ts      INTEGER NOT NULL,
            completion_ts     INTEGER,
            driver_response   BLOB
        );
        CREATE INDEX IF NOT EXISTS idx_aef_state  ON {APPLIED_EFFECTS_LEDGER_TABLE}(state);
        CREATE INDEX IF NOT EXISTS idx_aef_target ON {APPLIED_EFFECTS_LEDGER_TABLE}(target_id, state);"
    )).map_err(|e| format!("create applied_effects_ledger: {e}"))
}

pub fn insert_actuating_tx(tx: &Transaction<'_>, row: &AppliedEffectRow) -> Result<(), String> {
    tx.execute(
        &format!("INSERT INTO {APPLIED_EFFECTS_LEDGER_TABLE}
            (entry_id,issuer_did,target_id,param,desired_mantissa,desired_exponent,desired_unit_id,sequence_number,idempotency_key,expiry_est,policy_version,enrollment_epoch,state,actuating_ts,completion_ts,driver_response)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"),
        params![
            row.entry_id.as_slice(), row.issuer_did, row.target_id, row.param,
            row.desired_mantissa, row.desired_exponent as i64, row.desired_unit_id as i64,
            row.sequence_number as i64, row.idempotency_key.as_slice(), row.expiry_est,
            row.policy_version as i64, row.enrollment_epoch as i64, EffectState::Actuating.as_str(),
            row.actuating_ts, row.completion_ts, row.driver_response,
        ],
    ).map_err(|e| format!("insert Actuating: {e}"))?;
    Ok(())
}

pub fn update_terminal_state_tx(
    tx: &Transaction<'_>,
    entry_id: &[u8; 16],
    state: EffectState,
    completion_ts: i64,
    driver_response: Option<&[u8]>,
) -> Result<(), String> {
    tx.execute(
        &format!("UPDATE {APPLIED_EFFECTS_LEDGER_TABLE} SET state=?1, completion_ts=?2, driver_response=?3 WHERE entry_id=?4"),
        params![state.as_str(), completion_ts, driver_response, entry_id.as_slice()],
    ).map_err(|e| format!("update effect state: {e}"))?;
    Ok(())
}

#[derive(Debug)]
pub struct SqliteAppliedEffectsStore {
    conn: Mutex<Connection>,
}
impl SqliteAppliedEffectsStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("synchronous: {e}"))?;
        create_table(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    pub fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}
