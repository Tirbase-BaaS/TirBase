//! `applied_effects_ledger` SQLite store (PV-5.1, CLAIM-15.1/19.1, INV-12).
//! The first durable state is `Actuating` (no `Intent`).
//!
//! Task 19 adds boot crash reconciliation (19.2/19.3, PV-5.3, INV-11),
//! ledger pruning (19.5, PV-5.12), and failpoint coverage (19.6, PV-5.4).

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

pub const APPLIED_EFFECTS_LEDGER_TABLE: &str = "applied_effects_ledger";

/// Maximum retention: 90 days or 1,000,000 entries, whichever comes first (PV-5.12).
pub const PRUNE_MAX_AGE_SECS: i64 = 90 * 24 * 60 * 60;
pub const PRUNE_MAX_ENTRIES: i64 = 1_000_000;

/// Default driver read-back timeout for boot reconciliation (PV-5.3).
pub const RECONCILE_READBACK_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Actuating" => Some(EffectState::Actuating),
            "Complete" => Some(EffectState::Complete),
            "Failed" => Some(EffectState::Failed),
            "Unknown" => Some(EffectState::Unknown),
            _ => None,
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            EffectState::Complete | EffectState::Failed | EffectState::Unknown
        )
    }
}

/// Minimal view of an `Actuating` row used by boot reconciliation (19.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuatingEntry {
    pub entry_id: [u8; 16],
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub desired_mantissa: i64,
    pub desired_exponent: i8,
    pub desired_unit_id: u16,
    pub actuating_ts: i64,
}

/// Result of a driver read-back used by reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBackOutcome {
    /// Driver reports state matches the commanded value.
    Matches,
    /// Driver reports a different state.
    Mismatch { response: Vec<u8> },
    /// Driver did not respond within timeout.
    Timeout,
}

/// Summary of a boot reconciliation pass (19.2/19.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconciliationSummary {
    pub pre_actuating_marked_failed: usize,
    pub actuating_complete: usize,
    pub actuating_failed: usize,
    pub actuating_unknown: usize,
    pub timed_out: bool,
}
impl ReconciliationSummary {
    pub fn resolved_all(&self) -> bool {
        !self.timed_out && self.actuating_unknown == 0
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
    if tirbase_core::fail_crate::eval("aef_insert_actuating", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_insert_actuating"));
    }
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
    if tirbase_core::fail_crate::eval("aef_update_terminal", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_update_terminal"));
    }
    tx.execute(
        &format!("UPDATE {APPLIED_EFFECTS_LEDGER_TABLE} SET state=?1, completion_ts=?2, driver_response=?3 WHERE entry_id=?4"),
        params![state.as_str(), completion_ts, driver_response, entry_id.as_slice()],
    ).map_err(|e| format!("update effect state: {e}"))?;
    Ok(())
}

/// List all rows in `Actuating` state (19.2 boot reconciliation).
pub fn list_actuating(conn: &Connection) -> Result<Vec<ActuatingEntry>, String> {
    if tirbase_core::fail_crate::eval("aef_scan_actuating", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_scan_actuating"));
    }
    let mut stmt = conn
        .prepare(&format!(
            "SELECT entry_id,issuer_did,target_id,param,desired_mantissa,desired_exponent,desired_unit_id,actuating_ts \
             FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE state='Actuating'"
        ))
        .map_err(|e| format!("prepare list_actuating: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let mut id = [0u8; 16];
            if blob.len() == 16 {
                id.copy_from_slice(&blob);
            }
            Ok(ActuatingEntry {
                entry_id: id,
                issuer_did: row.get(1)?,
                target_id: row.get(2)?,
                param: row.get(3)?,
                desired_mantissa: row.get(4)?,
                desired_exponent: row.get::<_, i64>(5)? as i8,
                desired_unit_id: row.get::<_, i64>(6)? as u16,
                actuating_ts: row.get(7)?,
            })
        })
        .map_err(|e| format!("query list_actuating: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("row list_actuating: {e}"))?);
    }
    Ok(out)
}

/// 19.3: Scan for ledger entries in a pre-Actuating state (legacy schema states
/// such as `Intent` that are not valid in the current Actuating-first schema)
/// and mark them `Failed` with reason `OLD_SCHEMA_ENTRY`. `Actuating` is NOT a
/// pre-Actuating state and MUST NOT be marked by this pass (INV-12 safety).
pub fn mark_pre_actuating_as_old_schema_failed(
    conn: &Connection,
    completion_ts: i64,
) -> Result<usize, String> {
    if tirbase_core::fail_crate::eval("aef_mark_pre_actuating", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_mark_pre_actuating"));
    }
    let changed = conn
        .execute(
            &format!(
                "UPDATE {APPLIED_EFFECTS_LEDGER_TABLE} \
                 SET state='Failed', completion_ts=?1, driver_response=?2 \
                 WHERE state NOT IN ('Actuating','Complete','Failed','Unknown')"
            ),
            params![completion_ts, b"OLD_SCHEMA_ENTRY".as_slice()],
        )
        .map_err(|e| format!("mark_pre_actuating: {e}"))?;
    Ok(changed)
}

/// 19.2: Apply a single reconciliation outcome to an `Actuating` entry.
pub fn apply_reconciliation_outcome(
    conn: &Connection,
    entry_id: &[u8; 16],
    outcome: &ReadBackOutcome,
    completion_ts: i64,
) -> Result<EffectState, String> {
    if tirbase_core::fail_crate::eval("aef_apply_reconciliation", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_apply_reconciliation"));
    }
    let (state, response): (EffectState, Option<&[u8]>) = match outcome {
        ReadBackOutcome::Matches => (EffectState::Complete, Some(b"MATCH".as_slice())),
        ReadBackOutcome::Mismatch { response } => (EffectState::Failed, Some(response.as_slice())),
        ReadBackOutcome::Timeout => (EffectState::Unknown, Some(b"TIMEOUT".as_slice())),
    };
    conn.execute(
        &format!(
            "UPDATE {APPLIED_EFFECTS_LEDGER_TABLE} \
             SET state=?1, completion_ts=?2, driver_response=?3 WHERE entry_id=?4"
        ),
        params![state.as_str(), completion_ts, response, entry_id.as_slice()],
    )
    .map_err(|e| format!("apply_reconciliation_outcome: {e}"))?;
    Ok(state)
}

/// Read the current state string for an entry (test/helper).
pub fn get_state(conn: &Connection, entry_id: &[u8; 16]) -> Result<Option<String>, String> {
    conn.query_row(
        &format!("SELECT state FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE entry_id=?1"),
        params![entry_id.as_slice()],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| format!("get_state: {e}"))
}

/// 19.5: Prune oldest `Complete`/`Failed` entries beyond retention limits.
/// Returns number of rows deleted.
pub fn prune_retention(
    conn: &Connection,
    now_est: i64,
    max_age_secs: i64,
    max_entries: i64,
) -> Result<usize, String> {
    if tirbase_core::fail_crate::eval("aef_prune", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_prune"));
    }
    let cutoff = now_est.saturating_sub(max_age_secs);
    // Age-based pruning of terminal Complete/Failed entries.
    let age_deleted = conn
        .execute(
            &format!(
                "DELETE FROM {APPLIED_EFFECTS_LEDGER_TABLE} \
                 WHERE state IN ('Complete','Failed') AND COALESCE(completion_ts, actuating_ts) < ?1"
            ),
            params![cutoff],
        )
        .map_err(|e| format!("prune age: {e}"))?;
    // Count-based pruning: keep newest entries overall, removing oldest Complete/Failed first.
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {APPLIED_EFFECTS_LEDGER_TABLE}"),
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("prune count: {e}"))?;
    let mut count_deleted = 0usize;
    if total > max_entries {
        let excess = total - max_entries;
        count_deleted = conn
            .execute(
                &format!(
                    "DELETE FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE rowid IN ( \
                        SELECT rowid FROM {APPLIED_EFFECTS_LEDGER_TABLE} \
                        WHERE state IN ('Complete','Failed') \
                        ORDER BY COALESCE(completion_ts, actuating_ts) ASC, rowid ASC \
                        LIMIT ?1 \
                     )"
                ),
                params![excess],
            )
            .map_err(|e| format!("prune count: {e}"))?;
    }
    Ok(age_deleted + count_deleted)
}

pub fn count_entries(conn: &Connection) -> Result<i64, String> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {APPLIED_EFFECTS_LEDGER_TABLE}"),
        [],
        |r| r.get(0),
    )
    .map_err(|e| format!("count_entries: {e}"))
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

/// Task 21.9: list targets with unresolved `Unknown` entries.
pub fn list_unknown_targets(conn: &Connection) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT DISTINCT target_id FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE state='Unknown'"
        ))
        .map_err(|e| format!("prepare unknown targets: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| format!("query unknown targets: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("collect unknown targets: {e}"))
}

/// Task 21.9: operator-clear (PolicyAuthority) advances an `Unknown` entry to
/// `Failed`. Production caller: gateway admin path.
pub fn operator_clear_unknown_to_failed(
    conn: &Connection,
    entry_id: &[u8; 16],
    completion_ts: i64,
    operator_detail: &[u8],
) -> Result<bool, String> {
    let changed = conn
        .execute(
            &format!(
                "UPDATE {APPLIED_EFFECTS_LEDGER_TABLE}
                 SET state='Failed', completion_ts=?2, driver_response=?3
                 WHERE entry_id=?1 AND state='Unknown'"
            ),
            params![entry_id.as_slice(), completion_ts, operator_detail],
        )
        .map_err(|e| format!("operator clear unknown: {e}"))?;
    Ok(changed > 0)
}

/// Task 21.9: insert or upsert an Unknown entry (admin/operator/test helper).
pub fn mark_unknown_tx(
    tx: &Transaction<'_>,
    entry_id: [u8; 16],
    issuer_did: &str,
    target_id: &str,
    param: &str,
    actuating_ts: i64,
) -> Result<(), String> {
    tx.execute(
        &format!("INSERT OR REPLACE INTO {APPLIED_EFFECTS_LEDGER_TABLE} (entry_id,issuer_did,target_id,param,desired_mantissa,desired_exponent,desired_unit_id,sequence_number,idempotency_key,expiry_est,policy_version,enrollment_epoch,state,actuating_ts,completion_ts,driver_response) VALUES (?1,?2,?3,?4,0,0,0,0,?5,0,0,0,'Unknown',?6,?6,NULL)"),
        params![entry_id.as_slice(), issuer_did, target_id, param, entry_id.as_slice(), actuating_ts],
    ).map_err(|e| format!("mark unknown: {e}"))?;
    Ok(())
}

/// Task 21.9 runtime sync helper: resolve target_id for an entry (used to clear
/// pipeline unknown_targets after operator clear).
pub fn target_id_for_entry(
    conn: &Connection,
    entry_id: &[u8; 16],
) -> Result<Option<String>, String> {
    conn.query_row(
        &format!("SELECT target_id FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE entry_id=?1"),
        params![entry_id.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| format!("target_id_for_entry: {e}"))
}

/// Returns true if the target still has any `Unknown` AEF entries.
pub fn target_has_unknown(conn: &Connection, target_id: &str) -> Result<bool, String> {
    let n: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {APPLIED_EFFECTS_LEDGER_TABLE} WHERE target_id=?1 AND state='Unknown'"),
            params![target_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("target_has_unknown: {e}"))?;
    Ok(n > 0)
}
