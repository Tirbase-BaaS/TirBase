//! `drift_rate_history` SQLite store (PV-4.7, CLAIM-14.15/21.7/21.10/21.13).
//!
//! Supports two compatible access patterns:
//! - Sample history (`record`/`recent`) used by existing tests and in-memory
//!   drift window checks.
//! - Per-(target,param) summary row updated atomically in Stage 16 for dwell/
//!   min-off interlocks and persisted drift summary (`upsert_summary_tx`,
//!   `load_summary*`).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use tirbase_types::fixed_point::FixedPointValue;

pub const DRIFT_RATE_HISTORY_TABLE: &str = "drift_rate_history";
pub const DRIFT_RATE_SUMMARY_TABLE: &str = "drift_rate_summary";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftHistoryRow {
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub mono_secs: i64,
    pub value_mantissa: i64,
    pub exponent: i8,
    pub unit_id: u16,
}

/// Per-(target,param) summary state for Stage 13 dwell/min-off and Stage 16
/// atomic drift-history writes (Task 21.10/21.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftSummaryRow {
    pub target_id: String,
    pub param: String,
    pub last_accepted_est: i64,
    pub last_accepted_mono: i64,
    pub last_value: FixedPointValue,
    pub window_start_est: i64,
    pub cumulative_delta_mantissa: i64,
    /// Monotonic time of last accepted value change for this (target,param).
    pub last_change_mono: i64,
    /// Monotonic time of last accepted deactivation (Bool 1→0), if observed.
    pub last_deactivation_mono: Option<i64>,
}

pub fn create_summary_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {DRIFT_RATE_SUMMARY_TABLE} (
             target_id                 TEXT NOT NULL,
             param                     TEXT NOT NULL,
             last_accepted_est         INTEGER NOT NULL,
             last_accepted_mono        INTEGER NOT NULL,
             last_value_mantissa       INTEGER NOT NULL,
             last_value_exponent       INTEGER NOT NULL,
             last_value_unit_id        INTEGER NOT NULL,
             window_start_est          INTEGER NOT NULL DEFAULT 0,
             cumulative_delta_mantissa INTEGER NOT NULL DEFAULT 0,
             last_change_mono          INTEGER NOT NULL,
             last_deactivation_mono    INTEGER,
             PRIMARY KEY (target_id, param)
         );"
    ))
    .map_err(|e| format!("create drift_rate_summary: {e}"))
}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    // Legacy-compatible sample table; Stage 16/Stage 13 summary columns are
    // added by migrations or ensured best-effort below.
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {DRIFT_RATE_HISTORY_TABLE} (
             issuer_did     TEXT NOT NULL,
             target_id      TEXT NOT NULL,
             param          TEXT NOT NULL,
             mono_secs      INTEGER NOT NULL,
             value_mantissa INTEGER NOT NULL,
             exponent       INTEGER NOT NULL,
             unit_id        INTEGER NOT NULL,
             PRIMARY KEY (issuer_did, target_id, param, mono_secs)
         );
         CREATE INDEX IF NOT EXISTS idx_drift_lookup
           ON {DRIFT_RATE_HISTORY_TABLE}(issuer_did, target_id, param, mono_secs);"
    ))
    .map_err(|e| format!("create drift_rate_history: {e}"))?;
    ensure_summary_columns(conn).ok();
    create_summary_table(conn).ok();
    Ok(())
}

fn ensure_summary_columns(conn: &Connection) -> Result<(), String> {
    // Best-effort additive columns for DBs not yet on migration v2.
    for sql in [
        "ALTER TABLE drift_rate_history ADD COLUMN last_accepted_mono INTEGER",
        "ALTER TABLE drift_rate_history ADD COLUMN last_change_mono INTEGER",
        "ALTER TABLE drift_rate_history ADD COLUMN last_deactivation_mono INTEGER",
    ] {
        let _ = conn.execute(sql, []);
    }
    Ok(())
}

pub fn upsert_summary_tx(tx: &Transaction<'_>, summary: &DriftSummaryRow) -> Result<(), String> {
    tirbase_core::fail_crate::fail_point!("fp_drift_summary_upsert", |_| Err(
        "failpoint fp_drift_summary_upsert".to_string()
    ));
    tx.execute(
        &format!("INSERT INTO {DRIFT_RATE_SUMMARY_TABLE}
            (target_id,param,last_accepted_est,last_accepted_mono,last_value_mantissa,last_value_exponent,last_value_unit_id,
             window_start_est,cumulative_delta_mantissa,last_change_mono,last_deactivation_mono)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(target_id,param) DO UPDATE SET
            last_accepted_est=excluded.last_accepted_est,
            last_accepted_mono=excluded.last_accepted_mono,
            last_value_mantissa=excluded.last_value_mantissa,
            last_value_exponent=excluded.last_value_exponent,
            last_value_unit_id=excluded.last_value_unit_id,
            window_start_est=excluded.window_start_est,
            cumulative_delta_mantissa=excluded.cumulative_delta_mantissa,
            last_change_mono=excluded.last_change_mono,
            last_deactivation_mono=COALESCE(excluded.last_deactivation_mono,{DRIFT_RATE_SUMMARY_TABLE}.last_deactivation_mono)"),
        params![
            summary.target_id,
            summary.param,
            summary.last_accepted_est,
            summary.last_accepted_mono,
            summary.last_value.mantissa,
            summary.last_value.exponent as i64,
            summary.last_value.unit_id as i64,
            summary.window_start_est,
            summary.cumulative_delta_mantissa,
            summary.last_change_mono,
            summary.last_deactivation_mono,
        ],
    )
    .map_err(|e| format!("upsert drift summary: {e}"))?;
    Ok(())
}

pub fn load_summary_conn(
    conn: &Connection,
    target_id: &str,
    param: &str,
) -> Result<Option<DriftSummaryRow>, String> {
    conn.query_row(
        &format!("SELECT target_id,param,last_accepted_est,last_accepted_mono,last_value_mantissa,last_value_exponent,last_value_unit_id,window_start_est,cumulative_delta_mantissa,last_change_mono,last_deactivation_mono FROM {DRIFT_RATE_SUMMARY_TABLE} WHERE target_id=?1 AND param=?2"),
        params![target_id, param],
        |row| {
            Ok(DriftSummaryRow {
                target_id: row.get(0)?,
                param: row.get(1)?,
                last_accepted_est: row.get(2)?,
                last_accepted_mono: row.get(3)?,
                last_value: FixedPointValue { mantissa: row.get(4)?, exponent: row.get::<_, i64>(5)? as i8, unit_id: row.get::<_, i64>(6)? as u16 },
                window_start_est: row.get(7)?,
                cumulative_delta_mantissa: row.get(8)?,
                last_change_mono: row.get(9)?,
                last_deactivation_mono: row.get(10)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("load drift summary: {e}"))
}

#[derive(Debug)]
pub struct SqliteDriftRateHistoryStore {
    conn: Mutex<Connection>,
}

impl SqliteDriftRateHistoryStore {
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Insert/replace one sample row (legacy-compatible API).
    pub fn record(&self, row: &DriftHistoryRow) -> Result<(), String> {
        self.lock()
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {DRIFT_RATE_HISTORY_TABLE}
                     (issuer_did,target_id,param,mono_secs,value_mantissa,exponent,unit_id)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)"
                ),
                params![
                    row.issuer_did,
                    row.target_id,
                    row.param,
                    row.mono_secs,
                    row.value_mantissa,
                    row.exponent as i64,
                    row.unit_id as i64
                ],
            )
            .map_err(|e| format!("record drift: {e}"))?;
        Ok(())
    }

    /// Recent samples since `since_mono_secs` (legacy-compatible API).
    pub fn recent(
        &self,
        issuer_did: &str,
        target_id: &str,
        param: &str,
        since_mono_secs: i64,
    ) -> Result<Vec<DriftHistoryRow>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT issuer_did,target_id,param,mono_secs,value_mantissa,exponent,unit_id
                 FROM {DRIFT_RATE_HISTORY_TABLE}
                 WHERE issuer_did=?1 AND target_id=?2 AND param=?3 AND mono_secs>=?4
                 ORDER BY mono_secs ASC"
            ))
            .map_err(|e| format!("prepare drift: {e}"))?;
        let rows = stmt
            .query_map(
                params![issuer_did, target_id, param, since_mono_secs],
                |row| {
                    Ok(DriftHistoryRow {
                        issuer_did: row.get(0)?,
                        target_id: row.get(1)?,
                        param: row.get(2)?,
                        mono_secs: row.get(3)?,
                        value_mantissa: row.get(4)?,
                        exponent: row.get::<_, i64>(5)? as i8,
                        unit_id: row.get::<_, i64>(6)? as u16,
                    })
                },
            )
            .map_err(|e| format!("query drift: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect drift: {e}"))
    }

    pub fn load_summary(
        &self,
        target_id: &str,
        param: &str,
    ) -> Result<Option<DriftSummaryRow>, String> {
        let conn = self.lock();
        load_summary_conn(&conn, target_id, param)
    }

    pub fn prune_before(&self, mono_secs: i64) -> Result<usize, String> {
        self.lock()
            .execute(
                &format!("DELETE FROM {DRIFT_RATE_HISTORY_TABLE} WHERE mono_secs < ?1 AND issuer_did <> '__stage16__'"),
                params![mono_secs],
            )
            .map_err(|e| format!("prune drift: {e}"))
    }
}

impl tirbase_guard::admit::DriftHistoryStore for SqliteDriftRateHistoryStore {
    fn record(
        &self,
        issuer_did: &str,
        target_id: &str,
        param: &str,
        mono_secs: i64,
        value_mantissa: i64,
        exponent: i8,
        unit_id: u16,
    ) -> Result<(), String> {
        self.record(&DriftHistoryRow {
            issuer_did: issuer_did.to_string(),
            target_id: target_id.to_string(),
            param: param.to_string(),
            mono_secs,
            value_mantissa,
            exponent,
            unit_id,
        })
    }

    fn recent(
        &self,
        issuer_did: &str,
        target_id: &str,
        param: &str,
        since_mono_secs: i64,
    ) -> Result<Vec<tirbase_guard::admit::DriftRecord>, String> {
        let rows = self.recent(issuer_did, target_id, param, since_mono_secs)?;
        Ok(rows
            .into_iter()
            .map(|r| tirbase_guard::admit::DriftRecord {
                mono_secs: r.mono_secs,
                value_mantissa: r.value_mantissa,
                exponent: r.exponent,
                unit_id: r.unit_id,
            })
            .collect())
    }

    fn timing_summary(
        &self,
        target_id: &str,
        param: &str,
    ) -> Result<Option<tirbase_guard::admit::DriftTimingSummary>, String> {
        let row = self.load_summary(target_id, param)?;
        Ok(row.map(|r| tirbase_guard::admit::DriftTimingSummary {
            last_change_mono: Some(r.last_change_mono),
            last_deactivation_mono: r.last_deactivation_mono,
        }))
    }
}
