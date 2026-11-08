//! `drift_rate_history` SQLite store (PV-4.7, CLAIM-14.15, Stage 13).
//!
//! Records desired-state samples used for rate-of-change and cumulative drift
//! window checks.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

pub const DRIFT_RATE_HISTORY_TABLE: &str = "drift_rate_history";

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
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(|e| format!("synchronous: {e}"))?;
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
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() { Ok(g) => g, Err(p) => p.into_inner() }
    }

    pub fn record(&self, row: &DriftHistoryRow) -> Result<(), String> {
        self.lock()
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO {DRIFT_RATE_HISTORY_TABLE}
                     (issuer_did,target_id,param,mono_secs,value_mantissa,exponent,unit_id)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)"
                ),
                params![row.issuer_did, row.target_id, row.param, row.mono_secs, row.value_mantissa, row.exponent as i64, row.unit_id as i64],
            )
            .map_err(|e| format!("record drift: {e}"))?;
        Ok(())
    }

    pub fn recent(&self, issuer_did: &str, target_id: &str, param: &str, since_mono_secs: i64) -> Result<Vec<DriftHistoryRow>, String> {
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
            .query_map(params![issuer_did, target_id, param, since_mono_secs], |row| {
                Ok(DriftHistoryRow {
                    issuer_did: row.get(0)?,
                    target_id: row.get(1)?,
                    param: row.get(2)?,
                    mono_secs: row.get(3)?,
                    value_mantissa: row.get(4)?,
                    exponent: row.get::<_, i64>(5)? as i8,
                    unit_id: row.get::<_, i64>(6)? as u16,
                })
            })
            .map_err(|e| format!("query drift: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("collect drift: {e}"))
    }

    pub fn prune_before(&self, mono_secs: i64) -> Result<usize, String> {
        self.lock()
            .execute(&format!("DELETE FROM {DRIFT_RATE_HISTORY_TABLE} WHERE mono_secs < ?1"), params![mono_secs])
            .map_err(|e| format!("prune drift: {e}"))
    }
}
