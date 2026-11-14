// SPDX-License-Identifier: AGPL-3.0-only

//! `target_state` SQLite store (PV-4.5, CLAIM-21.12).
//!
//! Persists the last committed desired state `(target_id, param) -> FixedPointValue`
//! in `primary.db`. Stage 16 updates this atomically with the Actuating write.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use tirbase_types::fixed_point::FixedPointValue;

pub const TARGET_STATE_TABLE: &str = "target_state";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetStateRow {
    pub target_id: String,
    pub param: String,
    pub value_mantissa: i64,
    pub value_exponent: i8,
    pub value_unit_id: u16,
}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {TARGET_STATE_TABLE} (
             target_id       TEXT NOT NULL,
             param           TEXT NOT NULL,
             value_mantissa  INTEGER NOT NULL,
             value_exponent  INTEGER NOT NULL,
             value_unit_id   INTEGER NOT NULL,
             PRIMARY KEY (target_id, param)
         );"
    ))
    .map_err(|e| format!("create target_state: {e}"))
}

pub fn upsert_tx(
    tx: &Transaction<'_>,
    target_id: &str,
    param: &str,
    value: FixedPointValue,
) -> Result<(), String> {
    tirbase_core::fail_crate::fail_point!("fp_target_state_upsert", |_| Err(
        "failpoint fp_target_state_upsert".to_string()
    ));
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO {TARGET_STATE_TABLE}
             (target_id,param,value_mantissa,value_exponent,value_unit_id)
             VALUES (?1,?2,?3,?4,?5)"
        ),
        params![
            target_id,
            param,
            value.mantissa,
            value.exponent as i64,
            value.unit_id as i64
        ],
    )
    .map_err(|e| format!("upsert target_state: {e}"))?;
    Ok(())
}

pub fn load_all(conn: &Connection) -> Result<BTreeMap<(String, String), FixedPointValue>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT target_id,param,value_mantissa,value_exponent,value_unit_id FROM {TARGET_STATE_TABLE}"
        ))
        .map_err(|e| format!("prepare target_state: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                FixedPointValue {
                    mantissa: row.get(2)?,
                    exponent: row.get::<_, i64>(3)? as i8,
                    unit_id: row.get::<_, i64>(4)? as u16,
                },
            ))
        })
        .map_err(|e| format!("query target_state: {e}"))?;
    let mut out = BTreeMap::new();
    for r in rows {
        let (k, v) = r.map_err(|e| format!("read target_state: {e}"))?;
        out.insert(k, v);
    }
    Ok(out)
}

pub fn get(
    conn: &Connection,
    target_id: &str,
    param: &str,
) -> Result<Option<FixedPointValue>, String> {
    conn.query_row(
        &format!(
            "SELECT value_mantissa,value_exponent,value_unit_id FROM {TARGET_STATE_TABLE} WHERE target_id=?1 AND param=?2"
        ),
        params![target_id, param],
        |row| {
            Ok(FixedPointValue {
                mantissa: row.get(0)?,
                exponent: row.get::<_, i64>(1)? as i8,
                unit_id: row.get::<_, i64>(2)? as u16,
            })
        },
    )
    .optional()
    .map_err(|e| format!("get target_state: {e}"))
}

#[derive(Debug)]
pub struct SqliteTargetStateStore {
    conn: Mutex<Connection>,
}
impl SqliteTargetStateStore {
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
    pub fn load_all(&self) -> Result<BTreeMap<(String, String), FixedPointValue>, String> {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        load_all(&conn)
    }
}
