//! `idempotency_keys` SQLite store (PV-5.6, CLAIM-15.1/20.5, INV-2).
//! Scoped to `(issuer_did, target_id, idempotency_key)`.
//!
//! Retention is configurable (default 24h, valid 1 min–7 days). Expired rows
//! are ignored on lookup and may be pruned.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

pub const IDEMPOTENCY_KEYS_TABLE: &str = "idempotency_keys";
/// Default retention: 24 hours (PV-5.6).
pub const DEFAULT_IDEMPOTENCY_RETENTION_SECS: i64 = 24 * 60 * 60;
pub const MIN_IDEMPOTENCY_RETENTION_SECS: i64 = 60;
pub const MAX_IDEMPOTENCY_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

/// Clamp retention to the valid range [1 min, 7 days].
pub fn clamp_retention_secs(secs: i64) -> i64 {
    secs.clamp(
        MIN_IDEMPOTENCY_RETENTION_SECS,
        MAX_IDEMPOTENCY_RETENTION_SECS,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRow {
    pub issuer_did: String,
    pub target_id: String,
    pub idempotency_key: [u8; 16],
    pub original_result: String,
    pub recorded_at_est: i64,
    pub expires_at_est: i64,
}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {IDEMPOTENCY_KEYS_TABLE} (
            issuer_did       TEXT NOT NULL,
            target_id        TEXT NOT NULL,
            idempotency_key  BLOB NOT NULL,
            original_result  TEXT NOT NULL,
            recorded_at_est  INTEGER NOT NULL,
            expires_at_est   INTEGER NOT NULL,
            PRIMARY KEY (issuer_did, target_id, idempotency_key)
        );
        CREATE INDEX IF NOT EXISTS idx_idem_expiry ON {IDEMPOTENCY_KEYS_TABLE}(expires_at_est);"
    ))
    .map_err(|e| format!("create idempotency_keys: {e}"))
}

pub fn lookup_tx(
    tx: &Transaction<'_>,
    issuer_did: &str,
    target_id: &str,
    idempotency_key: &[u8; 16],
    now_est: i64,
) -> Result<Option<IdempotencyRow>, String> {
    tx.query_row(
        &format!("SELECT issuer_did,target_id,idempotency_key,original_result,recorded_at_est,expires_at_est FROM {IDEMPOTENCY_KEYS_TABLE} WHERE issuer_did=?1 AND target_id=?2 AND idempotency_key=?3"),
        params![issuer_did, target_id, idempotency_key.as_slice()],
        |row| {
            let blob: Vec<u8> = row.get(2)?;
            let mut key = [0u8; 16];
            if blob.len() == 16 { key.copy_from_slice(&blob); }
            Ok(IdempotencyRow {
                issuer_did: row.get(0)?,
                target_id: row.get(1)?,
                idempotency_key: key,
                original_result: row.get(3)?,
                recorded_at_est: row.get(4)?,
                expires_at_est: row.get(5)?,
            })
        },
    ).optional().map_err(|e| format!("lookup idempotency_key: {e}")).map(|opt| opt.filter(|r| r.expires_at_est >= now_est))
}

/// Prune expired idempotency keys (background/maintenance). Returns rows deleted.
pub fn prune_expired_tx(tx: &Transaction<'_>, now_est: i64) -> Result<usize, String> {
    tx.execute(
        &format!("DELETE FROM {IDEMPOTENCY_KEYS_TABLE} WHERE expires_at_est < ?1"),
        params![now_est],
    )
    .map_err(|e| format!("prune idempotency_keys: {e}"))
}

pub fn insert_tx(tx: &Transaction<'_>, row: &IdempotencyRow) -> Result<(), String> {
    tirbase_core::fail_crate::fail_point!("fp_idempotency_insert", |_| Err(
        "failpoint fp_idempotency_insert".to_string()
    ));
    tx.execute(
        &format!("INSERT INTO {IDEMPOTENCY_KEYS_TABLE} (issuer_did,target_id,idempotency_key,original_result,recorded_at_est,expires_at_est) VALUES (?1,?2,?3,?4,?5,?6)"),
        params![row.issuer_did, row.target_id, row.idempotency_key.as_slice(), row.original_result, row.recorded_at_est, row.expires_at_est],
    ).map_err(|e| format!("insert idempotency_key: {e}"))?;
    Ok(())
}

#[derive(Debug)]
pub struct SqliteIdempotencyStore {
    conn: Mutex<Connection>,
}
impl SqliteIdempotencyStore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn clamp_retention_bounds() {
        assert_eq!(clamp_retention_secs(10), MIN_IDEMPOTENCY_RETENTION_SECS);
        assert_eq!(
            clamp_retention_secs(MAX_IDEMPOTENCY_RETENTION_SECS + 1),
            MAX_IDEMPOTENCY_RETENTION_SECS
        );
        assert_eq!(clamp_retention_secs(3600), 3600);
    }
}
