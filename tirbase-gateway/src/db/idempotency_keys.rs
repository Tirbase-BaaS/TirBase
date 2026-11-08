//! `idempotency_keys` SQLite store (PV-5.6, CLAIM-15.1, INV-2).
//! Scoped to `(issuer_did, target_id, idempotency_key)`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

pub const IDEMPOTENCY_KEYS_TABLE: &str = "idempotency_keys";

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

pub fn insert_tx(tx: &Transaction<'_>, row: &IdempotencyRow) -> Result<(), String> {
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
