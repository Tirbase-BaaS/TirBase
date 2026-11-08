//! `pending_approvals` SQLite store (task 12.8 — CLAIM-12.8, PV-4.10).
//!
//! Stores partial multi-signature operations (policy loosening, lockdown-exit,
//! epoch bump, time-ratchet reset) until they reach quorum or are cancelled.
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS pending_approvals (
//!     op_id              TEXT PRIMARY KEY,
//!     op_type            TEXT NOT NULL,
//!     target             TEXT,
//!     payload_json       TEXT NOT NULL,
//!     required_m         INTEGER NOT NULL,
//!     required_n         INTEGER NOT NULL,
//!     timelock_until_est INTEGER,
//!     cancel_deadline_est INTEGER,
//!     created_est        INTEGER NOT NULL,
//!     status             TEXT NOT NULL
//! );
//! CREATE TABLE IF NOT EXISTS pending_approval_signatures (
//!     op_id      TEXT NOT NULL,
//!     signer_did TEXT NOT NULL,
//!     signature_json TEXT NOT NULL,
//!     role       TEXT,
//!     PRIMARY KEY (op_id, signer_did)
//! );
//! ```

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

pub const PENDING_APPROVALS_TABLE: &str = "pending_approvals";
pub const PENDING_APPROVAL_SIGNATURES_TABLE: &str = "pending_approval_signatures";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApprovalRow {
    pub op_id: String,
    pub op_type: String,
    pub target: Option<String>,
    pub payload_json: String,
    pub required_m: i64,
    pub required_n: i64,
    pub timelock_until_est: Option<i64>,
    pub cancel_deadline_est: Option<i64>,
    pub created_est: i64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignatureRow {
    pub op_id: String,
    pub signer_did: String,
    pub signature_json: String,
    pub role: Option<String>,
}

#[derive(Debug)]
pub struct SqlitePendingApprovalsStore {
    conn: Mutex<Connection>,
}

impl SqlitePendingApprovalsStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("synchronous: {e}"))?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {PENDING_APPROVALS_TABLE} (
                 op_id              TEXT PRIMARY KEY,
                 op_type            TEXT NOT NULL,
                 target             TEXT,
                 payload_json       TEXT NOT NULL,
                 required_m         INTEGER NOT NULL,
                 required_n         INTEGER NOT NULL,
                 timelock_until_est INTEGER,
                 cancel_deadline_est INTEGER,
                 created_est        INTEGER NOT NULL,
                 status             TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS {PENDING_APPROVAL_SIGNATURES_TABLE} (
                 op_id          TEXT NOT NULL,
                 signer_did     TEXT NOT NULL,
                 signature_json TEXT NOT NULL,
                 role           TEXT,
                 PRIMARY KEY (op_id, signer_did)
             );"
        ))
        .map_err(|e| format!("create pending_approvals: {e}"))?;
        Ok(SqlitePendingApprovalsStore {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn upsert(&self, row: &PendingApprovalRow) -> Result<(), String> {
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO {PENDING_APPROVALS_TABLE}
                 (op_id, op_type, target, payload_json, required_m, required_n,
                  timelock_until_est, cancel_deadline_est, created_est, status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(op_id) DO UPDATE SET
                  op_type=excluded.op_type, target=excluded.target,
                  payload_json=excluded.payload_json, required_m=excluded.required_m,
                  required_n=excluded.required_n, timelock_until_est=excluded.timelock_until_est,
                  cancel_deadline_est=excluded.cancel_deadline_est, status=excluded.status"
            ),
            params![
                row.op_id,
                row.op_type,
                row.target,
                row.payload_json,
                row.required_m,
                row.required_n,
                row.timelock_until_est,
                row.cancel_deadline_est,
                row.created_est,
                row.status
            ],
        )
        .map_err(|e| format!("upsert pending approval: {e}"))?;
        Ok(())
    }

    pub fn load(&self, op_id: &str) -> Result<Option<PendingApprovalRow>, String> {
        let conn = self.lock();
        conn.query_row(
            &format!(
                "SELECT op_id,op_type,target,payload_json,required_m,required_n,
                        timelock_until_est,cancel_deadline_est,created_est,status
                 FROM {PENDING_APPROVALS_TABLE} WHERE op_id=?1"
            ),
            params![op_id],
            |row| {
                Ok(PendingApprovalRow {
                    op_id: row.get(0)?,
                    op_type: row.get(1)?,
                    target: row.get(2)?,
                    payload_json: row.get(3)?,
                    required_m: row.get(4)?,
                    required_n: row.get(5)?,
                    timelock_until_est: row.get(6)?,
                    cancel_deadline_est: row.get(7)?,
                    created_est: row.get(8)?,
                    status: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("load pending approval: {e}"))
    }

    pub fn add_signature(&self, sig: &PendingSignatureRow) -> Result<bool, String> {
        let conn = self.lock();
        let changed = conn
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO {PENDING_APPROVAL_SIGNATURES_TABLE}
                     (op_id, signer_did, signature_json, role) VALUES (?1,?2,?3,?4)"
                ),
                params![sig.op_id, sig.signer_did, sig.signature_json, sig.role],
            )
            .map_err(|e| format!("add pending signature: {e}"))?;
        Ok(changed > 0)
    }

    pub fn list_signatures(&self, op_id: &str) -> Result<Vec<PendingSignatureRow>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT op_id,signer_did,signature_json,role
                 FROM {PENDING_APPROVAL_SIGNATURES_TABLE} WHERE op_id=?1 ORDER BY signer_did"
            ))
            .map_err(|e| format!("prepare signatures: {e}"))?;
        let rows = stmt
            .query_map(params![op_id], |row| {
                Ok(PendingSignatureRow {
                    op_id: row.get(0)?,
                    signer_did: row.get(1)?,
                    signature_json: row.get(2)?,
                    role: row.get(3)?,
                })
            })
            .map_err(|e| format!("list signatures: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("collect signatures: {e}"))
    }

    pub fn set_status(&self, op_id: &str, status: &str) -> Result<(), String> {
        let conn = self.lock();
        conn.execute(
            &format!("UPDATE {PENDING_APPROVALS_TABLE} SET status=?2 WHERE op_id=?1"),
            params![op_id, status],
        )
        .map_err(|e| format!("set status: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_db(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let u = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-pending-{tag}-{}-{u}.db",
            std::process::id()
        ))
    }

    #[test]
    fn pending_approval_accumulates_signatures() {
        let path = temp_db("accum");
        let store = SqlitePendingApprovalsStore::open(&path).expect("open");
        let row = PendingApprovalRow {
            op_id: "policy-loosen:v2".into(),
            op_type: "policy_loosening".into(),
            target: Some("cold_room#1".into()),
            payload_json: "{}".into(),
            required_m: 2,
            required_n: 3,
            timelock_until_est: Some(2_000),
            cancel_deadline_est: Some(2_300),
            created_est: 1_000,
            status: "pending".into(),
        };
        store.upsert(&row).unwrap();
        assert!(store
            .add_signature(&PendingSignatureRow {
                op_id: row.op_id.clone(),
                signer_did: "did:a".into(),
                signature_json: "{\"sig\":1}".into(),
                role: Some("PolicyAuthority".into()),
            })
            .unwrap());
        assert!(!store
            .add_signature(&PendingSignatureRow {
                op_id: row.op_id.clone(),
                signer_did: "did:a".into(),
                signature_json: "{\"sig\":1}".into(),
                role: Some("PolicyAuthority".into()),
            })
            .unwrap());
        assert_eq!(store.list_signatures(&row.op_id).unwrap().len(), 1);
        let loaded = store.load(&row.op_id).unwrap().unwrap();
        assert_eq!(loaded.required_m, 2);
        assert_eq!(loaded.op_type, "policy_loosening");
        let _ = std::fs::remove_file(&path);
    }
}
