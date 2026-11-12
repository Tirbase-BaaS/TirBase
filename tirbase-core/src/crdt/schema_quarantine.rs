//! Schema_Quarantine_Ledger — replayable structural-anomaly quarantine in a
//! SQLite table (PV-6.7, CLAIM-23.3, CLAIM-23.5).
//!
//! The canonical table name is `schema_quarantine` (compatible with gateway
//! `derived.db` migrations). Core opens/creates the table in the provided
//! SQLite database path (CoreHandle uses a derived sibling DB by default).
//!
//! Replayable reason codes (PV-6.7): CLOCK_JUMP, MISSING_DEPENDENCY_TIMEOUT,
//! PENDING_QUEUE_OVERFLOW, OP_COUNT_EXCEEDED, TRAVERSAL_BUDGET_EXCEEDED,
//! BATCH_EXCEEDED, HEAD_COUNT_EXCEEDED, DEP_COUNT_EXCEEDED.
//!
//! Manual replay requires a PolicyAuthority signature (enforced by the replay
//! API path; this module records `replay_status`/`replay_ts`).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::crdt::delta::{Delta, Did};
use crate::errors::TirBaseError;
use crate::events::{emit_crdt, ReasonCode, Severity};

pub const SCHEMA_QUARANTINE_PER_SENDER_LIMIT: usize = 1_000;
pub const SCHEMA_QUARANTINE_GLOBAL_ENTRIES: usize = 50_000;
pub const SCHEMA_QUARANTINE_GLOBAL_BYTES: usize = 256 * 1024 * 1024;

/// Replayable structural-anomaly reason codes for `Schema_Quarantine_Ledger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaQuarantineReason {
    ClockJump,
    MissingDependencyTimeout,
    PendingQueueOverflow,
    OpCountExceeded,
    TraversalBudgetExceeded,
    BatchExceeded,
    HeadCountExceeded,
    DepCountExceeded,
}

impl SchemaQuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClockJump => "CLOCK_JUMP",
            Self::MissingDependencyTimeout => "MISSING_DEPENDENCY_TIMEOUT",
            Self::PendingQueueOverflow => "PENDING_QUEUE_OVERFLOW",
            Self::OpCountExceeded => "OP_COUNT_EXCEEDED",
            Self::TraversalBudgetExceeded => "TRAVERSAL_BUDGET_EXCEEDED",
            Self::BatchExceeded => "BATCH_EXCEEDED",
            Self::HeadCountExceeded => "HEAD_COUNT_EXCEEDED",
            Self::DepCountExceeded => "DEP_COUNT_EXCEEDED",
        }
    }

    pub fn reason_code(self) -> ReasonCode {
        match self {
            Self::ClockJump => ReasonCode::ClockJump,
            Self::MissingDependencyTimeout => ReasonCode::MissingDependencyTimeout,
            Self::PendingQueueOverflow => ReasonCode::PendingQueueOverflow,
            Self::OpCountExceeded => ReasonCode::OpCountExceeded,
            Self::TraversalBudgetExceeded => ReasonCode::TraversalBudgetExceeded,
            Self::BatchExceeded => ReasonCode::BatchExceeded,
            Self::HeadCountExceeded => ReasonCode::HeadCountExceeded,
            Self::DepCountExceeded => ReasonCode::DepCountExceeded,
        }
    }

    pub fn from_reason_code(code: ReasonCode) -> Option<Self> {
        match code {
            ReasonCode::ClockJump => Some(Self::ClockJump),
            ReasonCode::MissingDependencyTimeout => Some(Self::MissingDependencyTimeout),
            ReasonCode::PendingQueueOverflow => Some(Self::PendingQueueOverflow),
            ReasonCode::OpCountExceeded => Some(Self::OpCountExceeded),
            ReasonCode::TraversalBudgetExceeded => Some(Self::TraversalBudgetExceeded),
            ReasonCode::BatchExceeded => Some(Self::BatchExceeded),
            ReasonCode::HeadCountExceeded => Some(Self::HeadCountExceeded),
            ReasonCode::DepCountExceeded => Some(Self::DepCountExceeded),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaQuarantineRecord {
    pub id: [u8; 32],
    pub sender_did: String,
    pub raw_bytes: Vec<u8>,
    pub reason: String,
    pub received_at: i64,
    pub replay_status: Option<String>,
    pub replay_ts: Option<i64>,
}

/// SQLite-backed schema quarantine ledger with per-sender FIFO eviction and
/// global limits (PV-6.7, CLAIM-23.5).
#[derive(Debug)]
pub struct SchemaQuarantineLedger {
    conn: Connection,
    per_sender_limit: usize,
    global_entries: usize,
    global_bytes: usize,
}

impl SchemaQuarantineLedger {
 /// Open (or create) the ledger at `path`, creating the `schema_quarantine`
 /// table if missing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let conn = Connection::open(path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("open schema_quarantine db: {e}"),
        })?;
        Self::init(conn)
    }

 /// Wrap an existing connection (caller ensures table exists / WAL pragmas).
    pub fn from_connection(conn: Connection) -> Result<Self, TirBaseError> {
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, TirBaseError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_quarantine (
                id           BLOB PRIMARY KEY,
                sender_did   TEXT NOT NULL,
                raw_bytes    BLOB NOT NULL,
                reason       TEXT NOT NULL,
                received_at  INTEGER NOT NULL,
                migration_id BLOB,
                replay_status TEXT,
                replay_ts    INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_sq_sender ON schema_quarantine(sender_did, received_at);
            "#,
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("create schema_quarantine table: {e}"),
        })?;
        Ok(Self {
            conn,
            per_sender_limit: SCHEMA_QUARANTINE_PER_SENDER_LIMIT,
            global_entries: SCHEMA_QUARANTINE_GLOBAL_ENTRIES,
            global_bytes: SCHEMA_QUARANTINE_GLOBAL_BYTES,
        })
    }

    #[cfg(test)]
    pub fn with_limits(
        mut self,
        per_sender_limit: usize,
        global_entries: usize,
        global_bytes: usize,
    ) -> Self {
        self.per_sender_limit = per_sender_limit.max(1);
        self.global_entries = global_entries.max(1);
        self.global_bytes = global_bytes.max(1);
        self
    }

    fn now_micros() -> i64 {
 // Untrusted wall-clock hint, read through the injected TimeSource (PV-3.12).
        crate::traits::wall_hint().unwrap_or(0)
    }

    fn delta_raw_bytes(delta: &Delta) -> Vec<u8> {
        serde_json::to_vec(delta).unwrap_or_else(|_| delta.automerge_bytes.clone())
    }

 /// Record an anomalous delta with a replayable structural reason code
 /// (CLAIM-23.3). Emits a `CrdtHardening` security event and enforces
 /// per-sender/global quotas (CLAIM-23.5).
    pub fn quarantine_delta(
        &mut self,
        delta: &Delta,
        reason: SchemaQuarantineReason,
        detail: &str,
    ) -> Result<[u8; 32], TirBaseError> {
        let raw = Self::delta_raw_bytes(delta);
        let received_at = Self::now_micros();
        let id = self.insert_raw(&delta.author_did, &raw, reason.as_str(), received_at)?;
        emit_crdt(
            Severity::High,
            reason.reason_code(),
            Some(hex::encode(id)),
            format!(
                "schema_quarantine reason={} sender={} delta={} detail={}",
                reason.as_str(),
                delta.author_did,
                hex::encode(delta.id),
                detail
            ),
        );
        Ok(id)
    }

 /// Insert raw bytes (used for overflow/timeout evictions from pending queue).
    pub fn quarantine_raw(
        &mut self,
        sender_did: &str,
        raw_bytes: &[u8],
        reason: SchemaQuarantineReason,
        received_at_micros: i64,
        detail: &str,
    ) -> Result<[u8; 32], TirBaseError> {
        let id = self.insert_raw(sender_did, raw_bytes, reason.as_str(), received_at_micros)?;
        emit_crdt(
            Severity::High,
            reason.reason_code(),
            Some(hex::encode(id)),
            format!(
                "schema_quarantine reason={} sender={} detail={}",
                reason.as_str(),
                sender_did,
                detail
            ),
        );
        Ok(id)
    }

    fn insert_raw(
        &mut self,
        sender_did: &str,
        raw_bytes: &[u8],
        reason: &str,
        received_at: i64,
    ) -> Result<[u8; 32], TirBaseError> {
        let id: [u8; 32] = Sha256::digest(raw_bytes).into();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("schema_quarantine transaction: {e}"),
            })?;

 // Per-sender FIFO eviction (oldest by received_at, then id).
        let sender_count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM schema_quarantine WHERE sender_did = ?1",
                params![sender_did],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if sender_count as usize >= self.per_sender_limit {
            let to_delete = (sender_count as usize)
                .saturating_sub(self.per_sender_limit)
                .saturating_add(1);
            tx.execute(
                "DELETE FROM schema_quarantine WHERE id IN (
                   SELECT id FROM schema_quarantine WHERE sender_did = ?1
                   ORDER BY received_at ASC, id ASC LIMIT ?2
                 )",
                params![sender_did, to_delete as i64],
            )
            .ok();
        }

 // Global entry/byte caps (oldest-first FIFO across all senders).
        Self::enforce_global_caps_tx(&tx, raw_bytes.len(), self.global_entries, self.global_bytes)?;

        tx.execute(
            "INSERT OR REPLACE INTO schema_quarantine
             (id, sender_did, raw_bytes, reason, received_at, migration_id, replay_status, replay_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL)",
            params![&id[..], sender_did, raw_bytes, reason, received_at],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("insert schema_quarantine: {e}"),
        })?;
        tx.commit()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("commit schema_quarantine: {e}"),
            })?;
        Ok(id)
    }

    fn enforce_global_caps_tx(
        tx: &rusqlite::Transaction<'_>,
        incoming_bytes: usize,
        global_entries: usize,
        global_bytes: usize,
    ) -> Result<(), TirBaseError> {
        loop {
            let (count, bytes): (i64, i64) = tx
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(raw_bytes)), 0) FROM schema_quarantine",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or((0, 0));
            let over_entries = count as usize >= global_entries;
            let over_bytes = (bytes as usize).saturating_add(incoming_bytes) > global_bytes;
            if !over_entries && !over_bytes {
                break;
            }
            let deleted = tx
                .execute(
                    "DELETE FROM schema_quarantine WHERE id IN (
                       SELECT id FROM schema_quarantine ORDER BY received_at ASC, id ASC LIMIT 1
                     )",
                    [],
                )
                .unwrap_or(0);
            if deleted == 0 {
                break;
            }
        }
        Ok(())
    }

    pub fn count(&self) -> Result<usize, TirBaseError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM schema_quarantine", [], |r| r.get(0))
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("count schema_quarantine: {e}"),
            })?;
        Ok(n as usize)
    }

    pub fn count_for_sender(&self, sender_did: &str) -> Result<usize, TirBaseError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM schema_quarantine WHERE sender_did = ?1",
                params![sender_did],
                |r| r.get(0),
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("count schema_quarantine sender: {e}"),
            })?;
        Ok(n as usize)
    }

    pub fn entries(&self) -> Result<Vec<SchemaQuarantineRecord>, TirBaseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, sender_did, raw_bytes, reason, received_at, replay_status, replay_ts
                 FROM schema_quarantine ORDER BY received_at ASC, id ASC",
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("list schema_quarantine: {e}"),
            })?;
        let rows = stmt
            .query_map([], |row| {
                let id_blob: Vec<u8> = row.get(0)?;
                let mut id = [0u8; 32];
                if id_blob.len() == 32 {
                    id.copy_from_slice(&id_blob);
                }
                Ok(SchemaQuarantineRecord {
                    id,
                    sender_did: row.get(1)?,
                    raw_bytes: row.get(2)?,
                    reason: row.get(3)?,
                    received_at: row.get(4)?,
                    replay_status: row.get(5)?,
                    replay_ts: row.get(6)?,
                })
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("iter schema_quarantine: {e}"),
            })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("read schema_quarantine row: {e}"),
            })?);
        }
        Ok(out)
    }

    pub fn has_sender(&self, sender_did: &str) -> Result<bool, TirBaseError> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM schema_quarantine WHERE sender_did = ?1 LIMIT 1",
                params![sender_did],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("has_sender schema_quarantine: {e}"),
            })?;
        Ok(v.is_some())
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};

    fn mk_delta(author: &str, n: u8) -> Delta {
        let mut id = [0u8; 32];
        id[0] = n;
        Delta {
            id,
            author_did: author.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![n; 16],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        }
    }

    #[test]
    fn per_sender_quota_evicts_only_that_sender() {
        let mut l = SchemaQuarantineLedger::open(":memory:")
            .unwrap()
            .with_limits(2, 100, 1024 * 1024);
        l.quarantine_delta(
            &mk_delta("did:a", 1),
            SchemaQuarantineReason::ClockJump,
            "t",
        )
        .unwrap();
        l.quarantine_delta(
            &mk_delta("did:b", 2),
            SchemaQuarantineReason::ClockJump,
            "t",
        )
        .unwrap();
        l.quarantine_delta(
            &mk_delta("did:a", 3),
            SchemaQuarantineReason::ClockJump,
            "t",
        )
        .unwrap();
        l.quarantine_delta(
            &mk_delta("did:a", 4),
            SchemaQuarantineReason::ClockJump,
            "t",
        )
        .unwrap();
        assert!(l.count_for_sender("did:a").unwrap() <= 2);
        assert_eq!(l.count_for_sender("did:b").unwrap(), 1);
    }
}
