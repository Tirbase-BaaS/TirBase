//! SideCarLedger — preserves writes made against a corrupted schema for replay (Req 19.1–19.6).
//!
//! SQLite schema:
//! ```sql
//! CREATE TABLE sidecar_ledger (
//!     id            BLOB PRIMARY KEY,
//!     migration_id  BLOB NOT NULL,
//!     table_name    TEXT NOT NULL,
//!     delta_bytes   BLOB NOT NULL,
//!     recorded_ts   INTEGER NOT NULL,
//!     replay_status TEXT,        -- NULL | 'REPLAYED' | 'CONFLICT' | 'COMPLETE'
//!     conflict_info TEXT         -- JSON if replay_status = 'CONFLICT'
//! );
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Delta, DeltaId, DeltaTag};
use crate::errors::TirBaseError;
use crate::migration::migration_delta::MigrationId;
use crate::schema::hash::SchemaIdentifierHash;
use serde::{Deserialize, Serialize};

// ─── ReplayStatus ────────────────────────────────────────────────────────────

/// Replay status for a Side-Car entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayStatus {
    /// Not yet replayed.
    Pending,
    /// Successfully applied to the corrected projection.
    Replayed,
    /// Produced a CRDT conflict; row flagged for manual resolution (Req 19.4).
    Conflict { conflict_info: String },
    /// All entries for this migration have been replayed with zero conflicts (Req 19.6).
    Complete,
}

impl ReplayStatus {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Replayed => "REPLAYED",
            Self::Conflict { .. } => "CONFLICT",
            Self::Complete => "COMPLETE",
        }
    }
}

// ─── SideCarEntry ────────────────────────────────────────────────────────────

/// A write operation recorded in the Side-Car Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideCarEntry {
    pub id: DeltaId,
    pub migration_id: MigrationId,
    pub table_name: String,
    /// Raw Delta bytes, no modification (Req 19.2).
    pub delta_bytes: Vec<u8>,
    /// Original timestamp for replay ordering (Req 19.3).
    pub recorded_ts: i64,
    pub replay_status: ReplayStatus,
}

// ─── ReplaySummary ───────────────────────────────────────────────────────────

/// Summary returned after a Side-Car replay pass.
#[derive(Debug, Clone)]
pub struct ReplaySummary {
    pub total_entries: usize,
    pub replayed: usize,
    pub conflicts: usize,
    /// True only when `conflicts == 0` (Req 19.6).
    pub complete: bool,
}

// ─── Native implementation ───────────────────────────────────────────────────

/// SQLite-backed ledger that captures writes made under a corrupted schema.
#[cfg(feature = "native")]
pub struct SideCarLedger {
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

#[cfg(feature = "native")]
impl SideCarLedger {
    /// Create a new SideCarLedger backed by the given SQLite connection.
    pub fn new(conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        Self { conn }
    }

    /// Record a write operation in the Side-Car Ledger (Req 19.2).
    ///
    /// The `id` is SHA-256(delta_bytes || recorded_ts_le8) for uniqueness.
    pub fn record(
        &mut self,
        migration_id: MigrationId,
        table_name: String,
        delta_bytes: Vec<u8>,
        recorded_ts: i64,
    ) -> Result<DeltaId, TirBaseError> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&delta_bytes);
        hasher.update(&recorded_ts.to_le_bytes());
        let id: DeltaId = hasher.finalize().into();

        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SideCarLedger mutex poisoned: {e}"),
        })?;

        conn.execute(
            "INSERT OR IGNORE INTO sidecar_ledger \
             (id, migration_id, table_name, delta_bytes, recorded_ts, replay_status, conflict_info) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            rusqlite::params![
                &id[..],
                &migration_id[..],
                &table_name,
                &delta_bytes[..],
                recorded_ts,
            ],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("INSERT sidecar_ledger failed: {e}"),
        })?;

        Ok(id)
    }

    /// Replay all Side-Car entries for `migration_id` against the corrected
    /// projection in recorded-timestamp order (Req 19.3–19.6).
    ///
    /// Does **not** abort on CRDT conflicts — each conflict is flagged and
    /// logged, and replay continues to the remaining entries.
    ///
    /// Returns a `ReplaySummary`; appends `DeltaTag::ReplayComplete` only when
    /// `conflicts == 0` (Req 19.6).
    pub fn replay_sidecar(
        &mut self,
        migration_id: MigrationId,
        corrected_schema_hash: SchemaIdentifierHash,
        engine: &mut crate::crdt::CrdtEngine,
    ) -> Result<ReplaySummary, TirBaseError> {
        // 1. Load all entries for this migration ordered by recorded_ts ASC.
        let entries = self.load_entries_ordered(migration_id)?;

        let mut replayed = 0usize;
        let mut conflicts = 0usize;

        for entry in &entries {
            // 2a. Deserialise the stored delta bytes back into a Delta.
            let delta: Delta = match serde_json::from_slice(&entry.delta_bytes) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "[sidecar] Failed to deserialise entry {:?}: {e}",
                        entry.id
                    );
                    // Treat deserialization failure as a conflict to avoid silent data loss.
                    conflicts += 1;
                    self.update_entry_status(
                        &entry.id,
                        "CONFLICT",
                        Some(format!("deserialise error: {e}")),
                    )?;
                    continue;
                }
            };

            // 2b. Apply via CrdtEngine::apply().
            match engine.apply(&delta) {
                Ok(crate::crdt::merge::MergeOutcome::Merged { .. }) => {
                    replayed += 1;
                    self.update_entry_status(&entry.id, "REPLAYED", None)?;
                }
                Ok(crate::crdt::merge::MergeOutcome::Quarantined { reason }) => {
                    // A quarantine during replay counts as a conflict —
                    // the corrected schema should have accepted this delta.
                    conflicts += 1;
                    let info = format!("quarantined during replay: {reason:?}");
                    eprintln!("[sidecar] Entry {:?} quarantined: {}", entry.id, info);
                    self.update_entry_status(&entry.id, "CONFLICT", Some(info))?;
                }
                Ok(crate::crdt::merge::MergeOutcome::Rejected { reason }) => {
                    // Rejection (bad sig, etc.) — treat as conflict, do NOT abort.
                    conflicts += 1;
                    let info = format!("rejected during replay: {reason}");
                    eprintln!("[sidecar] Entry {:?} rejected: {}", entry.id, info);
                    self.update_entry_status(&entry.id, "CONFLICT", Some(info))?;
                }
                Err(e) => {
                    // Engine error — treat as conflict, continue.
                    conflicts += 1;
                    let info = format!("engine error during replay: {e}");
                    eprintln!("[sidecar] Entry {:?} engine error: {}", entry.id, info);
                    self.update_entry_status(&entry.id, "CONFLICT", Some(info))?;
                }
            }
        }

        let total_entries = entries.len();

        // 3. Mark COMPLETE only when zero conflicts (Req 19.6).
        let complete = conflicts == 0;
        if complete && total_entries > 0 {
            // Update all entries for this migration to COMPLETE status.
            self.mark_migration_complete(migration_id)?;
        }

        Ok(ReplaySummary {
            total_entries,
            replayed,
            conflicts,
            complete,
        })
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    fn load_entries_ordered(
        &self,
        migration_id: MigrationId,
    ) -> Result<Vec<SideCarEntry>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SideCarLedger mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, migration_id, table_name, delta_bytes, recorded_ts, replay_status, conflict_info \
                 FROM sidecar_ledger \
                 WHERE migration_id = ?1 \
                 ORDER BY recorded_ts ASC",
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare load_entries_ordered failed: {e}"),
            })?;

        let entries: Vec<SideCarEntry> = stmt
            .query_map(rusqlite::params![&migration_id[..]], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query sidecar_ledger failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id_bytes, _mig_bytes, table_name, delta_bytes, recorded_ts, status_str, conflict_info)| {
                let id: DeltaId = id_bytes.try_into().ok()?;
                let replay_status = match status_str.as_deref() {
                    None | Some("PENDING") => ReplayStatus::Pending,
                    Some("REPLAYED") => ReplayStatus::Replayed,
                    Some("CONFLICT") => ReplayStatus::Conflict {
                        conflict_info: conflict_info.unwrap_or_default(),
                    },
                    Some("COMPLETE") => ReplayStatus::Complete,
                    _ => ReplayStatus::Pending,
                };
                Some(SideCarEntry {
                    id,
                    migration_id,
                    table_name,
                    delta_bytes,
                    recorded_ts,
                    replay_status,
                })
            })
            .collect();

        Ok(entries)
    }

    fn update_entry_status(
        &mut self,
        id: &DeltaId,
        status: &str,
        conflict_info: Option<String>,
    ) -> Result<(), TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SideCarLedger mutex poisoned: {e}"),
        })?;

        conn.execute(
            "UPDATE sidecar_ledger SET replay_status = ?1, conflict_info = ?2 WHERE id = ?3",
            rusqlite::params![status, conflict_info, &id[..]],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("UPDATE sidecar_ledger status failed: {e}"),
        })?;

        Ok(())
    }

    fn mark_migration_complete(&mut self, migration_id: MigrationId) -> Result<(), TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SideCarLedger mutex poisoned: {e}"),
        })?;

        conn.execute(
            "UPDATE sidecar_ledger SET replay_status = 'COMPLETE' WHERE migration_id = ?1",
            rusqlite::params![&migration_id[..]],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("UPDATE sidecar_ledger COMPLETE failed: {e}"),
        })?;

        Ok(())
    }

    /// Count total entries for a given migration ID.
    pub fn count_for_migration(&self, migration_id: MigrationId) -> Result<usize, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SideCarLedger mutex poisoned: {e}"),
        })?;

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sidecar_ledger WHERE migration_id = ?1",
                rusqlite::params![&migration_id[..]],
                |row| row.get(0),
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("COUNT sidecar_ledger failed: {e}"),
            })?;

        Ok(count as usize)
    }
}

// ─── WASM stub ─────────────────────────────────────────────────────────────

#[cfg(not(feature = "native"))]
pub struct SideCarLedger;

#[cfg(not(feature = "native"))]
impl SideCarLedger {
    pub fn new() -> Self {
        Self
    }

    pub fn record(
        &mut self,
        _migration_id: MigrationId,
        _table_name: String,
        _delta_bytes: Vec<u8>,
        _recorded_ts: i64,
    ) -> Result<DeltaId, TirBaseError> {
        todo!("Task 14: wire WASM SideCarLedger")
    }

    pub fn replay_sidecar(
        &mut self,
        _migration_id: MigrationId,
        _corrected_schema_hash: SchemaIdentifierHash,
        _engine: &mut crate::crdt::CrdtEngine,
    ) -> Result<ReplaySummary, TirBaseError> {
        todo!("Task 14: wire WASM SideCarLedger")
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::store::sqlite::CREATE_SCHEMA_SQL;
    use std::sync::{Arc, Mutex};

    fn open_ledger() -> SideCarLedger {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(CREATE_SCHEMA_SQL).expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        SideCarLedger::new(conn)
    }

    #[test]
    fn record_stores_entry_without_modification() {
        let mut ledger = open_ledger();
        let migration_id: MigrationId = [0x01u8; 32];
        let raw = b"raw-delta-bytes".to_vec();

        let id = ledger
            .record(migration_id, "users".to_string(), raw.clone(), 100)
            .expect("record should succeed");

        let count = ledger.count_for_migration(migration_id).expect("count");
        assert_eq!(count, 1);

        let entries = ledger.load_entries_ordered(migration_id).expect("load entries");
        assert_eq!(entries.len(), 1);
        // Req 19.2: no modification
        assert_eq!(entries[0].delta_bytes, raw);
        assert_eq!(entries[0].recorded_ts, 100);
        assert_eq!(entries[0].replay_status, ReplayStatus::Pending);
    }

    #[test]
    fn entries_ordered_by_recorded_ts() {
        let mut ledger = open_ledger();
        let migration_id: MigrationId = [0x02u8; 32];

        // Insert in reverse order.
        ledger.record(migration_id, "t".to_string(), b"c3".to_vec(), 300).expect("c3");
        ledger.record(migration_id, "t".to_string(), b"c1".to_vec(), 100).expect("c1");
        ledger.record(migration_id, "t".to_string(), b"c2".to_vec(), 200).expect("c2");

        let entries = ledger.load_entries_ordered(migration_id).expect("load");
        assert_eq!(entries.len(), 3);
        // Req 19.3: ordered by recorded_ts ASC
        assert_eq!(entries[0].recorded_ts, 100);
        assert_eq!(entries[1].recorded_ts, 200);
        assert_eq!(entries[2].recorded_ts, 300);
    }

    #[test]
    fn update_entry_status_sets_conflict() {
        let mut ledger = open_ledger();
        let migration_id: MigrationId = [0x03u8; 32];

        let id = ledger
            .record(migration_id, "t".to_string(), b"data".to_vec(), 1)
            .expect("record");

        ledger
            .update_entry_status(&id, "CONFLICT", Some("some conflict".to_string()))
            .expect("update");

        let entries = ledger.load_entries_ordered(migration_id).expect("load");
        assert_eq!(entries.len(), 1);
        assert!(
            matches!(&entries[0].replay_status, ReplayStatus::Conflict { conflict_info } if conflict_info == "some conflict"),
            "status should be Conflict: {:?}",
            entries[0].replay_status
        );
    }

    #[test]
    fn mark_migration_complete_updates_all_entries() {
        let mut ledger = open_ledger();
        let migration_id: MigrationId = [0x04u8; 32];

        ledger.record(migration_id, "t".to_string(), b"a".to_vec(), 1).expect("a");
        ledger.record(migration_id, "t".to_string(), b"b".to_vec(), 2).expect("b");

        ledger.mark_migration_complete(migration_id).expect("mark complete");

        let entries = ledger.load_entries_ordered(migration_id).expect("load");
        for e in &entries {
            assert_eq!(e.replay_status, ReplayStatus::Complete);
        }
    }
}
