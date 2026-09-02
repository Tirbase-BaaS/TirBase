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
    /// Returns a `ReplaySummary`; appends `DeltaTag::ReplayComplete` to every
    /// successfully-replayed Delta only when `conflicts == 0` (Req 19.6).
    pub fn replay_sidecar(
        &mut self,
        migration_id: MigrationId,
        corrected_schema_hash: SchemaIdentifierHash,
        engine: &mut crate::crdt::CrdtEngine,
    ) -> Result<ReplaySummary, TirBaseError> {
        use crate::contamination::taint::append_tag_to_db;

        // 1. Load all entries for this migration ordered by recorded_ts ASC.
        let entries = self.load_entries_ordered(migration_id)?;

        let mut replayed = 0usize;
        let mut conflicts = 0usize;
        // Track the original Delta IDs of entries that were successfully replayed.
        // We use the embedded Delta.id (not the sidecar entry id) so we can
        // append DeltaTag::ReplayComplete to the matching dag_nodes row.
        let mut replayed_delta_ids: Vec<DeltaId> = Vec::new();

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

            // Capture the Delta ID before moving delta into apply().
            let delta_id = delta.id;

            // 2b. Apply via CrdtEngine::apply().
            match engine.apply(&delta) {
                Ok(crate::crdt::merge::MergeOutcome::Merged { .. }) => {
                    replayed += 1;
                    replayed_delta_ids.push(delta_id);
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

        // 3. Mark COMPLETE only when zero conflicts AND at least one entry was
        // processed (Req 19.6).  An empty ledger is not "complete" — nothing
        // was replayed.
        let complete = conflicts == 0 && total_entries > 0;
        if complete && total_entries > 0 {
            // Update all entries for this migration to COMPLETE status in SQLite.
            self.mark_migration_complete(migration_id)?;

            // Append DeltaTag::ReplayComplete to every successfully-replayed Delta
            // in dag_nodes (Req 19.6, design.md §replay algorithm step 3).
            // This is the canonical append-only tag path — tags are never removed.
            let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("SideCarLedger mutex poisoned appending ReplayComplete: {e}"),
            })?;
            for delta_id in &replayed_delta_ids {
                // Best-effort: the delta may have been compacted from dag_nodes
                // (dag_nodes.compacted = 1).  We attempt the append and silently
                // continue if the row is absent — a missing row simply means the
                // tag store has no record to update, which is acceptable.
                let tag = DeltaTag::ReplayComplete { migration_id };
                if let Err(e) = append_tag_to_db(&conn, delta_id, tag) {
                    eprintln!(
                        "[sidecar] Could not append ReplayComplete to delta {:?}: {e}",
                        delta_id
                    );
                }
            }
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
pub struct SideCarLedger {
    entries: Vec<SideCarEntry>,
}

#[cfg(not(feature = "native"))]
impl SideCarLedger {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
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

        // INSERT OR IGNORE semantics.
        if !self.entries.iter().any(|e| e.id == id) {
            self.entries.push(SideCarEntry {
                id,
                migration_id,
                table_name,
                delta_bytes,
                recorded_ts,
                replay_status: ReplayStatus::Pending,
            });
        }
        Ok(id)
    }

    /// Replay all Side-Car entries for `migration_id` against the corrected
    /// projection in recorded-timestamp order (Req 19.3–19.6).
    ///
    /// Does **not** abort on CRDT conflicts — each conflict is flagged and
    /// replay continues to the remaining entries.
    ///
    /// Returns a `ReplaySummary`; appends `DeltaTag::ReplayComplete` to every
    /// successfully-replayed Delta only when `conflicts == 0` (Req 19.6).
    pub fn replay_sidecar(
        &mut self,
        migration_id: MigrationId,
        _corrected_schema_hash: SchemaIdentifierHash,
        engine: &mut crate::crdt::CrdtEngine,
    ) -> Result<ReplaySummary, TirBaseError> {
        use crate::contamination::taint::append_tag;

        // Sort entries by recorded_ts ASC.
        let mut entries: Vec<SideCarEntry> = self
            .entries
            .iter()
            .filter(|e| e.migration_id == migration_id)
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.recorded_ts);

        let total_entries = entries.len();
        let mut replayed = 0usize;
        let mut conflicts = 0usize;
        // Track delta IDs of successfully-replayed entries for tag appending.
        let mut replayed_delta_ids: Vec<DeltaId> = Vec::new();

        for entry in &entries {
            let delta: crate::crdt::delta::Delta = match serde_json::from_slice(&entry.delta_bytes) {
                Ok(d) => d,
                Err(e) => {
                    conflicts += 1;
                    self.update_entry_status(&entry.id, ReplayStatus::Conflict {
                        conflict_info: format!("deserialise error: {e}"),
                    });
                    continue;
                }
            };

            let delta_id = delta.id;

            match engine.apply(&delta) {
                Ok(crate::crdt::merge::MergeOutcome::Merged { .. }) => {
                    replayed += 1;
                    replayed_delta_ids.push(delta_id);
                    self.update_entry_status(&entry.id, ReplayStatus::Replayed);
                }
                Ok(crate::crdt::merge::MergeOutcome::Quarantined { reason }) => {
                    conflicts += 1;
                    self.update_entry_status(&entry.id, ReplayStatus::Conflict {
                        conflict_info: format!("quarantined during replay: {reason:?}"),
                    });
                }
                Ok(crate::crdt::merge::MergeOutcome::Rejected { reason }) => {
                    conflicts += 1;
                    self.update_entry_status(&entry.id, ReplayStatus::Conflict {
                        conflict_info: format!("rejected during replay: {reason}"),
                    });
                }
                Err(e) => {
                    conflicts += 1;
                    self.update_entry_status(&entry.id, ReplayStatus::Conflict {
                        conflict_info: format!("engine error: {e}"),
                    });
                }
            }
        }

        let complete = conflicts == 0 && total_entries > 0;
        if complete {
            // Update status for all entries for this migration.
            for entry in self.entries.iter_mut() {
                if entry.migration_id == migration_id {
                    entry.replay_status = ReplayStatus::Complete;
                }
            }

            // Append DeltaTag::ReplayComplete to the WASM in-memory tag store
            // for every successfully-replayed Delta (Req 19.6).
            for delta_id in &replayed_delta_ids {
                let tag = DeltaTag::ReplayComplete { migration_id };
                if let Err(e) = append_tag(delta_id, tag) {
                    eprintln!(
                        "[sidecar] Could not append ReplayComplete to delta {:?}: {e}",
                        delta_id
                    );
                }
            }
        }

        Ok(ReplaySummary {
            total_entries,
            replayed,
            conflicts,
            complete,
        })
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    fn update_entry_status(&mut self, id: &DeltaId, status: ReplayStatus) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == *id) {
            entry.replay_status = status;
        }
    }

    /// Count entries for a migration (used by tests).
    pub fn count_for_migration(&self, migration_id: MigrationId) -> Result<usize, TirBaseError> {
        Ok(self.entries.iter().filter(|e| e.migration_id == migration_id).count())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::contamination::taint::read_tags_from_db;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::dag::{ChangesetDag, DagNode};
    use crate::store::sqlite::CREATE_SCHEMA_SQL;
    use std::sync::{Arc, Mutex};

    fn open_conn() -> Arc<Mutex<rusqlite::Connection>> {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(CREATE_SCHEMA_SQL).expect("create schema");
        Arc::new(Mutex::new(conn))
    }

    fn open_ledger() -> SideCarLedger {
        SideCarLedger::new(open_conn())
    }

    /// Build a valid signed Delta and insert its DagNode into the database
    /// so that `append_tag_to_db` can find it.
    ///
    /// Uses empty `automerge_bytes` (accepted by `CrdtEngine::apply()` as a
    /// no-op merge) so the delta passes the Automerge parse step.  Deltas are
    /// differentiated by their `lamport` value.
    fn make_and_insert_delta(
        conn: &Arc<Mutex<rusqlite::Connection>>,
        schema_hash: [u8; 32],
        lamport: u64,
    ) -> Delta {
        use ed25519_dalek::SigningKey;

        let secret = [0xA1u8; 32];
        let sk = SigningKey::from_bytes(&secret);
        let public: [u8; 32] = sk.verifying_key().to_bytes();
        let did = crate::crdt::derive_did_from_public_key(&public);

        let mut delta = Delta {
            id: [0u8; 32],
            author_did: did.clone(),
            signature: Ed25519Signature::default(),
            schema_hash,
            // Empty bytes → CrdtEngine::apply() treats this as a no-op merge.
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = delta.canonical_bytes();
        delta.signature = crate::identity::keypair::sign(&secret, &canonical).expect("sign");
        delta.id = Delta::compute_id(&canonical);

        // Insert a DagNode so append_tag_to_db can find the row.
        let mut dag = ChangesetDag::new(conn.clone());
        dag.insert(DagNode {
            delta_id: delta.id,
            payload: vec![],
            parent_ids: vec![],
            actor_id: public.to_vec(),
            lamport,
            schema_hash,
            compacted: false,
            author_did: did,
        })
        .expect("insert DagNode");

        delta
    }

    /// Build a CrdtEngine backed by the shared connection.
    fn make_engine_on(
        conn: Arc<Mutex<rusqlite::Connection>>,
        schema_hash: [u8; 32],
    ) -> crate::crdt::CrdtEngine {
        use ed25519_dalek::SigningKey;
        let secret = [0xA1u8; 32];
        let sk = SigningKey::from_bytes(&secret);
        let public: [u8; 32] = sk.verifying_key().to_bytes();
        let did = crate::crdt::derive_did_from_public_key(&public);
        crate::crdt::CrdtEngine::new(secret, public, did, schema_hash, conn)
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

    // ─── ReplayComplete DeltaTag tests (Req 19.6) ────────────────────────────

    /// Zero-conflict replay: every successfully-replayed Delta must receive a
    /// `DeltaTag::ReplayComplete { migration_id }` entry in its tag log.
    #[test]
    fn replay_with_zero_conflicts_appends_replay_complete_tag_to_all_deltas() {
        let schema_hash = [0xABu8; 32];
        let migration_id: MigrationId = [0xF1u8; 32];
        let conn = open_conn();

        // Build and insert 3 valid deltas into DAG so their dag_nodes rows exist.
        let d1 = make_and_insert_delta(&conn, schema_hash, 1);
        let d2 = make_and_insert_delta(&conn, schema_hash, 2);
        let d3 = make_and_insert_delta(&conn, schema_hash, 3);

        let mut ledger = SideCarLedger::new(conn.clone());

        // Serialise each delta and store in the sidecar.
        for (i, d) in [&d1, &d2, &d3].iter().enumerate() {
            let bytes = serde_json::to_vec(d).expect("serialise");
            ledger
                .record(migration_id, "users".to_string(), bytes, i as i64)
                .expect("record");
        }

        // Replay against a fresh engine.
        let mut engine = make_engine_on(conn.clone(), schema_hash);
        let summary = ledger
            .replay_sidecar(migration_id, schema_hash, &mut engine)
            .expect("replay_sidecar must not error");

        // Confirm zero conflicts.
        assert_eq!(summary.conflicts, 0, "expected zero conflicts");
        assert!(summary.complete, "summary.complete must be true");

        // Every replayed delta must carry DeltaTag::ReplayComplete { migration_id }.
        let lock = conn.lock().unwrap();
        for d in [&d1, &d2, &d3] {
            let tags = read_tags_from_db(&lock, &d.id).expect("read_tags_from_db");
            let has_replay_complete = tags.iter().any(|t| {
                matches!(t, DeltaTag::ReplayComplete { migration_id: mid } if *mid == migration_id)
            });
            assert!(
                has_replay_complete,
                "delta {:?} must carry ReplayComplete tag after zero-conflict replay",
                d.id,
            );
        }
    }

    /// Replay with at least one conflict: NO Delta should receive a
    /// `DeltaTag::ReplayComplete` tag (Req 19.6 — flag only on zero failures).
    #[test]
    fn replay_with_conflicts_does_not_append_replay_complete_tag() {
        let schema_hash = [0xABu8; 32];
        let migration_id: MigrationId = [0xF2u8; 32];
        let conn = open_conn();

        // One valid delta.
        let d1 = make_and_insert_delta(&conn, schema_hash, 1);
        let mut ledger = SideCarLedger::new(conn.clone());

        let bytes = serde_json::to_vec(&d1).expect("serialise");
        ledger
            .record(migration_id, "users".to_string(), bytes, 0)
            .expect("record valid");

        // One malformed entry (guaranteed conflict).
        ledger
            .record(
                migration_id,
                "users".to_string(),
                b"not-valid-json-delta".to_vec(),
                1,
            )
            .expect("record malformed");

        let mut engine = make_engine_on(conn.clone(), schema_hash);
        let summary = ledger
            .replay_sidecar(migration_id, schema_hash, &mut engine)
            .expect("replay_sidecar must not error");

        assert!(summary.conflicts >= 1, "expected at least 1 conflict");
        assert!(!summary.complete, "summary.complete must be false when conflicts > 0");

        // The valid delta must NOT carry a ReplayComplete tag.
        let lock = conn.lock().unwrap();
        let tags = read_tags_from_db(&lock, &d1.id).expect("read_tags_from_db");
        let has_replay_complete = tags.iter().any(|t| {
            matches!(t, DeltaTag::ReplayComplete { .. })
        });
        assert!(
            !has_replay_complete,
            "ReplayComplete must NOT be appended when replay has conflicts",
        );
    }

    /// Empty sidecar (no entries): replay must return complete=false and append
    /// no tags.  (The spec: REPLAY_COMPLETE only when zero *failures*, but also
    /// only when entries exist — an empty ledger has nothing to mark complete.)
    #[test]
    fn replay_with_no_entries_does_not_mark_complete() {
        let migration_id: MigrationId = [0xF3u8; 32];
        let conn = open_conn();
        let mut ledger = SideCarLedger::new(conn.clone());
        let mut engine = make_engine_on(conn.clone(), [0xABu8; 32]);

        let summary = ledger
            .replay_sidecar(migration_id, [0xABu8; 32], &mut engine)
            .expect("replay_sidecar must not error on empty ledger");

        assert_eq!(summary.total_entries, 0);
        assert_eq!(summary.conflicts, 0);
        assert!(!summary.complete, "complete must be false for empty ledger");
    }
}
